package aap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	gatewayTokensPath      = "/api/gateway/v1/tokens/"
	maxGatewayResponseSize = 1 << 20
)

var (
	tokenIDPattern       = regexp.MustCompile(`^[1-9][0-9]*$`)
	recoverableIDPattern = regexp.MustCompile(`^\s*\{\s*"id"\s*:\s*([1-9][0-9]*)\s*,`)
)

type aapClient struct {
	baseURL     string
	issuerToken string
	http        *http.Client
}

type issuedToken struct {
	ID        string
	Token     string
	ExpiresAt time.Time
}

func newAAPClient(config *config) (*aapClient, error) {
	baseURL, err := validateGateway(config.URL, config.AllowInsecureHTTP)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.IssuerToken) == "" {
		return nil, fmt.Errorf("AAP issuer token is empty")
	}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: config.TLSSkipVerify} // #nosec G402 -- explicitly controlled by the operator.
	if config.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.CACert)) {
			return nil, fmt.Errorf("invalid AAP CA certificate")
		}
		tlsConfig.RootCAs = pool
	}

	return &aapClient{
		baseURL:     baseURL,
		issuerToken: config.IssuerToken,
		http: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return fmt.Errorf("AAP gateway redirected the request")
			},
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}, nil
}

func validateGateway(rawURL string, allowInsecureHTTP bool) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" || parsedURL.Opaque != "" {
		return "", fmt.Errorf("invalid AAP gateway URL")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || parsedURL.RawFragment != "" {
		return "", fmt.Errorf("AAP gateway URL must be an origin")
	}
	if parsedURL.Path != "" && parsedURL.Path != "/" || parsedURL.RawPath != "" {
		return "", fmt.Errorf("AAP gateway URL must not include a path")
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return "", fmt.Errorf("AAP gateway URL must use HTTP or HTTPS")
	}
	if parsedURL.Scheme == "http" && !allowInsecureHTTP {
		return "", fmt.Errorf("AAP gateway URL requires HTTPS unless allow_insecure_http is enabled")
	}
	return parsedURL.Scheme + "://" + parsedURL.Host, nil
}

func (c *aapClient) issueToken(ctx context.Context, scope, description string) (*issuedToken, error) {
	body, err := json.Marshal(map[string]string{
		"scope":       scope,
		"description": description,
	})
	if err != nil {
		return nil, fmt.Errorf("encode AAP token request: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, gatewayTokensPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := c.do(req, http.StatusCreated, http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	payload, err := decodeIssuedToken(response.Body)
	if err != nil {
		return payload, err
	}
	return payload, nil
}

func decodeIssuedToken(body io.Reader) (*issuedToken, error) {
	contents, err := io.ReadAll(io.LimitReader(body, maxGatewayResponseSize+1))
	if err != nil || len(contents) > maxGatewayResponseSize {
		return nil, fmt.Errorf("AAP token response is invalid")
	}
	var payload struct {
		ID      json.RawMessage `json:"id"`
		Token   string          `json:"token"`
		Expires string          `json:"expires"`
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return recoverableTokenID(contents), fmt.Errorf("AAP token response is invalid")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return recoverableTokenID(contents), fmt.Errorf("AAP token response is invalid")
	}
	tokenID := string(payload.ID)
	if !validTokenID(tokenID) {
		return nil, fmt.Errorf("AAP token response has an invalid id")
	}
	token := &issuedToken{ID: tokenID, Token: payload.Token}
	if payload.Token == "" || payload.Expires == "" {
		return token, fmt.Errorf("AAP token response omitted token or expires")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, payload.Expires)
	if err != nil {
		return token, fmt.Errorf("AAP token response has an invalid expiry")
	}
	token.ExpiresAt = expiresAt
	return token, nil
}

func (c *aapClient) revokeToken(ctx context.Context, tokenID string) error {
	if !validTokenID(tokenID) {
		return fmt.Errorf("AAP token id is invalid")
	}
	req, err := c.newRequest(ctx, http.MethodDelete, gatewayTokensPath+url.PathEscape(tokenID)+"/", nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("AAP token revoke request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return responseError(response)
	}
	return nil
}

func (c *aapClient) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create AAP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.issuerToken)
	return req, nil
}

func (c *aapClient) do(req *http.Request, successCodes ...int) (*http.Response, error) {
	response, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AAP token request failed")
	}
	for _, statusCode := range successCodes {
		if response.StatusCode == statusCode {
			return response, nil
		}
	}
	defer response.Body.Close()
	return nil, responseError(response)
}

func responseError(response *http.Response) error {
	return fmt.Errorf("AAP API returned status %d", response.StatusCode)
}

func validTokenID(tokenID string) bool {
	return tokenIDPattern.MatchString(tokenID)
}

func recoverableTokenID(contents []byte) *issuedToken {
	matches := recoverableIDPattern.FindSubmatch(contents)
	if len(matches) != 2 {
		return nil
	}
	return &issuedToken{ID: string(matches[1])}
}

func (c *aapClient) close() {
	c.http.CloseIdleConnections()
}
