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
	"strings"
	"time"
)

const gatewayTokensPath = "/api/gateway/v1/tokens/"

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
	parsedURL, err := url.Parse(config.URL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid AAP URL %q", config.URL)
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("AAP URL must use http or https")
	}
	if parsedURL.Scheme == "http" && !config.AllowInsecureHTTP {
		return nil, fmt.Errorf("AAP URL uses insecure HTTP; set allow_insecure_http only for a test environment")
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
		baseURL:     strings.TrimRight(config.URL, "/"),
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

	var payload struct {
		ID      json.Number `json:"id"`
		Token   string      `json:"token"`
		Expires string      `json:"expires"`
	}
	decoder := json.NewDecoder(response.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode AAP token response: %w", err)
	}
	if payload.ID == "" || payload.Token == "" || payload.Expires == "" {
		return nil, fmt.Errorf("AAP token response omitted id, token, or expires")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, payload.Expires)
	if err != nil {
		return nil, fmt.Errorf("parse AAP token expiry: %w", err)
	}

	return &issuedToken{ID: payload.ID.String(), Token: payload.Token, ExpiresAt: expiresAt}, nil
}

func (c *aapClient) revokeToken(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return fmt.Errorf("AAP token id is empty")
	}
	req, err := c.newRequest(ctx, http.MethodDelete, gatewayTokensPath+url.PathEscape(tokenID)+"/", nil)
	if err != nil {
		return err
	}
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call AAP token revoke endpoint: %w", err)
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
		return nil, fmt.Errorf("call AAP token endpoint: %w", err)
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
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = response.Status
	}
	return fmt.Errorf("AAP API returned %s: %s", response.Status, message)
}
