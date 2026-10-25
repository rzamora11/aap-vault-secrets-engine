package aap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const expirySafetyMargin = time.Minute

func (b *Backend) aapToken() *framework.Secret {
	return &framework.Secret{
		Type: tokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: "AAP OAuth bearer token.",
			},
			"host": {
				Type:        framework.TypeString,
				Description: "AAP platform gateway base URL.",
			},
			"expires_at": {
				Type:        framework.TypeString,
				Description: "AAP-reported token expiry in RFC3339 format.",
			},
		},
		Revoke: b.tokenRevoke,
	}
}

func pathCredentials(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "AAP token-issuing role name.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredentialsRead},
		},
		HelpSynopsis:    "Generate a short-lived AAP OAuth token.",
		HelpDescription: "The lease is non-renewable. Request a new credential after it expires.",
	}
}

func (b *Backend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q does not exist", roleName)
	}

	client, config, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	defer client.close()
	description, err := tokenDescription(role.DescriptionPrefix, roleName)
	if err != nil {
		return nil, err
	}
	token, err := client.issueToken(ctx, role.Scope, description)
	if err != nil {
		if token != nil {
			_ = client.revokeToken(ctx, token.ID)
		}
		return nil, err
	}

	remainingAAPLifetime := time.Until(token.ExpiresAt) - expirySafetyMargin
	if remainingAAPLifetime <= 0 {
		_ = client.revokeToken(ctx, token.ID)
		return nil, fmt.Errorf("AAP returned a token expiring too soon to issue safely")
	}
	leaseTTL := minDuration(role.TTL, role.MaxTTL, remainingAAPLifetime)
	if leaseTTL <= 0 {
		_ = client.revokeToken(ctx, token.ID)
		return nil, fmt.Errorf("unable to calculate a usable lease duration")
	}

	response := b.Secret(tokenType).Response(
		map[string]interface{}{
			"token":      token.Token,
			"host":       config.URL,
			"expires_at": token.ExpiresAt.UTC().Format(time.RFC3339),
		},
		map[string]interface{}{"token_id": token.ID},
	)
	response.Secret.TTL = leaseTTL
	response.Secret.MaxTTL = leaseTTL
	response.Secret.Renewable = false
	return response, nil
}

func (b *Backend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if req.Secret == nil {
		return nil, fmt.Errorf("missing AAP secret for revocation")
	}
	tokenID, ok := req.Secret.InternalData["token_id"].(string)
	if !ok || tokenID == "" {
		return nil, fmt.Errorf("AAP token id is missing from lease data")
	}
	client, _, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	defer client.close()
	if err := client.revokeToken(ctx, tokenID); err != nil {
		return nil, err
	}
	return nil, nil
}

func tokenDescription(prefix, roleName string) (string, error) {
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate token description suffix: %w", err)
	}
	return fmt.Sprintf("%s:%s:%d:%s", prefix, roleName, time.Now().UTC().Unix(), hex.EncodeToString(randomBytes)), nil
}

func minDuration(durations ...time.Duration) time.Duration {
	minimum := durations[0]
	for _, duration := range durations[1:] {
		if duration < minimum {
			minimum = duration
		}
	}
	return minimum
}
