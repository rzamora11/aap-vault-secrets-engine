// Package aap implements a Vault logical secrets engine for AAP OAuth tokens.
package aap

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
	tokenType         = "aap_oauth_token"
)

// Backend is the AAP Vault secrets engine.
type Backend struct {
	*framework.Backend
}

// Factory creates and configures an AAP secrets engine backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func backend() *Backend {
	b := &Backend{}
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				configStoragePath,
				"roles/",
			},
		},
		Paths: []*framework.Path{
			pathConfig(b),
			pathRole(b),
			pathRoleList(b),
			pathCredentials(b),
		},
		Secrets: []*framework.Secret{
			b.aapToken(),
		},
		BackendType: logical.TypeLogical,
	}
	return b
}

func (b *Backend) client(ctx context.Context, storage logical.Storage) (*aapClient, *config, error) {
	config, err := getConfig(ctx, storage)
	if err != nil {
		return nil, nil, err
	}
	if config == nil {
		return nil, nil, fmt.Errorf("AAP secrets engine is not configured")
	}
	client, err := newAAPClient(config)
	if err != nil {
		return nil, nil, err
	}
	return client, config, nil
}

const backendHelp = `
The AAP secrets backend creates short-lived OAuth tokens using a protected AAP
issuer token. Vault revokes the AAP token when the generated secret lease
expires or is manually revoked.

Configure the issuer token with "config", define an issuing role with
"roles/<name>", and request a token with "creds/<name>".
`
