package aap

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type config struct {
	URL               string `json:"url"`
	IssuerToken       string `json:"issuer_token"`
	TLSSkipVerify     bool   `json:"tls_skip_verify"`
	CACert            string `json:"ca_cert"`
	AllowInsecureHTTP bool   `json:"allow_insecure_http"`
}

func pathConfig(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "AAP platform gateway base URL, for example https://aap.example.com.",
				Required:    true,
			},
			"issuer_token": {
				Type:        framework.TypeString,
				Description: "AAP bearer token Vault uses only to create and revoke child tokens. Use a dedicated, minimally privileged service identity.",
				Required:    true,
			},
			"tls_skip_verify": {
				Type:        framework.TypeBool,
				Description: "Disable AAP TLS certificate verification. Defaults to false.",
				Default:     false,
			},
			"allow_insecure_http": {
				Type:        framework.TypeBool,
				Description: "Allow an unencrypted HTTP gateway URL. Only use for a non-production test environment.",
				Default:     false,
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM-encoded CA certificate for the AAP gateway.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
		},
		HelpSynopsis:    "Configure the AAP platform gateway connection.",
		HelpDescription: "The issuer token and optional CA certificate are never returned by a configuration read.",
	}
}

func (b *Backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil || config == nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{
		"url":                     config.URL,
		"issuer_token_configured": config.IssuerToken != "",
		"tls_skip_verify":         config.TLSSkipVerify,
		"allow_insecure_http":     config.AllowInsecureHTTP,
		"ca_cert_configured":      config.CACert != "",
	}}, nil
}

func (b *Backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	url, err := validateGateway(data.Get("url").(string), data.Get("allow_insecure_http").(bool))
	if err != nil {
		return nil, fmt.Errorf("invalid AAP configuration: %w", err)
	}
	if _, err := newAAPClient(&config{
		URL:               url,
		IssuerToken:       data.Get("issuer_token").(string),
		TLSSkipVerify:     data.Get("tls_skip_verify").(bool),
		CACert:            data.Get("ca_cert").(string),
		AllowInsecureHTTP: data.Get("allow_insecure_http").(bool),
	}); err != nil {
		return nil, fmt.Errorf("invalid AAP configuration: %w", err)
	}

	entry := &config{
		URL:               url,
		IssuerToken:       data.Get("issuer_token").(string),
		TLSSkipVerify:     data.Get("tls_skip_verify").(bool),
		CACert:            data.Get("ca_cert").(string),
		AllowInsecureHTTP: data.Get("allow_insecure_http").(bool),
	}
	storageEntry, err := logical.StorageEntryJSON(configStoragePath, entry)
	if err != nil {
		return nil, fmt.Errorf("encode AAP configuration: %w", err)
	}
	if err := req.Storage.Put(ctx, storageEntry); err != nil {
		return nil, fmt.Errorf("store AAP configuration: %w", err)
	}
	return nil, nil
}

func (b *Backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, fmt.Errorf("delete AAP configuration: %w", err)
	}
	return nil, nil
}

func getConfig(ctx context.Context, storage logical.Storage) (*config, error) {
	entry, err := storage.Get(ctx, configStoragePath)
	if err != nil || entry == nil {
		return nil, err
	}
	var config config
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("decode AAP configuration: %w", err)
	}
	return &config, nil
}
