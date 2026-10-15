package aap

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleStoragePrefix = "roles/"
	defaultTTL        = time.Hour
	defaultMaxTTL     = 24 * time.Hour
)

type role struct {
	Scope             string        `json:"scope"`
	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
	DescriptionPrefix string        `json:"description_prefix"`
}

func pathRole(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Role name.",
				Required:    true,
			},
			"scope": {
				Type:        framework.TypeString,
				Description: "AAP OAuth scope. Must be read or write. Write includes read.",
				Default:     "write",
			},
			"ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Default generated-secret lifetime. Defaults to one hour.",
				Default:     int(defaultTTL.Seconds()),
			},
			"max_ttl": {
				Type:        framework.TypeDurationSecond,
				Description: "Maximum generated-secret lifetime. Defaults to 24 hours.",
				Default:     int(defaultMaxTTL.Seconds()),
			},
			"description_prefix": {
				Type:        framework.TypeString,
				Description: "Prefix used to identify Vault-issued tokens in AAP.",
				Default:     "vault-aap",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
		},
		HelpSynopsis:    "Manage an AAP token-issuing role.",
		HelpDescription: "AAP RBAC is determined by the identity that owns the configured issuer token. This role controls only OAuth scope and Vault lease lifetimes.",
	}
}

func pathRoleList(b *Backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
		},
		HelpSynopsis: "List AAP token-issuing roles.",
	}
}

func (b *Backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil || role == nil {
		return nil, err
	}
	return &logical.Response{Data: role.responseData()}, nil
}

func (b *Backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	role := &role{
		Scope:             data.Get("scope").(string),
		TTL:               time.Duration(data.Get("ttl").(int)) * time.Second,
		MaxTTL:            time.Duration(data.Get("max_ttl").(int)) * time.Second,
		DescriptionPrefix: data.Get("description_prefix").(string),
	}
	if role.Scope != "read" && role.Scope != "write" {
		return nil, fmt.Errorf("scope must be read or write")
	}
	if role.TTL <= 0 || role.MaxTTL <= 0 {
		return nil, fmt.Errorf("ttl and max_ttl must be positive")
	}
	if role.TTL > role.MaxTTL {
		return nil, fmt.Errorf("ttl must not exceed max_ttl")
	}
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, role)
	if err != nil {
		return nil, fmt.Errorf("encode role: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("store role: %w", err)
	}
	return nil, nil
}

func (b *Backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, roleStoragePrefix+data.Get("name").(string)); err != nil {
		return nil, fmt.Errorf("delete role: %w", err)
	}
	return nil, nil
}

func (b *Backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return logical.ListResponse(keys), nil
}

func getRole(ctx context.Context, storage logical.Storage, name string) (*role, error) {
	entry, err := storage.Get(ctx, roleStoragePrefix+name)
	if err != nil || entry == nil {
		return nil, err
	}
	var role role
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("decode role: %w", err)
	}
	return &role, nil
}

func (r *role) responseData() map[string]interface{} {
	return map[string]interface{}{
		"scope":              r.Scope,
		"ttl":                int(r.TTL.Seconds()),
		"max_ttl":            int(r.MaxTTL.Seconds()),
		"description_prefix": r.DescriptionPrefix,
	}
}
