package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	aap "github.com/rzamora11/aap-vault-secrets-engine/aap"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: aap.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(tlsConfig),
	})
	if err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})
		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
