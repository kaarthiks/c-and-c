#!/bin/bash
setup_vault () {
	export VAULT_ADDR='http://127.0.0.1:8200'
	mkdir -p /tmp/vault-plugins
}
enable_cors () {
        curl  -k   --header "X-Vault-Token: root"     --request PUT     --data @payload.json     https://127.0.0.1:9800/v1/sys/config/cors
}
create_policy () {
	vault policy write test test.hcl

}
enable_auth_plugin () {
	export VAULT_ADDR='http://127.0.0.1:8200'
	cd chakravyuh
	go build -o ../chowkidar/vault/plugins/chakravyuh
	vault auth enable -path=chakravyuh -plugin-name=chakravyuh plugin	
	cd ..
}

enable_secret_plugin () {
	export VAULT_ADDR='http://127.0.0.1:8200'
	cd chowkidar
	go build -o vault/plugins/chowkidar cmd/chowkidar/main.go
    vault secrets enable -path=chowkidar -plugin-name=chowkidar plugin
    cd ..
}

start_vault () {
	export VAULT_ADDR='http://127.0.0.1:8200'
	vault server -dev -dev-root-token-id=root -dev-plugin-dir=./chowkidar/vault/plugins
}
