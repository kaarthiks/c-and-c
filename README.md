# Start Vault

```
source ctrl-test.sh
start_vault
```

# Enable plugins and policy

```
enable_auth_plugin
enable_secret_plugin
create_policy

```

# Vaild credentials
- app1/app1
- app2/app2
- policy `test` provides to access chowkidar/* paths

# To set policy for each user

```

```

# To set policy for a user

```
vault write auth/chakravyuh/role/app1 policies="test"
```

# To login as user

```
vault write auth/chakravyuh/login username="app1" password="app1"

vault login <token returned from previous cli>

```

# To store a secret

```
vault write chowkidar/test message="Hello World"
```

# To read a secret

```
vault read chowkidar/test
```


