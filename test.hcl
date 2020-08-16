# write permission on 'chowkidar/logs' path
path "chowkidar/*" {
	capabilities = [ "update", "create" , "read"]
}
