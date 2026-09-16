package postgres

import _ "embed"

//go:embed 000001_init.up.sql
var Initial string
