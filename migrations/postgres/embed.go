package postgres

import _ "embed"

//go:embed 000001_init.up.sql
var Initial string

//go:embed 000002_identity.up.sql
var Identity string
