package pfsense

import (
	_ "embed"
)

//go:embed scripts/read_state.php
var PhpReadScript string

//go:embed scripts/apply_config.php
var PhpWriteScript string

//go:embed scripts/gateway_status.php
var PhpGatewayStatusScript string

//go:embed scripts/traffic_stats.php
var PhpTrafficStatsScript string

//go:embed scripts/enable_interface.php
var PhpEnableScript string

//go:embed scripts/backup.php
var PhpBackupScript string

//go:embed scripts/restore.php
var PhpRestoreScript string

//go:embed scripts/reset.php
var PhpResetScript string

//go:embed scripts/reboot.php
var PhpRebootScript string

//go:embed scripts/shutdown.php
var PhpShutdownScript string

//go:embed scripts/pfblockerng_category.php
var PhpPfBlockerNGCategoryScript string
