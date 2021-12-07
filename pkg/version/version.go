package version

import "runtime/debug"

var (
	version = "dev"
	commit  = ""
	date    = ""
)

// Version returns the current version.
func Version() string {
	return version
}

// Commit returns the current commit.
func Commit() string {
	return commit
}

// BuildDate returns the build date.
func BuildDate() string {
	return date
}

// ModuleName returns the module name.
func ModuleName() string {
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		return buildInfo.Main.Path
	}
	return ""
}
