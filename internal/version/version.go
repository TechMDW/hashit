package version

import (
	"strings"
)

var Version string
var GoVersion string

func init() {
	// If the version is not set, assume it is a development build
	if Version == "" {
		Version = "development"
		return
	}

	// Remove the leading "v" if it exists
	if Version[0] == 'v' {
		Version = Version[1:]
	}

	// Remove the leading "go" if it exists
	GoVersion = strings.TrimLeft(GoVersion, "go")
}
