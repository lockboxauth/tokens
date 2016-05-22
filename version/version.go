package version

// Version should be set (using ldflags) to the git tag the binary was built from.
var Version string

// Hash should be set (using ldflags) to the git hash the binary was built from.
var Hash string
