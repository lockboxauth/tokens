#! /bin/bash

# set our ldflags to inject version info
PACKAGE_PREFIX=code.impractical.co/tokens
source vendor/darlinggo.co/version/ldflags.sh

# build the binary
CGO_ENABLED=$CGO_ENABLED GOOS=$GOOS GOARCH=$GOARCH go build -o ./tokensd/tokensd -ldflags "${LDFLAGS}" ./tokensd
