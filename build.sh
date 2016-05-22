#! /bin/bash
COMMIT=$(git rev-parse --short HEAD)
TAG=$(git name-rev --tags --name-only $COMMIT)

GOOS=$GOOS GOARCH=$GOARCH go build -o ./tokensd/tokensd -ldflags "-X darlinggo.co/tokens.Version=${TAG} -X darlinggo.co/tokens.Hash=${COMMIT}" ./tokensd
