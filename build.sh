#! /bin/bash
COMMIT=$(git rev-parse --short HEAD)
TAG=$(git name-rev --tags --name-only $COMMIT)

CGO_ENABLED=$CGO_ENABLED GOOS=$GOOS GOARCH=$GOARCH go build -o ./tokensd/tokensd -ldflags "-X darlinggo.co/tokens/version.Version=${TAG} -X darlinggo.co/tokens/version.Hash=${COMMIT}" ./tokensd
rm -rf ./tokensd/sql
cp -r ./sql ./tokensd/sql
