#!/bin/bash

mkdir -p coverage
rm -rf coverage/*
for pkg in $(go list ./... | grep -v '/vendor/'); do \
	echo "################### testing ${pkg} ###################"; \
	go test $pkg -race -v -covermode=atomic -coverprofile=coverage/${pkg//\//.}.out; \
done
combinedcoverage $(find coverage/*.out | grep -v '/vendor/')
gocovmerge $(find coverage/*.out | grep -v '/vendor/') > coverage/total.out
