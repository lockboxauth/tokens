#!/bin/bash

mkdir -p .cover-profiles
rm .cover-profiles/*
for pkg in $(go list ./... | grep -v '/vendor/'); do \
	echo "################### testing ${pkg} ###################"; \
	go test $pkg -race -v -covermode=atomic -coverprofile=.cover-profiles/${pkg//\//.}.out; \
done
combinedcoverage $(find .cover-profiles/*.out | grep -v '/vendor/')
gocovmerge $(find .cover-profiles/*.out | grep -v '/vendor/') > .cover-profiles/total.out
