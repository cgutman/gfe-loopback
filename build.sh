#!/bin/sh

set -e

# AMD64
docker build --pull -t cgutman/gfe-loopback:manifest-amd64 --build-arg ARCH=amd64/ .
docker push cgutman/gfe-loopback:manifest-amd64

# ARM64
docker build --pull -t cgutman/gfe-loopback:manifest-arm64v8 --build-arg ARCH=arm64v8/ .
docker push cgutman/gfe-loopback:manifest-arm64v8

# Create combined multi-arch manifest
docker manifest create cgutman/gfe-loopback:latest \
	--amend cgutman/gfe-loopback:manifest-amd64 \
	--amend cgutman/gfe-loopback:manifest-arm64v8
docker manifest push cgutman/gfe-loopback:latest
