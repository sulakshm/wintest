
CMDS=wintest
PKG = github.com/sulakshm/wintest
GINKGO_FLAGS = -ginkgo.v
GO111MODULE = on
GOPATH ?= $(shell go env GOPATH)
GOBIN ?= $(GOPATH)/bin
DOCKER_CLI_EXPERIMENTAL = enabled
IMAGENAME ?= wintest
export GOPATH GOBIN GO111MODULE DOCKER_CLI_EXPERIMENTAL

include release-tools/build.make

GIT_COMMIT ?= $(shell git rev-parse HEAD)
REGISTRY ?= docker.io/sulakshm
REGISTRY_NAME = $(shell echo $(REGISTRY) | sed "s/.azurecr.io//g")
IMAGE_VERSION ?= v0.0.1
VERSION ?= latest
# Use a custom version for E2E tests if we are testing in CI
ifdef CI
ifndef PUBLISH
override IMAGE_VERSION := e2e-$(GIT_COMMIT)
endif
endif
IMAGE_TAG = $(REGISTRY)/$(IMAGENAME):$(IMAGE_VERSION)


IMAGE_TAG = $(REGISTRY)/$(IMAGENAME):$(IMAGE_VERSION)
IMAGE_TAG_LATEST = $(REGISTRY)/$(IMAGENAME):latest
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS = -X ${PKG}/main.driverVersion=${IMAGE_VERSION} -X ${PKG}/main.gitCommit=${GIT_COMMIT} -X ${PKG}/main.buildDate=${BUILD_DATE}
EXT_LDFLAGS = -s -w -extldflags "-static"
# Generate all combination of all OS, ARCH, and OSVERSIONS for iteration
ALL_OS = windows
ALL_ARCH.windows = amd64
ALL_OSVERSIONS.windows := 1809 20H2 ltsc2022
ALL_OS_ARCH.windows = $(foreach arch, $(ALL_ARCH.windows), $(foreach osversion, ${ALL_OSVERSIONS.windows}, windows-${osversion}-${arch}))
ALL_OS_ARCH = $(foreach os, $(ALL_OS), ${ALL_OS_ARCH.${os}})

# The current context of image building
# The architecture of the image
ARCH ?= amd64
# OS Version for the Windows images: 1809, 1903, 1909, 2004
OSVERSION ?= 1809
# Output type of docker buildx build
OUTPUT_TYPE ?= registry

.EXPORT_ALL_VARIABLES:

all: wintest-windows

.PHONY: wintest-windows
wintest-windows:
	CGO_ENABLED=0 GOOS=windows go build -a -ldflags "${LDFLAGS} ${EXT_LDFLAGS}" -mod vendor -o _output/${ARCH}/wintest.exe .


