# Makefile for fscrypt
#
# Copyright 2017 Google Inc.
# Author: Joe Richey (joerichey@google.com)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

# Update on each new release!!
VERSION := v0.2.4
NAME := fscrypt
PAM_NAME := pam_$(NAME)

###### Makefile Command Line Flags ######
#
# BIN: The locaton where binaries will be built.    Default: ./bin
# INSTALL: The tool used to install binaries.       Default: sudo install
# DESTDIR: The location for the fscrypt binary.     Default: /usr/local/bin
# PAM_MODULE_DIR: The location for pam_fscrypt.so.  Default: /lib/security
#
# MOUNT: The filesystem where our tests are run.    Default: /mnt/fscrypt_mount
#   Ex: make test-setup MOUNT=/foo/bar
#     Creates a test filesystem at that location.
#   Ex: make test-teardown MOUNT=/foo/bar
#     Cleans up a test filesystem created with "make test-setup".
#   Ex: make test MOUNT=/foo/bar
#     Run all integration tests on that filesystem. This can be an existing
#     filesystem, or one created with "make test-setup" (this is the default).
#
# CFLAGS: The flags passed to the C compiler.       Default: -O2 -Wall
#   Ex: make fscrypt "CFLAGS = -O3 -Werror"
#     Builds fscrypt with the C code failing on warnings and highly optimized.
#
# LDFLAGS: The flags passed to the C linker.        Default empty
#   Ex: make fscrypt "LDFLAGS = -static -ldl -laudit -lcap-ng"
#     Builds fscrypt as a static binary.
#
# GO_FLAGS: The flags passed to "go build".         Default empty
#   Ex: make fscrypt "GO_FLAGS = -race"
#     Builds fscrypt with race detection for the go code.
#
# GO_LINK_FLAGS: The flags passed to the go linker. Default: -s -w
#   Ex: make fscrypt GO_LINK_FLAGS=""
#     Builds fscrypt without stripping the binary.

BIN := bin
export PATH := $(BIN):$(PATH)
PAM_MODULE := $(BIN)/$(PAM_NAME).so

###### Setup Build Flags #####
CFLAGS := -O2 -Wall
# Pass CFLAGS to each cgo invocation.
export CGO_CFLAGS = $(CFLAGS)
# By default, we strip the binary to reduce size.
GO_LINK_FLAGS := -s -w

# Flag to embed the version (pulled from tags) into the binary.
TAG_VERSION := $(shell git describe --tags)
VERSION_FLAG := -X "main.version=$(if $(TAG_VERSION),$(TAG_VERSION),$(VERSION))"
# Flag to embed the date and time of the build into the binary.
DATE_FLAG := -X "main.buildTime=$(shell date)"

override GO_LINK_FLAGS += $(VERSION_FLAG) $(DATE_FLAG) -extldflags "$(LDFLAGS)"
override GO_FLAGS += --ldflags '$(GO_LINK_FLAGS)'

###### Find All Files and Directories ######
FILES := $(shell find . \( -path ./vendor -o -path "./.*" \) -prune -o -type f -printf "%P\n")
GO_FILES := $(filter %.go,$(FILES))
GO_NONGEN_FILES := $(filter-out %.pb.go,$(GO_FILES))
GO_DIRS := $(sort $(dir $(GO_FILES)))
C_FILES := $(filter %.c %.h,$(FILES))
PROTO_FILES := $(filter %.proto,$(FILES))

###### Build, Formatting, and Linting Commands ######
.PHONY: default all gen format lint clean
default: $(BIN)/$(NAME) $(PAM_MODULE)
all: tools gen default format lint test

$(BIN)/$(NAME): $(GO_FILES) $(C_FILES)
	go build $(GO_FLAGS) -o $@ ./cmd/$(NAME)

$(PAM_MODULE): $(GO_FILES) $(C_FILES)
	go build -buildmode=c-shared $(GO_FLAGS) -o $@ ./$(PAM_NAME)
	rm -f $(BIN)/$(PAM_NAME).h

gen: $(BIN)/protoc $(BIN)/protoc-gen-go $(PROTO_FILES)
	protoc --go_out=. $(PROTO_FILES)

format: $(BIN)/goimports
	goimports -w $(GO_NONGEN_FILES)
	clang-format -i -style=Google $(C_FILES)

lint: $(BIN)/golint $(BIN)/staticcheck $(BIN)/misspell
	go vet ./...
	go list ./... | xargs -L1 golint -set_exit_status
	staticcheck ./...
	misspell -source=text $(FILES)

clean:
	rm -f $(BIN)/$(NAME) $(PAM_MODULE) $(TOOLS) coverage.out $(COVERAGE_FILES) $(PAM_CONFIG)

###### Testing Commands (setup/teardown require sudo) ######
.PHONY: test test-setup test-teardown

# If MOUNT exists signal that we should run integration tests.
MOUNT := /tmp/$(NAME)-mount
IMAGE := /tmp/$(NAME)-image
ifneq ("$(wildcard $(MOUNT))","")
export TEST_FILESYSTEM_ROOT = $(MOUNT)
endif

test:
	go test -p 1 ./...

test-setup:
	dd if=/dev/zero of=$(IMAGE) bs=1M count=20
	mkfs.ext4 -b 4096 -O encrypt $(IMAGE) -F
	mkdir -p $(MOUNT)
	sudo mount -o rw,loop,user $(IMAGE) $(MOUNT)
	sudo chmod +777 $(MOUNT)

test-teardown:
	sudo umount $(MOUNT)
	rmdir $(MOUNT)
	rm -f $(IMAGE)

# Runs tests and generates coverage
COVERAGE_FILES := $(addsuffix coverage.out,$(GO_DIRS))
coverage.out: $(BIN)/gocovmerge $(COVERAGE_FILES)
	@gocovmerge $(COVERAGE_FILES) > $@

%/coverage.out: $(GO_FILES) $(C_FILES)
	@go test -coverpkg=./... -covermode=count -coverprofile=$@ -p 1 ./$* 2> /dev/null

###### Installation Commands (require sudo) #####
.PHONY: install install-bin install-pam uninstall
install: install-bin install-pam

PREFIX := /usr/local
DESTDIR := $(PREFIX)/bin

install-bin: $(BIN)/$(NAME)
	install -d $(DESTDIR)
	install $< $(DESTDIR)

PAM_MODULE_DIR := $(PREFIX)/lib/security
PAM_INSTALL_PATH := $(PAM_MODULE_DIR)/$(PAM_NAME).so
PAM_CONFIG := $(BIN)/config
PAM_CONFIG_DIR := $(PREFIX)/share/pam-configs

install-pam: $(PAM_MODULE)
	install -d $(PAM_MODULE_DIR)
	install $(PAM_MODULE) $(PAM_MODULE_DIR)

	m4 --define=PAM_INSTALL_PATH=$(PAM_INSTALL_PATH) < $(PAM_NAME)/config > $(PAM_CONFIG)
	install -d $(PAM_CONFIG_DIR)
	install $(PAM_CONFIG) $(PAM_CONFIG_DIR)/$(NAME)

uninstall:
	rm -f $(DESTDIR)/$(NAME) $(PAM_INSTALL_PATH) $(PAM_CONFIG_DIR)/$(NAME)

#### Tool Building Commands ####
TOOLS := $(addprefix $(BIN)/,protoc golint protoc-gen-go goimports staticcheck gocovmerge misspell)
.PHONY: tools
tools: $(TOOLS)

$(BIN)/golint:
	GO111MODULE=off go get golang.org/x/lint/golint
	GO111MODULE=off go build -o $@ golang.org/x/lint/golint
$(BIN)/protoc-gen-go:
	GO111MODULE=off go get -d github.com/golang/protobuf/protoc-gen-go
	git -C "$(shell go env GOPATH)/src/github.com/golang/protobuf" checkout v1.2.0
	go install github.com/golang/protobuf/protoc-gen-go
	GO111MODULE=off go build -o $@ github.com/golang/protobuf/protoc-gen-go
$(BIN)/goimports:
	GO111MODULE=off go get golang.org/x/tools/cmd/goimports
	GO111MODULE=off go build -o $@ golang.org/x/tools/cmd/goimports
$(BIN)/staticcheck:
	GO111MODULE=off go get honnef.co/go/tools/cmd/staticcheck
	GO111MODULE=off go build -o $@ honnef.co/go/tools/cmd/staticcheck
$(BIN)/gocovmerge:
	GO111MODULE=off go get github.com/wadey/gocovmerge
	GO111MODULE=off go build -o $@ github.com/wadey/gocovmerge
$(BIN)/misspell:
	GO111MODULE=off go get github.com/client9/misspell
	GO111MODULE=off go build -o $@ github.com/client9/misspell/cmd/misspell

# Non-go tools downloaded from appropriate repository
PROTOC_VERSION := 3.6.1
ARCH := $(shell uname -m)
ifeq (x86_64,$(ARCH))
PROTOC_ARCH := x86_64
else ifneq ($(filter i386 i686,$(ARCH)),)
PROTOC_ARCH := x86_32
else ifneq ($(filter aarch64 armv8l,$(ARCH)),)
PROTOC_ARCH := aarch_64
endif
ifdef PROTOC_ARCH
PROTOC_URL := https://github.com/google/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-linux-$(PROTOC_ARCH).zip
$(BIN)/protoc:
	wget -q $(PROTOC_URL) -O /tmp/protoc.zip
	unzip -q -j /tmp/protoc.zip bin/protoc -d $(BIN)
else
PROTOC_PATH := $(shell which protoc)
$(BIN)/protoc: $(PROTOC_PATH)
ifneq ($(wildcard $(PROTOC_PATH)),)
	cp $< $@
else
	$(error Could not download protoc binary or locate it on the system. Please install it)
endif
endif
