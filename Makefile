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

NAME = fscrypt

INSTALL = install
DESTDIR = /usr/local/bin

CMD_PKG = github.com/google/$(NAME)/cmd/$(NAME)

SRC_FILES = $(shell find . -type f -name '*.go' -o -name "*.h" -o -name "*.c")
GO_FILES = $(shell find . -type f -name '*.go' -not -path "./vendor/*")
PROTO_FILES = $(shell find . -type f -name '*.proto' -not -path "./vendor/*")
C_FILES = $(shell find . -type f -name "*.h" -o -name "*.c" -not -path "./vendor/*")
GO_PKGS = $(shell go list ./... | grep -v /vendor/)

# IMAGE will be the path to our test ext4 image file.
IMAGE ?= $(NAME)_image

# MOUNT will be the path to the filesystem where our tests are run.
#
# Running "make test-setup MOUNT=/foo/bar" creates a test filesystem at that
#	location. Be sure to also run "make test-teardown MOUNT=/foo/bar".
# Running "make all MOUNT=/foo/bar" (or "make go") will run all tests on that
# 	filesystem. By default, it is the one created with "make test-setup".
MOUNT ?= /mnt/$(NAME)_mount
# Only run the integration tests if our root exists.
ifneq ("$(wildcard $(MOUNT))","")
export TEST_FILESYSTEM_ROOT = $(MOUNT)
endif
# The flags code below lets the caller of the makefile change the build flags
# for fscrypt in a familiar manner.
#	CFLAGS
#		Change the flags passed to the C compiler. Default = "-O2 -Wall"
#		For example:
#			make fscrypt "CFLAGS = -O3 -Werror"
#		builds the C code with high optimizations, and C warnings fail.
#	LDFLAGS
#		Change the flags passed to the C linker. Empty by default.
#		For example:
#			make fscrypt "LDFLAGS = -static -luuid -ldl -laudit -lpthread"
#		will build a static binary.
#	GO_FLAGS
#		Change the flags passed to "go build". Empty by default.
#		For example:
#			make fscrypt "GO_FLAGS = -race"
#		will build the Go code with race detection.
#	GO_LINK_FLAGS
#		Change the flags passed to the Go linker. Default = "-s -w"
#		For example:
#			make fscrypt GO_LINK_FLAGS=""
#		will not strip the binary.

# Set the C flags so we don't need to set C flags in each CGO file.
CFLAGS ?= -O2 -Wall
export CGO_CFLAGS = $(CFLAGS)

# By default, we strip the binary to reduce size.
GO_LINK_FLAGS ?= -s -w
# Pass the version to the command line program (pulled from tags).
VERSION_FLAG = -X "main.version=$(shell git describe --tags)"
# Pass the current date and time to the command line program.
DATE_FLAG = -X "main.buildTime=$(shell date)"
# Add the version, date, and any specified LDFLAGS to any user-specified flags.
override GO_LINK_FLAGS += $(VERSION_FLAG) $(DATE_FLAG) -extldflags "$(LDFLAGS)"
# Add the link flags to any user-specified flags.
override GO_FLAGS += --ldflags '$(GO_LINK_FLAGS)'

.PHONY: default all
default: $(NAME)
all: gen update format lint default test

$(NAME): $(SRC_FILES)
	go build $(GO_FLAGS) -o $(NAME) $(CMD_PKG)

.PHONY: clean
clean:
	rm -rf $(NAME) $(IMAGE)

# Make sure go files build and tests pass.
.PHONY: test
test:
	@go test -p 1 $(GO_FLAGS) $(GO_PKGS)

# Make sure the protocol buffers are generated
.PHONY: gen
gen:
	protoc --go_out=. $(PROTO_FILES)

# Update the vendored dependencies.
.PHONY: update
update:
	@govendor init
	@govendor fetch +missing
	@govendor add +external
	@govendor remove +unused

# Format all the Go and C code
.PHONY: format
format:
	@gofmt -l -s -w $(GO_FILES)
	@clang-format -i -style=Google $(C_FILES)

# Run lint rules (skipping generated files)
.PHONY: lint
lint:
	@go vet $(GO_PKGS)
	@golint $(GO_PKGS) | grep -v "pb.go" | ./input_fail.py
	@megacheck -unused.exported $(GO_PKGS)

.PHONY: install
install: $(NAME)
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) $(NAME) $(DESTDIR)

.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)/$(NAME)

# Install the go tools used for checking/generating the code
.PHONY: go-tools
go-tools:
	go get -u github.com/golang/protobuf/protoc-gen-go
	go get -u github.com/golang/lint/golint
	go get -u github.com/kardianos/govendor
	go get -u honnef.co/go/tools/cmd/megacheck

##### Setup/Teardown for integration tests (need root permissions) #####
.PHONY: test-setup test-teardown
test-setup:
	dd if=/dev/zero of=$(IMAGE) bs=1M count=20
	mkfs.ext4 -b 4096 -O encrypt $(IMAGE) -F
	sudo mkdir -p $(MOUNT)
	sudo mount -o rw,loop $(IMAGE) $(MOUNT)
	sudo chmod +777 $(MOUNT)
	# Add UUID to BLKID cache
	sudo blkid $$(df $(MOUNT) --output=source | grep /dev/)

test-teardown:
	sudo umount $(MOUNT)
	sudo rmdir $(MOUNT)
	rm -f $(IMAGE)

##### Commands for Travis CI #####

.PHONY: check
check: lint default test
	@govendor list +missing +external +unused \
	| ./input_fail.py "Incorrect vendored dependencies. Run \"make update\"."
	@gofmt -s -d $(GO_FILES) \
	| ./input_fail.py "Incorrectly formatted Go files. Run \"make format\"."
	@clang-format -i -style=Google -output-replacements-xml $(C_FILES) \
	| grep "<replacement "
	| ./input_fail.py "Incorrectly formatted C files. Run \"make format\"." 
