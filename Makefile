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
C_FILES = $(shell find . -type f -name "*.h" -o -name "*.c" -not -path "./vendor/*")
GO_PKGS = $(shell go list ./... | grep -v /vendor/)

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
all: update go format lint default

$(NAME): $(SRC_FILES)
	go build $(GO_FLAGS) -o $(NAME) $(CMD_PKG)

.PHONY: clean
clean:
	rm -rf $(NAME)

# Make sure go files build and tests pass.
.PHONY: go
go:
	@go generate $(GO_FLAGS) $(GO_PKGS)
	@go build $(GO_FLAGS) $(GO_PKGS)
	@go test -p 1 $(GO_FLAGS) $(GO_PKGS)

# Update the vendored dependencies.
.PHONY: update
update:
	@govendor init
	@govendor fetch +missing
	@govendor add +external
	@govendor remove +unused

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

# Check all files
.PHONY: check
check: all 
	@govendor list +missing +external +unused \
	| ./input_fail.py "Incorrect vendored dependencies. Run \"make update\""
	@git diff
	@git status -s \
	| ./input_fail.py "Files have changed unexpectedly. Run \"make all\""

.PHONY: install
install: $(NAME)
	$(INSTALL) -d $(DESTDIR)
	$(INSTALL) $(NAME) $(DESTDIR)

.PHONY: uninstall
uninstall:
	rm -rf $(DESTDIR)/$(NAME)
