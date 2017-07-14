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

CFLAGS += -O2 -Wall
CMD_DIR = github.com/google/$(NAME)/cmd/$(NAME)

# The code below lets the caller of the makefile change the build flags for
# fscrypt in a familiar manner. For example, to force the program to statically
# link its C components, run "make fscrypt" with:
#	make fscrypt "LDFLAGS += -static -luuid -ldl -laudit -lpthread"
#
# Similarly, to modify the flags passed to the C components, just modify CFLAGS
# or LDFLAGS as you would with a C program. To modify the Go flags, either
# modify GO_FLAGS or GO_LINK_FLAGS (as appropriate).

# Set the C flags so we don't need to set C flags in each CGO file.
export CGO_CFLAGS = $(CFLAGS)

# Pass the version to the command line program (pulled from tags)
VERSION_FLAG = -X "main.version=$(shell git describe --tags)"
# Pass the current date and time to the command line program
DATE_FLAG = -X "main.buildTime=$(shell date)"
# Pass the C linking flags into Go
GO_LINK_FLAGS += -s -w $(VERSION_FLAG) $(DATE_FLAG) -extldflags "$(LDFLAGS)"
GOFLAGS += --ldflags '$(GO_LINK_FLAGS)'

.PHONY: default all $(NAME) go update lint format install clean

default: $(NAME)
all: update go format lint $(NAME)

$(NAME):
	go build $(GOFLAGS) -o $(NAME) $(CMD_DIR)

# Makes sure go files build and tests pass
go:
	govendor generate +local
	govendor build $(GOFLAGS) +local
	govendor test $(GOFLAGS) -p 1 +local

update:
	@govendor fetch +missing
	@govendor add +external
	@govendor remove +unused

lint:
	@golint $$(go list ./... | grep -v vendor) | grep -v "pb.go" || true
	@govendor vet +local

format:
	@govendor fmt +local
	@find . -name "*.h" -o -name "*.c" -not -path "./vendor/*" | xargs clang-format -i -style=Google

install:
	go install $(GOFLAGS) $(CMD_DIR)

install_all:
	govendor install $(GOFLAGS) +local

TARBALL = $(NAME).$(shell date --iso-8601).tar.gz
$(TARBALL):
	git archive --format=tar.gz --output=$(TARBALL) HEAD
tarball: $(TARBALL)

clean:
	rm -rf $(NAME) $(TARBALL)
