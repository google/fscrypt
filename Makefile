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
BUILD_DIR = build
CFLAGS += -O2 -Wall

CMD_DIR = $(NAME)/cmd/$(NAME)

# So we don't have to put our flags in each go file. This also lets the caller
# of the makefile change the build flags in the normal manner:
#	make fscrypt "LDFLAGS += -static"
export CGO_CFLAGS = $(CFLAGS)
ifdef LDFLAGS
	GOFLAGS += --ldflags '-extldflags "$(LDFLAGS)"'
endif

.PHONY: default all $(NAME) go update lint format install clean

default: $(NAME)
all: update go format lint $(NAME)

$(NAME):
	@mkdir -p $(BUILD_DIR)
	go build $(GOFLAGS) -o $(BUILD_DIR)/$(NAME) $(CMD_DIR)

# Makes sure go files build and tests pass
go:
	govendor generate $(GOFLAGS) +local
	govendor build $(GOFLAGS) +local
	govendor test $(GOFLAGS) +local

update:
	@govendor fetch +missing
	@govendor add +external
	@govendor remove +unused

lint:
	@golint $$(go list ./... | grep -v vendor) | grep -v "pb.go" || true
	@govendor vet +local

format:
	@govendor fmt +local

install:
	govendor install $(GOFLAGS) +local

clean:
	rm -rf $(BUILD_DIR)
