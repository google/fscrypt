// +build tools
// Never compiled, just used to manage tool dependencies

package tools

import (
	_ "github.com/client9/misspell/cmd/misspell"
	_ "github.com/wadey/gocovmerge"
	_ "golang.org/x/lint/golint"
	_ "golang.org/x/tools/cmd/goimports"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
