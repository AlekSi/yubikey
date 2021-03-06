// +build tools

package tools // import "github.com/AlekSi/yubikey/tools"

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/quasilyte/go-consistent"
	_ "github.com/reviewdog/reviewdog/cmd/reviewdog"
	_ "golang.org/x/perf/cmd/benchstat"
	_ "mvdan.cc/gofumpt/gofumports"
)

//go:generate go build -v -o ../bin/golangci-lint github.com/golangci/golangci-lint/cmd/golangci-lint
//go:generate go build -v -o ../bin/go-consistent github.com/quasilyte/go-consistent
//go:generate go build -v -o ../bin/reviewdog github.com/reviewdog/reviewdog/cmd/reviewdog
//go:generate go build -v -o ../bin/benchstat golang.org/x/perf/cmd/benchstat
//go:generate go build -v -o ../bin/gofumports mvdan.cc/gofumpt/gofumports
