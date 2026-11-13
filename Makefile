.PHONY: build test release clean

APP := malenia
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(APP) ./cmd/malenia

test:
	go test ./...

# 四平台交叉编译，输出到 dist/
release:
	@rm -rf dist && mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-windows-amd64.exe ./cmd/malenia
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-windows-arm64.exe ./cmd/malenia
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-amd64       ./cmd/malenia
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(APP)-linux-arm64       ./cmd/malenia
	@ls -la dist/

clean:
	rm -rf dist $(APP) data/*.db
