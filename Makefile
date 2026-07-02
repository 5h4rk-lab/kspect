VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -X main.version=$(VERSION)

.PHONY: build test vet lint cover clean install docker demo release-snapshot

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/kspect ./cmd/kspect

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	gofmt -l . | (! grep .) || (echo "gofmt: files need formatting" && exit 1)

cover:
	go test -coverprofile=cover.out ./...
	go tool cover -func=cover.out | tail -1

install:
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/kspect

docker:
	docker build --build-arg VERSION=$(VERSION) -t kspect:$(VERSION) .

demo: build
	./bin/kspect scan --root testdata/rootfs-weak --color always || true

# Cross-compile release artifacts for the common server platforms.
release-snapshot:
	@mkdir -p dist
	@for target in linux/amd64 linux/arm64; do \
	  os=$${target%/*}; arch=$${target#*/}; \
	  out=dist/kspect_$(VERSION)_$${os}_$${arch}; \
	  echo "building $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	    go build -trimpath -ldflags "$(LDFLAGS)" -o $$out ./cmd/kspect; \
	done
	@cd dist && sha256sum kspect_* > SHA256SUMS

clean:
	rm -rf bin dist cover.out
