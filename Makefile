.PHONY: clean lint test build \
		publish publish-latest image image-dev multi-arch-image-%

BIN_NAME := hub-agent-traefik
MAIN_DIRECTORY := ./cmd/agent

TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse --short HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),v0.0.0-$(SHA))
BUILD_DATE := $(shell date -u '+%Y-%m-%d_%I:%M:%S%p')
export DOCKER_BUILDKIT=1

DOCKER_BUILD_PLATFORMS ?= linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v6
DOCKER_IMAGE_TAG ?= $(if $(TAG_NAME),$(TAG_NAME),latest)
OUTPUT := $(if $(OUTPUT),$(OUTPUT),$(BIN_NAME))

default: clean lint test build

lint:
	golangci-lint run

clean:
	rm -rf cover.out

test: clean
	go test -v -race -cover ./...

build: clean
	@echo Version: $(VERSION) $(BUILD_DATE)
	CGO_ENABLED=0 go build -trimpath -ldflags '-X "github.com/traefik/hub-agent-traefik/pkg/version.date=${BUILD_DATE}" -X "github.com/traefik/hub-agent-traefik/pkg/version.version=${VERSION}" -X "github.com/traefik/hub-agent-traefik/pkg/version.commit=${SHA}"' -o ${OUTPUT} ${MAIN_DIRECTORY}

image: export GOOS := linux
image: export GOARCH := amd64
image: build
	docker build --build-arg VERSION=$(VERSION) -t ghcr.io/traefik/$(BIN_NAME):$(VERSION) .

image-dev: export GOOS := linux
image-dev: export GOARCH := amd64
image-dev: build
	docker build -t $(BIN_NAME):dev . -f ./dev.Dockerfile

dev: image-dev

## Build Multi archs Docker image
multi-arch-image-%:
	docker buildx build $(DOCKER_BUILDX_ARGS) --build-arg VERSION=$(VERSION) -t ghcr.io/traefik/$(BIN_NAME):$* --platform=$(DOCKER_BUILD_PLATFORMS) -f buildx.Dockerfile .

publish:
	docker push ghcr.io/traefik/$(BIN_NAME):$(VERSION)
