.PHONY: setup build test verify demo web-dev

setup:
	cd web && npm ci

build: setup
	cd web && npm run build
	go build ./cmd/atlas

test: setup
	go test -race . ./cmd/... ./internal/...
	cd web && npm test -- --run

verify: setup
	go vet . ./cmd/... ./internal/...
	cd web && npm run lint
	./scripts/verify-git-identity.sh

demo: setup
	cd web && npm run build:api
	go run ./cmd/atlas demo

web-dev:
	cd web && npm run dev
