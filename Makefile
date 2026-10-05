.PHONY: setup maintainer-setup build build-embedded build-pages test verify verify-maintainer demo app web-dev performance

setup:
	cd web && npm ci

maintainer-setup: setup
	git config --local core.hooksPath .githooks
	./scripts/verify-git-identity.sh

build: setup
	cd web && npm run build:embed
	go build ./cmd/atlas

build-embedded: build

build-pages: setup
	cd web && npm run build

test: setup
	go test -race . ./cmd/... ./internal/...
	cd web && npm test -- --run

verify: setup
	go vet . ./cmd/... ./internal/...
	cd web && npm run lint

verify-maintainer: verify
	./scripts/verify-git-identity.sh

demo: setup
	cd web && npm run build:embed
	go run ./cmd/atlas demo

app: setup
	cd web && npm run build:embed
	go run ./cmd/atlas app

performance: build-pages
	./scripts/check-bundle-budgets.sh web/dist
	go test -run TestScaleFixture5KResources20KRelationshipsIsDeterministic -count=1 ./internal/analysis
	go test -run '^$$' -bench BenchmarkAnalyzeScaleFixture5K20K -benchtime=1x -benchmem ./internal/analysis

web-dev:
	cd web && npm run dev
