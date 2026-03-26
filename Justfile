
_cargo_binstall_check := require("cargo-binstall")

default:
  just -l

# Install required cargo tools
setup:
    cargo binstall cargo-audit cargo-deny cargo-outdated cargo-nextest

# Run all linters
lint: fmt-check clippy audit deny outdated

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

audit:
    cargo audit

deny:
    cargo deny check

outdated:
    cargo outdated --exit-code 1

# Build the project
build:
    cargo build --release

# Run offline unit tests only
test:
    cargo test --no-default-features

# Run all tests including network tests
test-all:
    cargo test

# Run the server locally (requires CAMO_SECRET_KEY env var)
run:
    cargo run -- --secret-key "${CAMO_SECRET_KEY:-changeme}"

# Build the Docker image locally
docker-build:
    docker build -t camoflage .

# Lint the Helm chart
helm-lint:
    helm lint helm/camoflage
