# lists all available recipes
default:
    @just --list --justfile {{ justfile() }}

# Build the extension in development mode
build:
    uv run maturin develop

# Build in release mode
build-release:
    uv run maturin develop --release

# Run Python tests
test: build
    uv run pytest tests/ -v

# Check Rust compilation without building
check:
    cargo check

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format Rust code
fmt:
    cargo fmt

# Format and lint everything
tidy: fmt lint

# Clean all build artifacts
clean:
    cargo clean
    rm -rf .pytest_cache __pycache__ dist

# Build a wheel for distribution
wheel:
    uv run maturin build --release
