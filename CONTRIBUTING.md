# Contributing to Keep

## Getting Started

```bash
git clone https://github.com/privkeyio/keep
cd keep
cargo build
cargo test
```

Requires Rust 1.85+.

## Code Style

- Run `cargo fmt` before committing
- Run `cargo clippy -- -D warnings` and fix all warnings
- Follow existing code patterns

## Branch Naming

- `feature/<name>` - New features
- `fix/<name>` - Bug fixes
- `refactor/<name>` - Code refactoring
- `docs/<name>` - Documentation changes

## Commit Messages

Write atomic commits with clear reasoning:

```text
<type>: <short summary>

<why this change is needed>
<what the change does>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`

Example:
```text
fix: prevent memory exhaustion on malformed vault data

Unbounded deserialization could exhaust memory with crafted input.
Add size limits to bincode deserialization in hidden volume loading.
```

## Pull Requests

- One feature or fix per PR
- Reference related issues
- Include tests for new features
- Ensure CI passes (fmt, clippy, build, test)

## Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_frost_sign

# Run with output
cargo test -- --nocapture
```

New features require tests. Bug fixes should include regression tests.

## Code Review

All PRs require review before merging. Reviewers check:

- Code correctness and security
- Test coverage
- Style consistency
- Documentation for public APIs

## Issues

- Use `good first issue` label for newcomer-friendly tasks
- Use `bug` for defects
- Use `enhancement` for features

## Communication

- GitHub Issues for bugs and features
- GitHub Discussions for questions

## License

By contributing, you agree that your contributions will be licensed under AGPL-3.0-or-later.
