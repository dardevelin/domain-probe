# domain-probe

Colorful CLI to inspect a URL/domain:
- HTTP status, server, content metadata
- redirect behavior (input URL + http/https variant)
- public IPv4/IPv6 records
- RDAP registration, expiry, registrar, and available contact details

## Build

```bash
cargo build --release
```

Binary:

```bash
./target/release/domain-probe
```

## Install For Shell Usage

```bash
cargo install --path . --locked
```

This installs `domain-probe` into `~/.cargo/bin`. Ensure that path is in `PATH` in your `~/.zshrc` or `~/.bashrc`.

## Example

```bash
domain-probe https://models.dev/api.json
```

## Modes and Flags

```bash
domain-probe --quick github.com
domain-probe --json stripe.com | jq
domain-probe --section whois,dns,summary cloudflare.com
domain-probe --no-color --quick example.com
domain-probe --timeout 5 example.com
domain-probe --verbose example.com
```
