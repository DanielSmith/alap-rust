# Alap Expression Parser — Rust

Server-side Rust port of the Alap expression parser (`src/core/ExpressionParser.ts`). Use this to resolve Alap expressions in Rust servers without a Node.js sidecar.

## What's included

- **`alap-core` crate** — Recursive descent parser for the Alap expression grammar, macro expansion, regex search, config merging, URL sanitization, regex validation

## What's NOT included

This is the server-side subset of `alap/core`. It covers expression parsing, config merging, URL sanitization, and regex validation — everything a server needs to resolve cherry-pick and query requests.

Browser-side concerns (DOM rendering, menu positioning, event handling) are handled by the JavaScript client and are not ported here.

## Supported expression syntax

```
item1, item2              # item IDs (comma-separated)
.coffee                   # tag query
.nyc + .bridge            # AND (intersection)
.nyc | .sf                # OR (union)
.nyc - .tourist           # WITHOUT (subtraction)
(.nyc | .sf) + .open      # parenthesized grouping
@favorites                # macro expansion
/mypattern/               # regex search (by pattern key)
/mypattern/lu             # regex with field options
```

## Usage

```rust
use alap_core::{Config, ExpressionParser, resolve, cherry_pick, merge_configs, sanitize_url};

let config: Config = serde_json::from_str(r#"{
    "allLinks": {
        "item1": { "label": "Example", "url": "https://example.com", "tags": ["demo"] },
        "item2": { "label": "Other",   "url": "https://other.com",   "tags": ["demo", "test"] }
    },
    "macros": {
        "all": { "linkItems": ".demo" }
    }
}"#).unwrap();

// Low-level: get matching IDs
let mut parser = ExpressionParser::new(&config);
let ids = parser.query(".demo", "");           // ["item1", "item2"]
let ids = parser.query(".demo - .test", "");   // ["item1"]

// Resolve: expression → full link objects (URLs sanitized)
let results = resolve(&config, ".demo");

// Cherry-pick: expression → HashMap<id, Link> (URLs sanitized)
let subset = cherry_pick(&config, ".test");

// Merge multiple configs
let merged = merge_configs(&[&config1, &config2]);

// URL sanitization (standalone)
let safe = sanitize_url("javascript:alert(1)"); // "about:blank"
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
alap-core = { path = "path/to/src/other-languages/rust" }
```

## Tests

```bash
cd src/other-languages/rust
cargo test
cargo clippy
```

35 tests across 8 tiers: operands, commas, operators, chaining, macros, parentheses, edge cases, and URL sanitization.

## Example Server

- [axum-sqlite](../../../examples/servers/axum-sqlite/) — Rust + Axum + rusqlite, all 7 endpoints
