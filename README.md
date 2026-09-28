# runity

Ethereum vanity address generator in Rust.

Author: Ayodapo Adesiyan (`dapslegend`)

## What it does

Generate an address that matches a hex prefix and/or suffix. Local CPU only. No RPC. No mempool. No transfers.

```bash
cargo run --release -- --prefix dead --suffix beef
# {"address":"0xdead...beef"}

cargo run --release -- --prefix 00 --show-secret
# secret printed only when you ask
```

## Layout

| Path | Role |
|---|---|
| `src/generator.rs` | Parallel vanity search |
| `src/bin/vanity_gen.rs` | CLI |
| `Cargo.toml` | Crate root |

The old nested `Runity/` folder is gone. This is the project root.

## Not included

- No transaction watcher
- No dust sender
- No SSH fan-out
- No private-key database

Use for lab wallets and test fixtures you control.
