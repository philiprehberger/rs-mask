# rs-mask

[![CI](https://github.com/philiprehberger/rs-mask/actions/workflows/ci.yml/badge.svg)](https://github.com/philiprehberger/rs-mask/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/philiprehberger-mask.svg)](https://crates.io/crates/philiprehberger-mask)
[![License](https://img.shields.io/github/license/philiprehberger/rs-mask)](LICENSE)

Data masking and redaction for strings, emails, and sensitive data.

## Installation

```toml
[dependencies]
philiprehberger-mask = "0.1.2"
```

## Usage

```rust
use philiprehberger_mask::{mask_email, mask_credit_card, mask_partial, MaskedString};

// Mask an email
assert_eq!(mask_email("john@example.com"), "j***@example.com");

// Mask a credit card
assert_eq!(mask_credit_card("4111-1111-1111-1111"), "****-****-****-1111");

// Partial masking
assert_eq!(mask_partial("SSN123456789", 4), "********6789");

// Safe wrapper for logging
let secret = MaskedString::new("my-api-key-123");
println!("{}", secret);       // prints "**************"
println!("{:?}", secret);     // prints MaskedString("**************")
assert_eq!(secret.reveal(), "my-api-key-123");
```

## API

| Function / Type | Description |
|-----------------|-------------|
| `mask_string(s)` | Replace all characters with `*` |
| `mask_partial(s, show_last)` | Mask all but last N characters |
| `mask_email(s)` | Mask email local part |
| `mask_credit_card(s)` | Mask all but last 4 digits |
| `mask_phone(s)` | Mask phone digits except last 4 |
| `mask_digits(s)` | Replace all digits with `*` |
| `mask_between(s, start, end)` | Mask content between markers |
| `MaskedString::new(s)` | Create a masked wrapper |
| `.reveal()` | Get the real value |

## License

MIT
