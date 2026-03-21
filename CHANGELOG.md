# Changelog

## 0.2.0 (2026-03-21)

- Add Default trait implementation for MaskedString
- Add From<&str> and From<String> implementations for MaskedString
- Add mask_ssn() function for Social Security Number masking
- Add mask_iban() function for IBAN masking
- Add #[must_use] attributes on all public functions and methods

## 0.1.7 (2026-03-17)

- Add readme, rust-version, documentation to Cargo.toml
- Add Development section to README
## 0.1.6 (2026-03-16)

- Update install snippet to use full version

## 0.1.5 (2026-03-16)

- Add README badges
- Synchronize version across Cargo.toml, README, and CHANGELOG

## 0.1.0 (2026-03-15)

- Initial release
- `mask_string()`, `mask_partial()` for basic masking
- `mask_email()`, `mask_credit_card()`, `mask_phone()` for structured data
- `MaskedString` wrapper with safe Debug/Display
- `mask_digits()`, `mask_between()` for pattern-based masking
- Zero dependencies
