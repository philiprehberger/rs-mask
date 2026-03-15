//! # philiprehberger-mask
//!
//! Data masking and redaction for strings, emails, and sensitive data.
//! Zero dependencies — std only.
//!
//! # Examples
//!
//! ```
//! use philiprehberger_mask::{mask_string, mask_email, mask_credit_card, MaskedString};
//!
//! assert_eq!(mask_string("secret"), "******");
//! assert_eq!(mask_email("john@example.com"), "j***@example.com");
//! assert_eq!(mask_credit_card("4111-1111-1111-1111"), "****-****-****-1111");
//!
//! let masked = MaskedString::new("api-key-123");
//! println!("{}", masked); // prints "***********"
//! assert_eq!(masked.reveal(), "api-key-123");
//! ```

use std::fmt;
use std::hash::{Hash, Hasher};

/// Replace all characters in a string with `*`.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_string;
/// assert_eq!(mask_string("hello"), "*****");
/// assert_eq!(mask_string(""), "");
/// ```
pub fn mask_string(s: &str) -> String {
    s.chars().map(|_| '*').collect()
}

/// Mask all but the last `show_last` characters.
///
/// If `show_last` is greater than or equal to the string length, returns the
/// original string unchanged.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_partial;
/// assert_eq!(mask_partial("12345678", 4), "****5678");
/// ```
pub fn mask_partial(s: &str, show_last: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    if show_last >= len {
        return s.to_string();
    }
    let mask_count = len - show_last;
    let mut result = String::with_capacity(s.len());
    for (i, &ch) in chars.iter().enumerate() {
        if i < mask_count {
            result.push('*');
        } else {
            result.push(ch);
        }
    }
    result
}

/// Mask an email address.
///
/// Shows the first character of the local part, masks the rest of the local
/// part, and keeps the domain intact. If no `@` is found, falls back to
/// [`mask_string`].
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_email;
/// assert_eq!(mask_email("john.doe@example.com"), "j*******@example.com");
/// assert_eq!(mask_email("noatsign"), "********");
/// ```
pub fn mask_email(s: &str) -> String {
    match s.find('@') {
        Some(at_pos) => {
            let local = &s[..at_pos];
            let domain = &s[at_pos..]; // includes '@'
            if local.is_empty() {
                return domain.to_string();
            }
            let mut chars = local.chars();
            let first = chars.next().unwrap();
            let masked_rest: String = chars.map(|_| '*').collect();
            format!("{first}{masked_rest}{domain}")
        }
        None => mask_string(s),
    }
}

/// Mask a credit card number, preserving formatting.
///
/// Replaces all digits except the last 4 with `*`. Non-digit characters
/// (dashes, spaces) remain in their original positions.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_credit_card;
/// assert_eq!(mask_credit_card("4111-1111-1111-1111"), "****-****-****-1111");
/// assert_eq!(mask_credit_card("4111 1111 1111 1111"), "**** **** **** 1111");
/// ```
pub fn mask_credit_card(s: &str) -> String {
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    let show_last = 4usize;
    let mask_digits_count = digit_count.saturating_sub(show_last);

    let mut digits_seen = 0usize;
    s.chars()
        .map(|ch| {
            if ch.is_ascii_digit() {
                digits_seen += 1;
                if digits_seen <= mask_digits_count {
                    '*'
                } else {
                    ch
                }
            } else {
                ch
            }
        })
        .collect()
}

/// Mask digits in a phone number except the last 4 digits.
///
/// Non-digit characters remain in their original positions.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_phone;
/// assert_eq!(mask_phone("+1 (555) 123-4567"), "+* (***) ***-4567");
/// ```
pub fn mask_phone(s: &str) -> String {
    let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
    let show_last = 4usize;
    let mask_digits_count = digit_count.saturating_sub(show_last);

    let mut digits_seen = 0usize;
    s.chars()
        .map(|ch| {
            if ch.is_ascii_digit() {
                digits_seen += 1;
                if digits_seen <= mask_digits_count {
                    '*'
                } else {
                    ch
                }
            } else {
                ch
            }
        })
        .collect()
}

/// Replace all ASCII digits in a string with `*`.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_digits;
/// assert_eq!(mask_digits("order-12345"), "order-*****");
/// ```
pub fn mask_digits(s: &str) -> String {
    s.chars()
        .map(|ch| if ch.is_ascii_digit() { '*' } else { ch })
        .collect()
}

/// Mask content between the first occurrence of `start_marker` and the
/// following `end_marker`.
///
/// The markers themselves are preserved. If either marker is not found, the
/// original string is returned unchanged.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::mask_between;
/// assert_eq!(
///     mask_between("token: [SECRET] end", "[", "]"),
///     "token: [******] end"
/// );
/// ```
pub fn mask_between(s: &str, start_marker: &str, end_marker: &str) -> String {
    let Some(start_pos) = s.find(start_marker) else {
        return s.to_string();
    };
    let after_start = start_pos + start_marker.len();
    let Some(end_pos) = s[after_start..].find(end_marker) else {
        return s.to_string();
    };
    let end_abs = after_start + end_pos;
    let content = &s[after_start..end_abs];
    let masked_content: String = content.chars().map(|_| '*').collect();

    let mut result = String::with_capacity(s.len());
    result.push_str(&s[..after_start]);
    result.push_str(&masked_content);
    result.push_str(&s[end_abs..]);
    result
}

/// A wrapper around a `String` that masks its value in `Debug` and `Display`
/// output, preventing accidental exposure in logs.
///
/// # Examples
///
/// ```
/// use philiprehberger_mask::MaskedString;
///
/// let secret = MaskedString::new("my-api-key");
/// assert_eq!(format!("{}", secret), "**********");
/// assert_eq!(format!("{:?}", secret), "MaskedString(\"**********\")");
/// assert_eq!(secret.reveal(), "my-api-key");
/// ```
#[derive(Clone)]
pub struct MaskedString {
    value: String,
}

impl MaskedString {
    /// Create a new `MaskedString` wrapping the given value.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Returns the actual (unmasked) value.
    pub fn reveal(&self) -> &str {
        &self.value
    }

    /// Returns the length of the original string.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns `true` if the original string is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn masked(&self) -> String {
        "*".repeat(self.value.len())
    }
}

impl fmt::Display for MaskedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.masked())
    }
}

impl fmt::Debug for MaskedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MaskedString(\"{}\")", self.masked())
    }
}

impl PartialEq for MaskedString {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for MaskedString {}

impl Hash for MaskedString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    // mask_string tests

    #[test]
    fn test_mask_string_basic() {
        assert_eq!(mask_string("hello"), "*****");
        assert_eq!(mask_string("a"), "*");
        assert_eq!(mask_string("test123"), "*******");
    }

    #[test]
    fn test_mask_string_empty() {
        assert_eq!(mask_string(""), "");
    }

    #[test]
    fn test_mask_string_unicode() {
        assert_eq!(mask_string("hi!"), "***");
    }

    // mask_partial tests

    #[test]
    fn test_mask_partial_basic() {
        assert_eq!(mask_partial("12345678", 4), "****5678");
    }

    #[test]
    fn test_mask_partial_show_none() {
        assert_eq!(mask_partial("secret", 0), "******");
    }

    #[test]
    fn test_mask_partial_show_all() {
        assert_eq!(mask_partial("abc", 3), "abc");
    }

    #[test]
    fn test_mask_partial_show_more_than_length() {
        assert_eq!(mask_partial("abc", 10), "abc");
    }

    #[test]
    fn test_mask_partial_empty() {
        assert_eq!(mask_partial("", 4), "");
    }

    #[test]
    fn test_mask_partial_show_one() {
        assert_eq!(mask_partial("abcdef", 1), "*****f");
    }

    // mask_email tests

    #[test]
    fn test_mask_email_basic() {
        assert_eq!(mask_email("john.doe@example.com"), "j*******@example.com");
    }

    #[test]
    fn test_mask_email_short_local() {
        assert_eq!(mask_email("a@example.com"), "a@example.com");
    }

    #[test]
    fn test_mask_email_no_at() {
        assert_eq!(mask_email("noatsign"), "********");
    }

    #[test]
    fn test_mask_email_two_char_local() {
        assert_eq!(mask_email("ab@test.com"), "a*@test.com");
    }

    // mask_credit_card tests

    #[test]
    fn test_mask_credit_card_dashes() {
        assert_eq!(
            mask_credit_card("4111-1111-1111-1111"),
            "****-****-****-1111"
        );
    }

    #[test]
    fn test_mask_credit_card_spaces() {
        assert_eq!(
            mask_credit_card("4111 1111 1111 1111"),
            "**** **** **** 1111"
        );
    }

    #[test]
    fn test_mask_credit_card_plain() {
        assert_eq!(mask_credit_card("4111111111111111"), "************1111");
    }

    #[test]
    fn test_mask_credit_card_short() {
        assert_eq!(mask_credit_card("1234"), "1234");
    }

    #[test]
    fn test_mask_credit_card_fewer_than_4_digits() {
        assert_eq!(mask_credit_card("12"), "12");
    }

    // mask_phone tests

    #[test]
    fn test_mask_phone_us_format() {
        assert_eq!(mask_phone("+1 (555) 123-4567"), "+* (***) ***-4567");
    }

    #[test]
    fn test_mask_phone_plain_digits() {
        assert_eq!(mask_phone("15551234567"), "*******4567");
    }

    #[test]
    fn test_mask_phone_short() {
        assert_eq!(mask_phone("1234"), "1234");
    }

    #[test]
    fn test_mask_phone_international() {
        assert_eq!(mask_phone("+44 20 7946 0958"), "+** ** **** 0958");
    }

    // mask_digits tests

    #[test]
    fn test_mask_digits_basic() {
        assert_eq!(mask_digits("order-12345"), "order-*****");
    }

    #[test]
    fn test_mask_digits_no_digits() {
        assert_eq!(mask_digits("hello"), "hello");
    }

    #[test]
    fn test_mask_digits_all_digits() {
        assert_eq!(mask_digits("12345"), "*****");
    }

    #[test]
    fn test_mask_digits_mixed() {
        assert_eq!(mask_digits("a1b2c3"), "a*b*c*");
    }

    // mask_between tests

    #[test]
    fn test_mask_between_basic() {
        assert_eq!(
            mask_between("token: [SECRET] end", "[", "]"),
            "token: [******] end"
        );
    }

    #[test]
    fn test_mask_between_no_start() {
        assert_eq!(
            mask_between("no markers here", "[", "]"),
            "no markers here"
        );
    }

    #[test]
    fn test_mask_between_no_end() {
        assert_eq!(
            mask_between("start [but no end", "[", "]"),
            "start [but no end"
        );
    }

    #[test]
    fn test_mask_between_multi_char_markers() {
        assert_eq!(
            mask_between("key: <<hidden>> done", "<<", ">>"),
            "key: <<******>> done"
        );
    }

    #[test]
    fn test_mask_between_empty_content() {
        assert_eq!(mask_between("empty [] here", "[", "]"), "empty [] here");
    }

    // MaskedString tests

    #[test]
    fn test_masked_string_display() {
        let ms = MaskedString::new("secret");
        assert_eq!(format!("{}", ms), "******");
    }

    #[test]
    fn test_masked_string_debug() {
        let ms = MaskedString::new("secret");
        assert_eq!(format!("{:?}", ms), "MaskedString(\"******\")");
    }

    #[test]
    fn test_masked_string_reveal() {
        let ms = MaskedString::new("my-api-key");
        assert_eq!(ms.reveal(), "my-api-key");
    }

    #[test]
    fn test_masked_string_len() {
        let ms = MaskedString::new("hello");
        assert_eq!(ms.len(), 5);
    }

    #[test]
    fn test_masked_string_is_empty() {
        assert!(MaskedString::new("").is_empty());
        assert!(!MaskedString::new("x").is_empty());
    }

    #[test]
    fn test_masked_string_equality() {
        let a = MaskedString::new("same");
        let b = MaskedString::new("same");
        let c = MaskedString::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_masked_string_hash_consistency() {
        let a = MaskedString::new("test");
        let b = MaskedString::new("test");

        let hash_a = {
            let mut h = DefaultHasher::new();
            a.hash(&mut h);
            h.finish()
        };
        let hash_b = {
            let mut h = DefaultHasher::new();
            b.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_masked_string_clone() {
        let original = MaskedString::new("clone-me");
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert_eq!(cloned.reveal(), "clone-me");
    }

    #[test]
    fn test_masked_string_from_string() {
        let ms = MaskedString::new(String::from("owned"));
        assert_eq!(ms.reveal(), "owned");
    }
}
