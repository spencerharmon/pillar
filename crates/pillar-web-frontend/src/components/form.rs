//! Structured `Form` field sets with inline validation.
//!
//! The validation is **pure logic** ([`FieldRule`], [`validate_field`],
//! [`validate_all`]) so every rule is host-tested; the Yew components render the
//! labelled controls and surface the validation messages inline.

/// A single validation rule for a form field value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldRule {
    /// The (trimmed) value must be non-empty.
    Required,
    /// The value's char length must be at least `n`.
    MinLen(usize),
    /// The value's char length must be at most `n`.
    MaxLen(usize),
    /// The value must be a valid `i64` integer.
    Integer,
}

impl FieldRule {
    /// Check `value` against this rule, returning an error message on failure.
    #[must_use]
    pub fn check(&self, value: &str) -> Option<String> {
        match self {
            FieldRule::Required => {
                if value.trim().is_empty() {
                    Some("This field is required.".to_owned())
                } else {
                    None
                }
            }
            FieldRule::MinLen(n) => {
                if value.chars().count() < *n {
                    Some(format!("Must be at least {n} characters."))
                } else {
                    None
                }
            }
            FieldRule::MaxLen(n) => {
                if value.chars().count() > *n {
                    Some(format!("Must be at most {n} characters."))
                } else {
                    None
                }
            }
            FieldRule::Integer => {
                if value.trim().parse::<i64>().is_ok() {
                    None
                } else {
                    Some("Must be a whole number.".to_owned())
                }
            }
        }
    }
}

/// Validate `value` against `rules` in order, returning the FIRST failure's
/// message (or `None` when every rule passes).
#[must_use]
pub fn validate_field(value: &str, rules: &[FieldRule]) -> Option<String> {
    rules.iter().find_map(|r| r.check(value))
}

/// Validate a set of `(field-name, value, rules)` triples, returning the
/// `(field-name, message)` pairs that failed. An empty result means the whole
/// form is valid.
#[must_use]
pub fn validate_all(fields: &[(String, String, Vec<FieldRule>)]) -> Vec<(String, String)> {
    fields
        .iter()
        .filter_map(|(name, value, rules)| {
            validate_field(value, rules).map(|msg| (name.clone(), msg))
        })
        .collect()
}

#[cfg(feature = "yew")]
pub use yew_impl::{FormField, FormFieldProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{validate_field, FieldRule};
    use yew::prelude::*;

    /// Props for [`FormField`].
    #[derive(Properties, PartialEq)]
    pub struct FormFieldProps {
        /// The field label.
        pub label: AttrValue,
        /// The current value.
        #[prop_or_default]
        pub value: AttrValue,
        /// Placeholder text.
        #[prop_or_default]
        pub placeholder: AttrValue,
        /// The validation rules, evaluated live for the inline message.
        #[prop_or_default]
        pub rules: Vec<FieldRule>,
        /// Input handler.
        #[prop_or_default]
        pub oninput: Callback<InputEvent>,
        /// Whether to show the validation message (typically after a blur /
        /// submit attempt).
        #[prop_or(true)]
        pub show_error: bool,
    }

    /// A labelled input with an inline validation message derived from the pure
    /// [`validate_field`].
    #[function_component(FormField)]
    pub fn form_field(props: &FormFieldProps) -> Html {
        let error = if props.show_error {
            validate_field(props.value.as_str(), &props.rules)
        } else {
            None
        };
        let invalid = error.is_some();
        html! {
            <div class={classes!("pillar-formfield", invalid.then_some("is-invalid"))}>
                <label class="pillar-formfield__label">{ props.label.clone() }</label>
                <input
                    class="pillar-formfield__input"
                    aria-invalid={invalid.to_string()}
                    value={props.value.clone()}
                    placeholder={props.placeholder.clone()}
                    oninput={props.oninput.clone()}
                />
                if let Some(msg) = error {
                    <p class="pillar-formfield__error" role="alert">{ msg }</p>
                }
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_rejects_blank_accepts_content() {
        assert!(FieldRule::Required.check("   ").is_some());
        assert!(FieldRule::Required.check("x").is_none());
    }

    #[test]
    fn length_rules_bound_char_count() {
        assert!(FieldRule::MinLen(3).check("ab").is_some());
        assert!(FieldRule::MinLen(3).check("abc").is_none());
        assert!(FieldRule::MaxLen(2).check("abc").is_some());
        assert!(FieldRule::MaxLen(2).check("ab").is_none());
    }

    #[test]
    fn integer_rule_parses_whole_numbers_only() {
        assert!(FieldRule::Integer.check("42").is_none());
        assert!(FieldRule::Integer.check("-7").is_none());
        assert!(FieldRule::Integer.check("3.5").is_some());
        assert!(FieldRule::Integer.check("abc").is_some());
    }

    #[test]
    fn validate_field_returns_the_first_failure() {
        let rules = vec![FieldRule::Required, FieldRule::MinLen(3)];
        // Blank fails Required first.
        assert_eq!(
            validate_field("", &rules).as_deref(),
            Some("This field is required.")
        );
        // Non-blank but short fails MinLen.
        assert!(validate_field("ab", &rules)
            .unwrap()
            .contains("at least 3"));
        // Valid.
        assert!(validate_field("abcd", &rules).is_none());
    }

    #[test]
    fn validate_all_collects_only_failing_fields() {
        let fields = vec![
            ("name".into(), "".into(), vec![FieldRule::Required]),
            ("age".into(), "42".into(), vec![FieldRule::Integer]),
            ("bio".into(), "x".into(), vec![FieldRule::MinLen(5)]),
        ];
        let errs = validate_all(&fields);
        // name and bio fail; age passes.
        assert_eq!(errs.len(), 2);
        assert!(errs.iter().any(|(f, _)| f == "name"));
        assert!(errs.iter().any(|(f, _)| f == "bio"));
        assert!(!errs.iter().any(|(f, _)| f == "age"));
    }
}
