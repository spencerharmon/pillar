//! `SecretReveal` — a **show-once secret surface** for values the server hands
//! back exactly once (an invite/reset temporary password, a freshly-registered
//! OAuth client secret). It renders the secret masked by default with a
//! reveal toggle and a copy-to-clipboard button, plus a persistent "shown only
//! once" warning — the best-in-class pattern (Okta activation link, Entra temp
//! password, GitHub personal-access-token) for a credential that cannot be
//! retrieved again.
//!
//! The masking is **pure logic** ([`mask`]) so it is host-tested with a plain
//! `cargo test`; the Yew component behind the `yew` feature is a thin wrapper
//! that toggles reveal state and drives the async Clipboard API.

/// Mask `secret` as a run of bullet characters of the SAME length (so the
/// field's shape is visible without leaking the value). An empty secret masks
/// to the empty string.
#[must_use]
pub fn mask(secret: &str) -> String {
    "\u{2022}".repeat(secret.chars().count())
}

#[cfg(feature = "yew")]
pub use yew_impl::{SecretReveal, SecretRevealProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::mask;
    use wasm_bindgen_futures::{spawn_local, JsFuture};
    use yew::prelude::*;

    /// Props for [`SecretReveal`].
    #[derive(Properties, PartialEq)]
    pub struct SecretRevealProps {
        /// A short human label for what the secret is (e.g. "Temporary
        /// password", "Client secret").
        pub label: AttrValue,
        /// The one-time secret value.
        pub secret: AttrValue,
    }

    /// A show-once secret box: masked value + reveal toggle + copy button +
    /// a persistent "shown only once" caption.
    #[function_component(SecretReveal)]
    pub fn secret_reveal(props: &SecretRevealProps) -> Html {
        let revealed = use_state(|| false);
        let copied = use_state(|| false);

        let toggle = {
            let revealed = revealed.clone();
            Callback::from(move |_: MouseEvent| revealed.set(!*revealed))
        };
        let copy = {
            let (secret, copied) = (props.secret.to_string(), copied.clone());
            Callback::from(move |_: MouseEvent| {
                if secret.is_empty() {
                    return;
                }
                let (secret, copied) = (secret.clone(), copied.clone());
                spawn_local(async move {
                    let Some(window) = web_sys::window() else {
                        return;
                    };
                    let clipboard = window.navigator().clipboard();
                    if JsFuture::from(clipboard.write_text(&secret)).await.is_ok() {
                        copied.set(true);
                    }
                });
            })
        };

        let shown = if *revealed {
            props.secret.to_string()
        } else {
            mask(props.secret.as_str())
        };

        html! {
            <div class="pillar-secret-reveal" role="group" aria-label={props.label.clone()}>
                <div class="pillar-secret-reveal__label">{ props.label.clone() }</div>
                <div class="pillar-secret-reveal__row">
                    <code class="pillar-secret-reveal__value" data-secret-field={props.label.clone()}>
                        { shown }
                    </code>
                    <button type="button" class="pillar-secret-reveal__toggle" onclick={toggle}>
                        { if *revealed { "Hide" } else { "Reveal" } }
                    </button>
                    <button
                        type="button"
                        class={classes!("pillar-secret-reveal__copy", copied.then_some("copied"))}
                        onclick={copy}
                    >{ if *copied { "Copied" } else { "Copy" } }</button>
                </div>
                <div class="pillar-secret-reveal__warn">
                    { "Shown only once \u{2014} copy it now. It cannot be retrieved again." }
                </div>
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mask;

    #[test]
    fn mask_matches_length_with_bullets() {
        assert_eq!(mask("abc"), "\u{2022}\u{2022}\u{2022}");
        assert_eq!(mask(""), "");
        // Unicode is counted by characters, not bytes.
        assert_eq!(mask("\u{e9}\u{e9}").chars().count(), 2);
    }
}
