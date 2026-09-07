//! Yew component wrappers around the design-system styles in [`crate::styles`].
//!
//! Each component attaches the scoped class the corresponding style builder
//! produces, so the visual language lives in ONE place. These compile on the
//! native host (so `cargo test -p pillar-web-frontend` typechecks them) and on
//! `wasm32-unknown-unknown` (where they become real DOM in the portal bundle).
//! The whole module is gated behind the `yew` feature.

use crate::auth::use_auth;
use crate::styles::{self, ButtonVariant};
use crate::theme::{Motion, Theme};
use crate::webauthn::{self, CeremonyError};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

/// Read the ambient [`Theme`] from Yew context, falling back to the dark theme
/// when no provider is mounted (so a component is always usable standalone).
#[hook]
fn use_theme() -> Theme {
    use_context::<Theme>().unwrap_or_default()
}

/// Read the ambient [`Motion`] preference, falling back to full motion.
#[hook]
fn use_motion() -> Motion {
    use_context::<Motion>().unwrap_or(Motion::Full)
}

/// Props for [`Card`].
#[derive(Properties, PartialEq)]
pub struct CardProps {
    /// The card body.
    #[prop_or_default]
    pub children: Html,
}

/// A card surface with a mouse-tracking spotlight (updates the `--spot-x` /
/// `--spot-y` custom properties on pointer move so the radial glow follows the
/// cursor). Under reduced motion the tracking still positions the glow but does
/// not animate.
#[function_component(Card)]
pub fn card(props: &CardProps) -> Html {
    let class = styles::card_spotlight(&use_theme(), use_motion());
    let onmousemove = Callback::from(|e: MouseEvent| {
        use wasm_bindgen::JsCast;
        if let Some(target) = e.current_target() {
            if let Ok(el) = target.dyn_into::<web_sys::HtmlElement>() {
                let rect = el.get_bounding_client_rect();
                let x = f64::from(e.client_x()) - rect.left();
                let y = f64::from(e.client_y()) - rect.top();
                let _ = el
                    .style()
                    .set_property("--spot-x", &format!("{x}px"));
                let _ = el
                    .style()
                    .set_property("--spot-y", &format!("{y}px"));
            }
        }
    });
    html! {
        <div class={class} {onmousemove}>{ props.children.clone() }</div>
    }
}

/// Props for [`Button`].
#[derive(Properties, PartialEq)]
pub struct ButtonProps {
    /// Visual variant.
    #[prop_or(ButtonVariant::Primary)]
    pub variant: ButtonVariant,
    /// Disabled state.
    #[prop_or_default]
    pub disabled: bool,
    /// Click handler.
    #[prop_or_default]
    pub onclick: Callback<MouseEvent>,
    /// Button label / content.
    #[prop_or_default]
    pub children: Html,
}

/// A button in one of the [`ButtonVariant`]s.
#[function_component(Button)]
pub fn button(props: &ButtonProps) -> Html {
    let class = styles::button(&use_theme(), props.variant, use_motion());
    html! {
        <button {class} disabled={props.disabled} onclick={props.onclick.clone()}>
            { props.children.clone() }
        </button>
    }
}

/// Props for [`Input`].
#[derive(Properties, PartialEq)]
pub struct InputProps {
    /// Placeholder text.
    #[prop_or_default]
    pub placeholder: AttrValue,
    /// Current value.
    #[prop_or_default]
    pub value: AttrValue,
    /// Input event handler.
    #[prop_or_default]
    pub oninput: Callback<InputEvent>,
}

/// A text input field.
#[function_component(Input)]
pub fn input(props: &InputProps) -> Html {
    let class = styles::input(&use_theme(), use_motion());
    html! {
        <input
            {class}
            placeholder={props.placeholder.clone()}
            value={props.value.clone()}
            oninput={props.oninput.clone()}
        />
    }
}

/// Props for [`Dialog`].
#[derive(Properties, PartialEq)]
pub struct DialogProps {
    /// Dialog contents.
    #[prop_or_default]
    pub children: Html,
}

/// A modal dialog surface (scale/fade entrance, suppressed under reduced
/// motion).
#[function_component(Dialog)]
pub fn dialog(props: &DialogProps) -> Html {
    let class = styles::dialog(&use_theme(), use_motion());
    html! {
        <div class={class} role="dialog" aria-modal="true">{ props.children.clone() }</div>
    }
}

/// One combobox option.
#[derive(Clone, PartialEq)]
pub struct ComboOption {
    /// The value submitted on select.
    pub value: AttrValue,
    /// The user-visible label.
    pub label: AttrValue,
}

/// Props for [`Combobox`].
#[derive(Properties, PartialEq)]
pub struct ComboboxProps {
    /// The filtered options to show.
    #[prop_or_default]
    pub options: Vec<ComboOption>,
    /// Index of the currently highlighted option, if any.
    #[prop_or_default]
    pub selected: Option<usize>,
    /// Current query text.
    #[prop_or_default]
    pub query: AttrValue,
    /// Query change handler.
    #[prop_or_default]
    pub oninput: Callback<InputEvent>,
}

/// A combobox / typeahead: an [`Input`]-styled field plus a floating results
/// list on the overlay layer.
#[function_component(Combobox)]
pub fn combobox(props: &ComboboxProps) -> Html {
    let wrapper = styles::combobox(&use_theme(), use_motion());
    let field = styles::input(&use_theme(), use_motion());
    html! {
        <div class={wrapper}>
            <input
                class={field}
                role="combobox"
                aria-expanded={(!props.options.is_empty()).to_string()}
                value={props.query.clone()}
                oninput={props.oninput.clone()}
            />
            if !props.options.is_empty() {
                <ul class="pillar-combobox__list" role="listbox">
                    { for props.options.iter().enumerate().map(|(i, opt)| {
                        let is_sel = props.selected == Some(i);
                        html! {
                            <li
                                class="pillar-combobox__option"
                                role="option"
                                aria-selected={is_sel.to_string()}
                            >{ opt.label.clone() }</li>
                        }
                    }) }
                </ul>
            }
        </div>
    }
}

/// Props for [`SecurityKeyControls`].
#[derive(Properties, PartialEq)]
pub struct SecurityKeyControlsProps {
    /// Invoked when the user clicks "Register a security key". The parent
    /// runs the real registration ceremony ([`crate::webauthn::run_register`]
    /// against `navigator.credentials.create()`) and, on failure, feeds the
    /// resulting [`CeremonyError`] back in via `error`.
    #[prop_or_default]
    pub on_register: Callback<MouseEvent>,
    /// Invoked when the user clicks "Sign in with a security key" — runs
    /// [`crate::webauthn::run_authenticate`] against `navigator.credentials
    /// .get()`.
    #[prop_or_default]
    pub on_signin: Callback<MouseEvent>,
    /// Disables both buttons while a ceremony is in flight.
    #[prop_or_default]
    pub busy: bool,
    /// The most recent ceremony error, if any, surfaced in-UI. `None` renders
    /// no message.
    #[prop_or_default]
    pub error: Option<CeremonyError>,
}

/// The **security-key controls** that REPLACE the old fake "passkey" control
/// (a `type=password` field mislabeled "passkey"): a "Register a security
/// key" button (runs `navigator.credentials.create()`) and a "Sign in with a
/// security key" button (runs `navigator.credentials.get()`).
///
/// Ceremony errors (no authenticator, user cancel, unsupported browser,
/// network/protocol) surface through the `error` prop as the clear,
/// UI-ready [`CeremonyError::message`] in an `aria-live` alert region.
/// Password/passphrase custody remains a supported fallback the login screen
/// renders alongside this control.
#[function_component(SecurityKeyControls)]
pub fn security_key_controls(props: &SecurityKeyControlsProps) -> Html {
    html! {
        <div class="pillar-security-key">
            <Button
                variant={ButtonVariant::Primary}
                disabled={props.busy}
                onclick={props.on_register.clone()}
            >
                { "Register a security key" }
            </Button>
            <Button
                variant={ButtonVariant::Secondary}
                disabled={props.busy}
                onclick={props.on_signin.clone()}
            >
                { "Sign in with a security key" }
            </Button>
            if let Some(err) = &props.error {
                <p class="pillar-security-key__error" role="alert" aria-live="assertive">
                    { err.message() }
                </p>
            }
        </div>
    }
}

/// The login screen: [`SecurityKeyControls`] wired to the real browser
/// ceremony ([`webauthn::run_register`]/[`webauthn::run_authenticate`],
/// driving actual `navigator.credentials.create()/get()` calls) mounted
/// alongside a password field, the supported custody fallback. This is the
/// control that replaces the old fake "passkey" (`type=password`) field.
#[function_component(LoginPanel)]
pub fn login_panel() -> Html {
    let auth = use_auth();
    let busy = use_state(|| false);
    let error = use_state(|| None::<CeremonyError>);

    let on_register = {
        let auth = auth.clone();
        let busy = busy.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let token = auth.token.clone().unwrap_or_default();
            let user_handle = auth.user.clone().unwrap_or_default();
            let busy = busy.clone();
            let error = error.clone();
            busy.set(true);
            spawn_local(async move {
                match webauthn::run_register(&token, &user_handle).await {
                    Ok(_credential_id) => error.set(None),
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };

    let on_signin = {
        let auth = auth.clone();
        let busy = busy.clone();
        let error = error.clone();
        Callback::from(move |_: MouseEvent| {
            let token = auth.token.clone().unwrap_or_default();
            let busy = busy.clone();
            let error = error.clone();
            busy.set(true);
            spawn_local(async move {
                match webauthn::run_authenticate(&token).await {
                    Ok(_unlock_secret) => error.set(None),
                    Err(e) => error.set(Some(e)),
                }
                busy.set(false);
            });
        })
    };

    html! {
        <div class="pillar-login">
            <SecurityKeyControls
                on_register={on_register}
                on_signin={on_signin}
                busy={*busy}
                error={(*error).clone()}
            />
            <p class="pillar-login__fallback-hint">
                { "You can also sign in with your password below." }
            </p>
            <Input placeholder="password" />
        </div>
    }
}
