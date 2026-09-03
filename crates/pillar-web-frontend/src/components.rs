//! Yew component wrappers around the design-system styles in [`crate::styles`].
//!
//! Each component attaches the scoped class the corresponding style builder
//! produces, so the visual language lives in ONE place. These compile on the
//! native host (so `cargo test -p pillar-web-frontend` typechecks them) and on
//! `wasm32-unknown-unknown` (where they become real DOM in the portal bundle).
//! The whole module is gated behind the `yew` feature.

use crate::styles::{self, ButtonVariant};
use crate::theme::{Motion, Theme};
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
