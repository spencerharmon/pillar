//! Component style builders — the design system's heart. Each function takes the
//! [`Theme`] and a [`Motion`] preference and returns a scoped `stylist` [`Style`]
//! whose emitted CSS carries the design tokens. These are pure and host-testable:
//! the tests build a style and assert the expected token strings appear (and,
//! under [`Motion::Reduced`], that no `transition`/`animation` is emitted).
//!
//! The Yew components in [`crate::components`] simply attach the class these
//! functions produce, so the visual language is defined ONCE here.

use crate::theme::{Motion, Theme};
use stylist::Style;

/// A card surface with a mouse-tracking spotlight. The spotlight is a radial
/// gradient positioned from two CSS custom properties (`--spot-x`/`--spot-y`)
/// the component updates on `mousemove`; under reduced motion the tracking
/// transition is dropped (the gradient still renders, it just does not animate).
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn card_spotlight(theme: &Theme, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let css = format!(
        r#"
        position: relative;
        background-color: {surface};
        border: 1px solid {border};
        border-radius: {radius};
        box-shadow: {shadow};
        color: {text};
        padding: 1.25rem;
        overflow: hidden;
        {transition}

        &::before {{
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background: radial-gradient(
                240px circle at var(--spot-x, 50%) var(--spot-y, 50%),
                {glow},
                transparent 60%
            );
            opacity: 0;
            {transition}
        }}

        &:hover {{
            box-shadow: {shadow_hover};
        }}

        &:hover::before {{
            opacity: 1;
        }}
        "#,
        surface = theme.surface_raised,
        border = theme.border_subtle,
        radius = theme.radius,
        shadow = theme.shadow_resting,
        shadow_hover = theme.shadow_elevated,
        text = theme.text_primary,
        glow = theme.accent_glow,
        transition = transition,
    );
    Style::new(css).expect("card_spotlight css parses")
}

/// The visual variants a [`button`] can take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonVariant {
    /// Solid indigo accent — the primary call to action.
    Primary,
    /// A quiet raised surface button.
    Secondary,
    /// Text-only, no fill, for tertiary actions.
    Ghost,
}

/// A button style for the given [`ButtonVariant`]. Every variant shares the
/// radius, the micro-interaction transition, and a subtle lift on hover; the
/// fill/border/text differ per variant. Reduced motion drops the transition.
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn button(theme: &Theme, variant: ButtonVariant, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let (bg, border, text, bg_hover) = match variant {
        ButtonVariant::Primary => (
            theme.accent.to_string(),
            theme.accent.to_string(),
            "#ffffff".to_string(),
            theme.accent_hover.to_string(),
        ),
        ButtonVariant::Secondary => (
            theme.surface_overlay.to_string(),
            theme.border_subtle.to_string(),
            theme.text_primary.to_string(),
            theme.surface_raised.to_string(),
        ),
        ButtonVariant::Ghost => (
            "transparent".to_string(),
            "transparent".to_string(),
            theme.text_muted.to_string(),
            theme.surface_raised.to_string(),
        ),
    };
    let css = format!(
        r#"
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        font: inherit;
        font-weight: 600;
        line-height: 1;
        padding: 0.55rem 0.95rem;
        border-radius: {radius};
        border: 1px solid {border};
        background-color: {bg};
        color: {text};
        cursor: pointer;
        {transition}

        &:hover {{
            background-color: {bg_hover};
            transform: translateY(-1px);
        }}

        &:active {{
            transform: translateY(0);
        }}

        &:focus-visible {{
            outline: 2px solid {accent};
            outline-offset: 2px;
        }}

        &:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }}
        "#,
        radius = theme.radius,
        border = border,
        bg = bg,
        text = text,
        bg_hover = bg_hover,
        accent = theme.accent,
        transition = transition,
    );
    Style::new(css).expect("button css parses")
}

/// A text input style: a raised inset field that glows with the accent when
/// focused. Reduced motion drops the focus transition.
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn input(theme: &Theme, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let css = format!(
        r#"
        width: 100%;
        box-sizing: border-box;
        font: inherit;
        color: {text};
        background-color: {surface};
        border: 1px solid {border};
        border-radius: {radius};
        padding: 0.55rem 0.75rem;
        {transition}

        &::placeholder {{
            color: {muted};
        }}

        &:focus {{
            outline: none;
            border-color: {accent};
            box-shadow: 0 0 0 3px {glow};
        }}
        "#,
        text = theme.text_primary,
        surface = theme.surface_base,
        border = theme.border_subtle,
        radius = theme.radius,
        muted = theme.text_muted,
        accent = theme.accent,
        glow = theme.accent_glow,
        transition = transition,
    );
    Style::new(css).expect("input css parses")
}

/// A dialog surface: the topmost overlay layer with the strongest shadow and a
/// scale/fade entrance animation. Reduced motion suppresses the entrance
/// animation entirely (the dialog simply appears).
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn dialog(theme: &Theme, motion: Motion) -> Style {
    // The entrance is an @keyframes animation; under reduced motion we emit no
    // `animation` declaration and no keyframes at all.
    let (animation, keyframes) = match motion {
        Motion::Full => (
            motion.animation(&format!(
                "pillar-dialog-in {} {} both",
                theme.motion_duration, theme.motion_easing
            )),
            r#"
            @keyframes pillar-dialog-in {
                from { opacity: 0; transform: translateY(8px) scale(0.98); }
                to   { opacity: 1; transform: translateY(0) scale(1); }
            }
            "#
            .to_string(),
        ),
        Motion::Reduced => (String::new(), String::new()),
    };
    let css = format!(
        r#"
        background-color: {surface};
        border: 1px solid {border};
        border-radius: {radius};
        box-shadow: {shadow};
        color: {text};
        padding: 1.5rem;
        max-width: 32rem;
        width: 100%;
        {animation}
        {keyframes}
        "#,
        surface = theme.surface_overlay,
        border = theme.border_subtle,
        radius = theme.radius,
        shadow = theme.shadow_elevated,
        text = theme.text_primary,
        animation = animation,
        keyframes = keyframes,
    );
    Style::new(css).expect("dialog css parses")
}

/// A combobox / typeahead popover style: the input plus a floating results list
/// on the overlay layer. The list fades/slides in; reduced motion drops that.
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn combobox(theme: &Theme, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let css = format!(
        r#"
        position: relative;

        & .pillar-combobox__list {{
            position: absolute;
            top: calc(100% + 4px);
            left: 0;
            right: 0;
            z-index: 20;
            list-style: none;
            margin: 0;
            padding: 0.25rem;
            background-color: {surface};
            border: 1px solid {border};
            border-radius: {radius};
            box-shadow: {shadow};
            {transition}
        }}

        & .pillar-combobox__option {{
            padding: 0.45rem 0.6rem;
            border-radius: 6px;
            color: {text};
            cursor: pointer;
            {transition}
        }}

        & .pillar-combobox__option[aria-selected="true"],
        & .pillar-combobox__option:hover {{
            background-color: {accent};
            color: #ffffff;
        }}
        "#,
        surface = theme.surface_overlay,
        border = theme.border_subtle,
        radius = theme.radius,
        shadow = theme.shadow_elevated,
        text = theme.text_primary,
        accent = theme.accent,
        transition = transition,
    );
    Style::new(css).expect("combobox css parses")
}
