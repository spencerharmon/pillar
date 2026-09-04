//! # pillar-web-frontend
//!
//! The pillar web portal's **design system** and **component library**.
//!
//! The design language is a "Linear/modern" dark aesthetic — near-black
//! layered-ambient surfaces, an indigo `#5E6AD2` accent, multi-layer
//! shadows/glows, and fast (200–300ms) expo-out micro-interactions with
//! mouse-tracking spotlights and a `prefers-reduced-motion` fallback.
//!
//! It is expressed as pure Rust that builds scoped `stylist` (CSS-in-Rust)
//! styles from a small set of [`Theme`] tokens, which makes the whole system
//! **host-testable**: the tests build a component's style and assert the design
//! tokens are present in the emitted CSS (and that, under [`Motion::Reduced`],
//! no `transition`/`animation` is emitted). The Yew components in
//! [`components`] (behind the default `yew` feature) simply attach those
//! classes, so the visual language is defined exactly once.

pub mod auth;
pub mod explore;
pub mod panels;
pub mod router;
pub mod styles;
pub mod theme;
pub mod webauthn;

#[cfg(feature = "yew")]
pub mod components;

pub use auth::{AuthAction, AuthSession};
pub use explore::{
    build_metric_query, build_profile_query, correlate_candidates, label_key_options,
    label_value_options, profile_correlate_candidates, METRIC_KIND, PROFILE_KIND,
};
pub use router::Route;
pub use styles::ButtonVariant;
pub use theme::{Motion, Theme};
pub use webauthn::{authenticate, register, CeremonyError, CredentialCeremony, RpTransport};

#[cfg(feature = "yew")]
pub use explore::{ExploreBuilder, ExploreBuilderProps, ExploreProfilesBuilder};

#[cfg(feature = "yew")]
pub use auth::{use_auth, AuthContext, AuthProvider};
#[cfg(feature = "yew")]
pub use router::Shell;

#[cfg(test)]
mod tests {
    use super::styles::{self, ButtonVariant};
    use super::theme::{Motion, Theme};

    /// The emitted, scoped CSS for a style. `stylist` scopes selectors under a
    /// generated class, but the property VALUES (our design tokens) appear
    /// verbatim, which is exactly what we assert.
    fn css(style: &stylist::Style) -> String {
        style.get_style_str().to_string()
    }

    #[test]
    fn theme_carries_the_linear_design_tokens() {
        let t = Theme::dark();
        // The signature indigo accent.
        assert_eq!(t.accent, "#5E6AD2");
        // Micro-interaction duration sits in the required 200–300ms band.
        assert_eq!(t.motion_duration, "250ms");
        let d: u32 = t
            .motion_duration
            .trim_end_matches("ms")
            .parse()
            .expect("duration is a ms integer");
        assert!((200..=300).contains(&d), "duration {d}ms out of 200–300 band");
        // Expo-out easing curve.
        assert!(t.motion_easing.starts_with("cubic-bezier"));
        // Near-black base surface (very dark).
        assert!(t.surface_base.starts_with('#'));
        // Multi-layer shadows (two comma-separated layers each).
        assert!(t.shadow_resting.matches("rgba").count() >= 2);
        assert!(t.shadow_elevated.matches("rgba").count() >= 2);
    }

    #[test]
    fn card_spotlight_applies_tokens_and_a_tracking_gradient() {
        let t = Theme::dark();
        let full = css(&styles::card_spotlight(&t, Motion::Full));
        // Raised surface + accent glow + a mouse-tracking radial spotlight.
        assert!(full.contains(t.surface_raised), "card missing raised surface");
        assert!(full.contains(t.accent_glow), "card missing accent glow");
        assert!(full.contains("radial-gradient"), "card missing spotlight gradient");
        assert!(full.contains("--spot-x"), "card missing spotlight x var");
        assert!(full.contains("--spot-y"), "card missing spotlight y var");
        // Multi-layer resting + elevated shadows both present.
        assert!(full.contains(t.shadow_resting));
        assert!(full.contains(t.shadow_elevated));
        // Full motion => a transition is emitted with the token duration.
        assert!(full.contains("transition"), "card missing transition under full motion");
        assert!(full.contains(t.motion_duration));
    }

    #[test]
    fn button_variants_apply_distinct_tokens() {
        let t = Theme::dark();
        let primary = css(&styles::button(&t, ButtonVariant::Primary, Motion::Full));
        let secondary = css(&styles::button(&t, ButtonVariant::Secondary, Motion::Full));
        let ghost = css(&styles::button(&t, ButtonVariant::Ghost, Motion::Full));

        // Primary is filled with the indigo accent.
        assert!(primary.contains(t.accent), "primary button missing accent fill");
        // Secondary uses a raised/overlay surface, not the accent fill.
        assert!(secondary.contains(t.surface_overlay), "secondary missing overlay surface");
        // Ghost is transparent.
        assert!(ghost.contains("transparent"), "ghost button not transparent");
        // All share the token radius and a focus-visible accent outline.
        for v in [&primary, &secondary, &ghost] {
            assert!(v.contains(t.radius), "button missing token radius");
            assert!(v.contains("focus-visible"), "button missing focus ring");
        }
    }

    #[test]
    fn input_glows_with_accent_on_focus() {
        let t = Theme::dark();
        let s = css(&styles::input(&t, Motion::Full));
        assert!(s.contains(t.border_subtle), "input missing subtle border");
        assert!(s.contains(t.accent), "input focus missing accent border");
        assert!(s.contains(t.accent_glow), "input focus missing accent glow ring");
        assert!(s.contains(t.radius));
    }

    #[test]
    fn dialog_uses_overlay_surface_and_entrance_animation() {
        let t = Theme::dark();
        let s = css(&styles::dialog(&t, Motion::Full));
        assert!(s.contains(t.surface_overlay), "dialog missing overlay surface");
        assert!(s.contains(t.shadow_elevated), "dialog missing elevated shadow");
        // Full motion => a keyframed entrance animation.
        assert!(s.contains("@keyframes"), "dialog missing entrance keyframes");
        assert!(s.contains("animation"), "dialog missing animation declaration");
    }

    #[test]
    fn combobox_lists_options_on_the_overlay_layer() {
        let t = Theme::dark();
        let s = css(&styles::combobox(&t, Motion::Full));
        assert!(s.contains("pillar-combobox__list"), "combobox missing list class");
        assert!(s.contains("pillar-combobox__option"), "combobox missing option class");
        assert!(s.contains(t.surface_overlay), "combobox list missing overlay surface");
        // The highlighted / hovered option uses the accent fill.
        assert!(s.contains(t.accent), "combobox selection missing accent");
        assert!(s.contains(r#"aria-selected="true""#), "combobox missing aria-selected styling");
    }

    /// The `prefers-reduced-motion` contract: under [`Motion::Reduced`] EVERY
    /// component style must emit NO `transition` and NO `animation` — the exact
    /// suppression the media-query fallback guarantees — while still carrying
    /// its non-animated design tokens.
    #[test]
    fn reduced_motion_suppresses_every_animation() {
        let t = Theme::dark();
        let reduced = [
            css(&styles::card_spotlight(&t, Motion::Reduced)),
            css(&styles::button(&t, ButtonVariant::Primary, Motion::Reduced)),
            css(&styles::button(&t, ButtonVariant::Secondary, Motion::Reduced)),
            css(&styles::button(&t, ButtonVariant::Ghost, Motion::Reduced)),
            css(&styles::input(&t, Motion::Reduced)),
            css(&styles::dialog(&t, Motion::Reduced)),
            css(&styles::combobox(&t, Motion::Reduced)),
        ];
        for s in &reduced {
            assert!(
                !s.contains("transition"),
                "reduced-motion style still emits a transition:\n{s}"
            );
            assert!(
                !s.contains("animation"),
                "reduced-motion style still emits an animation:\n{s}"
            );
            assert!(
                !s.contains("@keyframes"),
                "reduced-motion style still emits keyframes:\n{s}"
            );
        }
    }

    /// Directly contrasts full vs reduced for the same component, proving the
    /// change is the motion suppression (not, e.g., a missing token).
    #[test]
    fn full_motion_animates_where_reduced_does_not() {
        let t = Theme::dark();
        let full = css(&styles::card_spotlight(&t, Motion::Full));
        let reduced = css(&styles::card_spotlight(&t, Motion::Reduced));
        assert!(full.contains("transition"));
        assert!(!reduced.contains("transition"));
        // Both keep the surface token — only the motion differs.
        assert!(full.contains(t.surface_raised));
        assert!(reduced.contains(t.surface_raised));
    }
}
