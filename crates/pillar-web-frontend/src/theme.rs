//! Design tokens — the single source of truth for the pillar portal's visual
//! language (a "Linear/modern" dark aesthetic: near-black layered-ambient
//! surfaces, an indigo accent, multi-layer shadows/glows, and fast expo-out
//! micro-interactions). Every component style in this crate is built from these
//! tokens, so the look is centralized and the tests can assert that a component
//! actually applied the right token.

/// Motion preference. Mirrors the CSS `prefers-reduced-motion` media feature:
/// when the user (or their OS) asks for reduced motion, every animated
/// component style is built WITHOUT its transition/animation so the portal is
/// still fully usable and calm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Motion {
    /// Full micro-interactions (the default): transitions + spotlight tracking.
    Full,
    /// `prefers-reduced-motion: reduce` — animations suppressed.
    Reduced,
}

impl Motion {
    /// The `transition` declaration for a token duration, or an EMPTY string
    /// under [`Motion::Reduced`] (so no animation is emitted at all).
    #[must_use]
    pub fn transition(self, decl: &str) -> String {
        match self {
            Motion::Full => format!("transition: {decl};"),
            Motion::Reduced => String::new(),
        }
    }

    /// The `animation` declaration for a token, or an EMPTY string under
    /// [`Motion::Reduced`].
    #[must_use]
    pub fn animation(self, decl: &str) -> String {
        match self {
            Motion::Full => format!("animation: {decl};"),
            Motion::Reduced => String::new(),
        }
    }
}

/// The design-token palette + scale. All colors, radii, shadows, and motion
/// curves live here; components never hardcode a hex or a duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    /// The app's base near-black surface (page background).
    pub surface_base: &'static str,
    /// One layer up — panels/cards float above the base.
    pub surface_raised: &'static str,
    /// The topmost layer — dialogs/popovers.
    pub surface_overlay: &'static str,
    /// A hairline border between layered surfaces.
    pub border_subtle: &'static str,
    /// Primary text (high contrast on the dark surfaces).
    pub text_primary: &'static str,
    /// Muted secondary text.
    pub text_muted: &'static str,
    /// The indigo brand accent (Linear's signature).
    pub accent: &'static str,
    /// A brighter accent for hover states.
    pub accent_hover: &'static str,
    /// The ambient glow color derived from the accent (used in spotlights).
    pub accent_glow: &'static str,
    /// Corner radius token (px).
    pub radius: &'static str,
    /// The multi-layer resting shadow that lifts a raised surface.
    pub shadow_resting: &'static str,
    /// A stronger multi-layer shadow for hovered/elevated surfaces.
    pub shadow_elevated: &'static str,
    /// The micro-interaction duration (in the 200–300ms band).
    pub motion_duration: &'static str,
    /// The expo-out easing curve for micro-interactions.
    pub motion_easing: &'static str,
}

impl Theme {
    /// The default pillar dark theme.
    #[must_use]
    pub const fn dark() -> Self {
        Self {
            surface_base: "#0b0b10",
            surface_raised: "#141420",
            surface_overlay: "#1c1c2b",
            border_subtle: "rgba(255, 255, 255, 0.08)",
            text_primary: "#e8e8f0",
            text_muted: "#9a9ab0",
            accent: "#5E6AD2",
            accent_hover: "#6f7be6",
            accent_glow: "rgba(94, 106, 210, 0.35)",
            radius: "10px",
            // Multi-layer shadow: a tight contact shadow + a soft ambient one.
            shadow_resting: "0 1px 2px rgba(0, 0, 0, 0.4), 0 8px 24px rgba(0, 0, 0, 0.35)",
            shadow_elevated: "0 2px 4px rgba(0, 0, 0, 0.5), 0 16px 48px rgba(0, 0, 0, 0.45)",
            // 250ms sits squarely in the required 200–300ms band.
            motion_duration: "250ms",
            // expo-out: fast start, gentle settle.
            motion_easing: "cubic-bezier(0.16, 1, 0.3, 1)",
        }
    }

    /// The combined `transition` value (`all <duration> <easing>`) that every
    /// micro-interaction uses. Callers hand this to [`Motion::transition`].
    #[must_use]
    pub fn micro_transition(&self) -> String {
        format!("all {} {}", self.motion_duration, self.motion_easing)
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}
