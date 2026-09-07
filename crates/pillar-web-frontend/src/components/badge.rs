//! `Badge` / `StatusPill` — small status chips.
//!
//! The status→tone mapping is **pure logic** ([`Tone`], [`Tone::of_status`]) so
//! the semantic classification is host-tested; the Yew components render the
//! chip with the tone's class.

/// The semantic tone of a badge / status pill, driving its color class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// Neutral / informational (grey).
    Neutral,
    /// Healthy / success (green).
    Success,
    /// Warning (amber).
    Warning,
    /// Error / failure (red).
    Danger,
    /// In progress / pending (accent).
    Info,
}

impl Tone {
    /// The CSS modifier class for this tone.
    #[must_use]
    pub fn class(self) -> &'static str {
        match self {
            Tone::Neutral => "is-neutral",
            Tone::Success => "is-success",
            Tone::Warning => "is-warning",
            Tone::Danger => "is-danger",
            Tone::Info => "is-info",
        }
    }

    /// Classify a free-form status string into a [`Tone`] using the common
    /// operational vocabulary (ready/healthy/ok → success, failed/error →
    /// danger, warn/degraded → warning, pending/progressing → info, else
    /// neutral). Case-insensitive.
    #[must_use]
    pub fn of_status(status: &str) -> Tone {
        let s = status.trim().to_lowercase();
        const SUCCESS: [&str; 6] = ["ready", "healthy", "ok", "running", "active", "succeeded"];
        const DANGER: [&str; 5] = ["failed", "error", "crashloopbackoff", "unhealthy", "down"];
        const WARNING: [&str; 4] = ["warning", "degraded", "warn", "notready"];
        const INFO: [&str; 4] = ["pending", "progressing", "reconciling", "provisioning"];
        if SUCCESS.iter().any(|k| s == *k) {
            Tone::Success
        } else if DANGER.iter().any(|k| s == *k) {
            Tone::Danger
        } else if WARNING.iter().any(|k| s == *k) {
            Tone::Warning
        } else if INFO.iter().any(|k| s == *k) {
            Tone::Info
        } else {
            Tone::Neutral
        }
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::{Badge, BadgeProps, StatusPill, StatusPillProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::Tone;
    use yew::prelude::*;

    /// Props for [`Badge`].
    #[derive(Properties, PartialEq)]
    pub struct BadgeProps {
        /// The chip text.
        pub label: AttrValue,
        /// The tone (color).
        #[prop_or(Tone::Neutral)]
        pub tone: Tone,
    }

    /// A small labelled chip in a semantic [`Tone`].
    #[function_component(Badge)]
    pub fn badge(props: &BadgeProps) -> Html {
        html! {
            <span class={classes!("pillar-badge", props.tone.class())}>
                { props.label.clone() }
            </span>
        }
    }

    /// Props for [`StatusPill`].
    #[derive(Properties, PartialEq)]
    pub struct StatusPillProps {
        /// The raw status string; its tone is derived via [`Tone::of_status`].
        pub status: AttrValue,
    }

    /// A [`Badge`] whose tone is inferred from the status string, with a leading
    /// status dot.
    #[function_component(StatusPill)]
    pub fn status_pill(props: &StatusPillProps) -> Html {
        let tone = Tone::of_status(props.status.as_str());
        html! {
            <span class={classes!("pillar-statuspill", tone.class())}>
                <span class="pillar-statuspill__dot" />
                { props.status.clone() }
            </span>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_maps_to_the_expected_tones_case_insensitively() {
        assert_eq!(Tone::of_status("Ready"), Tone::Success);
        assert_eq!(Tone::of_status("HEALTHY"), Tone::Success);
        assert_eq!(Tone::of_status("Failed"), Tone::Danger);
        assert_eq!(Tone::of_status("error"), Tone::Danger);
        assert_eq!(Tone::of_status("Degraded"), Tone::Warning);
        assert_eq!(Tone::of_status("Pending"), Tone::Info);
        assert_eq!(Tone::of_status("Progressing"), Tone::Info);
        // Unknown => neutral, never a fabricated tone.
        assert_eq!(Tone::of_status("whatever"), Tone::Neutral);
    }

    #[test]
    fn every_tone_has_a_distinct_class() {
        let classes = [
            Tone::Neutral.class(),
            Tone::Success.class(),
            Tone::Warning.class(),
            Tone::Danger.class(),
            Tone::Info.class(),
        ];
        let mut uniq = classes.to_vec();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), classes.len(), "tone classes collide");
    }
}
