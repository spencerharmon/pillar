//! `Toast` — transient notification (feeds Phase 5's error/success toasts).
//!
//! The level→class mapping and the queue push/dismiss bookkeeping are **pure
//! logic** ([`Level`], [`Toast`], [`push`], [`dismiss`]) so the queue behaviour
//! is host-tested; the [`ToastStack`] Yew component renders the live queue.

/// The severity level of a toast.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Informational.
    Info,
    /// Success confirmation.
    Success,
    /// Warning.
    Warning,
    /// Error.
    Error,
}

impl Level {
    /// The severity modifier class.
    #[must_use]
    pub fn class(self) -> &'static str {
        match self {
            Level::Info => "is-info",
            Level::Success => "is-success",
            Level::Warning => "is-warning",
            Level::Error => "is-error",
        }
    }
}

/// One transient toast.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Toast {
    /// A unique, monotonically-assigned id (used to dismiss).
    pub id: u64,
    /// The severity level.
    pub level: Level,
    /// The message text.
    pub text: String,
}

/// Push a new toast onto `queue`, assigning it `next_id`, and return the new
/// queue capped to the most recent `max` toasts (oldest dropped first). Pure so
/// the cap/eviction is host-tested.
#[must_use]
pub fn push(queue: &[Toast], next_id: u64, level: Level, text: &str, max: usize) -> Vec<Toast> {
    let mut out = queue.to_vec();
    out.push(Toast {
        id: next_id,
        level,
        text: text.to_owned(),
    });
    if max > 0 && out.len() > max {
        let drop = out.len() - max;
        out.drain(0..drop);
    }
    out
}

/// Remove the toast with `id` from `queue` (a no-op if absent).
#[must_use]
pub fn dismiss(queue: &[Toast], id: u64) -> Vec<Toast> {
    queue.iter().filter(|t| t.id != id).cloned().collect()
}

#[cfg(feature = "yew")]
pub use yew_impl::{ToastStack, ToastStackProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::Toast;
    use yew::prelude::*;

    /// Props for [`ToastStack`].
    #[derive(Properties, PartialEq)]
    pub struct ToastStackProps {
        /// The live toast queue (owned by the parent; mutated via the pure
        /// [`super::push`]/[`super::dismiss`]).
        pub toasts: Vec<Toast>,
        /// Invoked with a toast id when its dismiss control is clicked.
        #[prop_or_default]
        pub on_dismiss: Callback<u64>,
    }

    /// A stacked list of transient toasts in the corner overlay layer.
    #[function_component(ToastStack)]
    pub fn toast_stack(props: &ToastStackProps) -> Html {
        html! {
            <div class="pillar-toaststack" role="status" aria-live="polite">
                { for props.toasts.iter().map(|t| {
                    let id = t.id;
                    let on_dismiss = props.on_dismiss.clone();
                    let onclick = Callback::from(move |_: MouseEvent| on_dismiss.emit(id));
                    html! {
                        <div class={classes!("pillar-toast", t.level.class())}>
                            <span class="pillar-toast__text">{ t.text.clone() }</span>
                            <button
                                type="button"
                                class="pillar-toast__dismiss"
                                aria-label="Dismiss"
                                onclick={onclick}
                            >{ "\u{00D7}" }</button>
                        </div>
                    }
                }) }
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_appends_and_assigns_the_id() {
        let q = push(&[], 1, Level::Info, "hello", 5);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].id, 1);
        assert_eq!(q[0].text, "hello");
        assert_eq!(q[0].level, Level::Info);
    }

    #[test]
    fn push_caps_to_max_dropping_oldest() {
        let mut q = Vec::new();
        for i in 1..=5 {
            q = push(&q, i, Level::Info, &format!("m{i}"), 3);
        }
        // Only the most recent 3 remain (m3,m4,m5).
        assert_eq!(q.len(), 3);
        assert_eq!(q[0].text, "m3");
        assert_eq!(q[2].text, "m5");
    }

    #[test]
    fn dismiss_removes_only_the_matching_id() {
        let q = vec![
            Toast { id: 1, level: Level::Info, text: "a".into() },
            Toast { id: 2, level: Level::Error, text: "b".into() },
        ];
        let after = dismiss(&q, 1);
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].id, 2);
        // Dismissing an absent id is a no-op.
        assert_eq!(dismiss(&q, 99), q);
    }

    #[test]
    fn every_level_has_a_distinct_class() {
        let cs = [
            Level::Info.class(),
            Level::Success.class(),
            Level::Warning.class(),
            Level::Error.class(),
        ];
        let mut u = cs.to_vec();
        u.sort_unstable();
        u.dedup();
        assert_eq!(u.len(), cs.len());
    }
}
