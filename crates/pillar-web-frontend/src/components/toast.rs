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
pub use yew_impl::{
    use_toast_error, ToastQueueHandle, ToastQueueProvider, ToastQueueProviderProps, ToastStack,
    ToastStackProps,
};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{dismiss, push, Level, Toast};
    use yew::prelude::*;

    /// The queue's reducer action: push a new error toast, or dismiss one by
    /// id. Kept minimal (the palette's only producer today is a fetch error)
    /// but general enough for a future success/info toast.
    pub enum ToastQueueAction {
        Push { level: Level, text: String },
        Dismiss(u64),
    }

    /// The live toast queue, as a `Reducible` so every console can share ONE
    /// instance via context instead of each owning its own dead `use_state`.
    #[derive(Clone, PartialEq)]
    pub struct ToastQueueState {
        toasts: Vec<Toast>,
        next_id: u64,
    }

    impl Default for ToastQueueState {
        fn default() -> Self {
            Self {
                toasts: Vec::new(),
                next_id: 1,
            }
        }
    }

    impl Reducible for ToastQueueState {
        type Action = ToastQueueAction;

        fn reduce(self: std::rc::Rc<Self>, action: Self::Action) -> std::rc::Rc<Self> {
            match action {
                ToastQueueAction::Push { level, text } => std::rc::Rc::new(ToastQueueState {
                    toasts: push(&self.toasts, self.next_id, level, &text, 4),
                    next_id: self.next_id + 1,
                }),
                ToastQueueAction::Dismiss(id) => std::rc::Rc::new(ToastQueueState {
                    toasts: dismiss(&self.toasts, id),
                    next_id: self.next_id,
                }),
            }
        }
    }

    /// The context handle every console fetch path reads to report a failure
    /// and every frame renders the live queue from.
    pub type ToastQueueHandle = UseReducerHandle<ToastQueueState>;

    /// Props for [`ToastQueueProvider`].
    #[derive(Properties, PartialEq)]
    pub struct ToastQueueProviderProps {
        /// Children rendered inside the provider.
        #[prop_or_default]
        pub children: Html,
    }

    /// Mounts ONE shared [`ToastQueueHandle`] in context for every descendant —
    /// mounted once by [`crate::console::ConsoleView`] so every section's
    /// fetch path (via [`use_toast_error`]) and the single [`ToastStack`]
    /// share the same queue instead of each tile owning an orphaned one.
    #[function_component(ToastQueueProvider)]
    pub fn toast_queue_provider(props: &ToastQueueProviderProps) -> Html {
        let queue = use_reducer(ToastQueueState::default);
        html! {
            <ContextProvider<ToastQueueHandle> context={queue}>
                { props.children.clone() }
            </ContextProvider<ToastQueueHandle>>
        }
    }

    /// The queue's current toasts, read from context (empty if no
    /// [`ToastQueueProvider`] is mounted — e.g. a component under host test).
    #[must_use]
    #[hook]
    pub fn use_toasts() -> Vec<Toast> {
        use_context::<ToastQueueHandle>()
            .map(|q| q.toasts.clone())
            .unwrap_or_default()
    }

    /// Dismiss a toast by id, reading the queue from context (a no-op with no
    /// provider mounted).
    #[must_use]
    #[hook]
    pub fn use_toast_dismiss() -> Callback<u64> {
        let queue = use_context::<ToastQueueHandle>();
        Callback::from(move |id: u64| {
            if let Some(q) = &queue {
                q.dispatch(ToastQueueAction::Dismiss(id));
            }
        })
    }

    /// Every console fetch path's ONE required error-reporting call: pushes an
    /// `Error`-level toast with `text` onto the shared queue (a no-op, never a
    /// panic, when no [`ToastQueueProvider`] is mounted — e.g. under host
    /// test or a standalone-rendered tile). This is the hook that turns a
    /// silent `Err(_) => {}`/`if let Ok(..) = .. { .. }` fetch failure into a
    /// user-visible notification.
    #[must_use]
    #[hook]
    pub fn use_toast_error() -> Callback<String> {
        let queue = use_context::<ToastQueueHandle>();
        Callback::from(move |text: String| {
            if let Some(q) = &queue {
                q.dispatch(ToastQueueAction::Push {
                    level: Level::Error,
                    text,
                });
            }
        })
    }

    /// Props for [`ToastStack`].
    #[derive(Properties, PartialEq)]
    pub struct ToastStackProps {
        /// The live toast queue. Defaults to reading the shared
        /// [`ToastQueueHandle`] from context (what [`crate::console::ConsoleView`]
        /// relies on); a caller under host test / Storybook-style isolation may
        /// still pass an explicit queue.
        #[prop_or_default]
        pub toasts: Option<Vec<Toast>>,
        /// Invoked with a toast id when its dismiss control is clicked.
        /// Defaults to dispatching the context queue's dismiss action.
        #[prop_or_default]
        pub on_dismiss: Option<Callback<u64>>,
    }

    /// A stacked list of transient toasts in the corner overlay layer, wired by
    /// default to the shared [`ToastQueueHandle`] context so it renders every
    /// error any console fetch path reports via [`use_toast_error`].
    #[function_component(ToastStack)]
    pub fn toast_stack(props: &ToastStackProps) -> Html {
        let ctx_toasts = use_toasts();
        let ctx_dismiss = use_toast_dismiss();
        let toasts = props.toasts.clone().unwrap_or(ctx_toasts);
        let dismiss_cb = props.on_dismiss.clone().unwrap_or(ctx_dismiss);
        html! {
            <div class="pillar-toaststack" role="status" aria-live="polite">
                { for toasts.iter().map(|t| {
                    let id = t.id;
                    let on_dismiss = dismiss_cb.clone();
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
            Toast {
                id: 1,
                level: Level::Info,
                text: "a".into(),
            },
            Toast {
                id: 2,
                level: Level::Error,
                text: "b".into(),
            },
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
