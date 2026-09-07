//! `Tabs` — a horizontal tab bar with a switched panel.
//!
//! The active-index clamping is **pure logic** ([`clamp_active`]) so the
//! selection invariant is host-tested; the [`Tabs`] Yew component renders the
//! bar and the active panel.

/// Clamp a requested active index to a valid tab index for `count` tabs
/// (returns `0` when there are no tabs). Keeps selection valid when the tab set
/// shrinks.
#[must_use]
pub fn clamp_active(requested: usize, count: usize) -> usize {
    if count == 0 {
        0
    } else {
        requested.min(count - 1)
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::{TabItem, Tabs, TabsProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::clamp_active;
    use yew::prelude::*;

    /// One tab: a label and its panel content.
    #[derive(Clone, PartialEq)]
    pub struct TabItem {
        /// The tab label.
        pub label: AttrValue,
        /// The panel shown when this tab is active.
        pub panel: Html,
    }

    /// Props for [`Tabs`].
    #[derive(Properties, PartialEq)]
    pub struct TabsProps {
        /// The tabs, in bar order.
        pub tabs: Vec<TabItem>,
        /// The initially-active tab index (clamped).
        #[prop_or(0)]
        pub default_active: usize,
    }

    /// A tab bar over [`TabItem`]s with a switched panel. The active index is
    /// held in state and kept valid via the pure [`clamp_active`].
    #[function_component(Tabs)]
    pub fn tabs(props: &TabsProps) -> Html {
        let active = use_state(|| clamp_active(props.default_active, props.tabs.len()));
        let cur = clamp_active(*active, props.tabs.len());
        let bar = props
            .tabs
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let is_active = i == cur;
                let onclick = {
                    let active = active.clone();
                    Callback::from(move |_: MouseEvent| active.set(i))
                };
                let mut class = Classes::from("pillar-tab");
                if is_active {
                    class.push("is-active");
                }
                html! {
                    <button
                        type="button"
                        class={class}
                        role="tab"
                        aria-selected={is_active.to_string()}
                        onclick={onclick}
                    >{ t.label.clone() }</button>
                }
            })
            .collect::<Html>();
        let panel = props.tabs.get(cur).map(|t| t.panel.clone()).unwrap_or_default();
        html! {
            <div class="pillar-tabs">
                <div class="pillar-tabs__bar" role="tablist">{ bar }</div>
                <div class="pillar-tabs__panel">{ panel }</div>
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_holds_active_in_range() {
        assert_eq!(clamp_active(0, 3), 0);
        assert_eq!(clamp_active(2, 3), 2);
        // Past the end clamps to the last tab.
        assert_eq!(clamp_active(9, 3), 2);
        // No tabs => 0.
        assert_eq!(clamp_active(5, 0), 0);
    }
}
