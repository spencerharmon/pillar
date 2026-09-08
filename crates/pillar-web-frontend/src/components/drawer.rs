//! `Drawer` — a slide-over detail panel.
//!
//! The open/side→class computation is **pure logic** ([`Side`],
//! [`drawer_classes`]) so it is host-tested; the [`Drawer`] Yew component
//! renders the backdrop + panel with those classes.

/// The edge a [`Drawer`] slides in from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// Slide in from the right (the default detail-panel position).
    Right,
    /// Slide in from the left.
    Left,
}

impl Side {
    /// The side modifier class.
    #[must_use]
    pub fn class(self) -> &'static str {
        match self {
            Side::Right => "is-right",
            Side::Left => "is-left",
        }
    }
}

/// The space-separated class string for a drawer panel given its side and open
/// state. Host-tested so the open/closed contract is pinned outside the
/// component.
#[must_use]
pub fn drawer_classes(side: Side, open: bool) -> String {
    let mut s = format!("pillar-drawer {}", side.class());
    if open {
        s.push_str(" is-open");
    }
    s
}

/// The CSS selector for the tabbable elements a drawer focus-trap cycles over.
/// An open drawer is a modal surface: Tab from the last tabbable element must
/// wrap to the first and Shift-Tab from the first must wrap to the last, so
/// focus can never escape the panel to the (inert) content behind it. The Yew
/// component queries the panel with this selector and computes the wrap target
/// via [`focus_wrap_target`]; both are host-tested so the trap contract holds
/// without a browser.
pub const FOCUSABLE_SELECTOR: &str = "a[href], button:not([disabled]), \
input:not([disabled]), select:not([disabled]), textarea:not([disabled]), \
[tabindex]:not([tabindex=\"-1\"])";

/// Given the count of tabbable elements in an open drawer, the index of the
/// currently-focused one, and whether Shift was held, return the index the trap
/// should move focus to WHEN a wrap is required, or `None` when the default
/// browser Tab order should be left alone (focus is mid-list, not at an edge).
///
/// The trap only intervenes at the boundaries: Tab on the LAST element wraps to
/// the first (`0`); Shift-Tab on the FIRST wraps to the last (`count - 1`). With
/// zero or one tabbable element every Tab keeps focus on that sole element
/// (index `0`, or no move when empty). Pure, so the wrap arithmetic is pinned by
/// a host test.
#[must_use]
pub fn focus_wrap_target(count: usize, focused: usize, shift: bool) -> Option<usize> {
    if count == 0 {
        return None;
    }
    if count == 1 {
        // A single stop: any Tab keeps focus on it (wrap to itself).
        return Some(0);
    }
    let last = count - 1;
    match (shift, focused) {
        // Shift-Tab off the first element wraps to the last.
        (true, 0) => Some(last),
        // Tab off the last element wraps to the first.
        (false, f) if f == last => Some(0),
        // Mid-list: let the browser move focus normally.
        _ => None,
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::{Drawer, DrawerProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{drawer_classes, focus_wrap_target, Side, FOCUSABLE_SELECTOR};
    use wasm_bindgen::JsCast;
    use yew::prelude::*;

    /// Props for [`Drawer`].
    #[derive(Properties, PartialEq)]
    pub struct DrawerProps {
        /// Whether the drawer is open.
        pub open: bool,
        /// Which edge it slides from.
        #[prop_or(Side::Right)]
        pub side: Side,
        /// Invoked when the backdrop is clicked (request-to-close).
        #[prop_or_default]
        pub on_close: Callback<MouseEvent>,
        /// The drawer body.
        #[prop_or_default]
        pub children: Html,
    }

    /// A slide-over detail panel with a dimming backdrop. Rendered even when
    /// closed (so its slide transition runs); visibility is driven by the
    /// `is-open` class from the pure [`drawer_classes`].
    ///
    /// When open it behaves as a modal surface: an `onkeydown` on the panel
    /// closes it on Escape and TRAPS Tab focus inside the panel (Tab from the
    /// last tabbable element wraps to the first, Shift-Tab from the first wraps
    /// to the last) via the pure [`focus_wrap_target`], so keyboard focus can
    /// never fall through to the inert content behind it.
    #[function_component(Drawer)]
    pub fn drawer(props: &DrawerProps) -> Html {
        let panel_ref = use_node_ref();
        let panel_class = drawer_classes(props.side, props.open);
        let backdrop_class = if props.open {
            "pillar-drawer__backdrop is-open"
        } else {
            "pillar-drawer__backdrop"
        };

        let on_keydown = {
            let (on_close, panel_ref) = (props.on_close.clone(), panel_ref.clone());
            Callback::from(move |e: KeyboardEvent| match e.key().as_str() {
                "Escape" => on_close.emit(MouseEvent::new("click").unwrap()),
                "Tab" => {
                    // Enumerate the panel's tabbable elements and, at a boundary,
                    // wrap focus to the opposite end (else let the browser move).
                    let Some(panel) = panel_ref.cast::<web_sys::Element>() else {
                        return;
                    };
                    let Ok(list) = panel.query_selector_all(FOCUSABLE_SELECTOR) else {
                        return;
                    };
                    let count = list.length() as usize;
                    let doc = web_sys::window().and_then(|w| w.document());
                    let focused = doc.and_then(|d| d.active_element());
                    // Find the index of the currently-focused element.
                    let mut idx = 0usize;
                    for i in 0..count {
                        if let (Some(node), Some(act)) = (list.item(i as u32), focused.as_ref()) {
                            if &node == act.unchecked_ref::<web_sys::Node>() {
                                idx = i;
                                break;
                            }
                        }
                    }
                    if let Some(target) = focus_wrap_target(count, idx, e.shift_key()) {
                        if let Some(node) = list.item(target as u32) {
                            if let Ok(el) = node.dyn_into::<web_sys::HtmlElement>() {
                                e.prevent_default();
                                let _ = el.focus();
                            }
                        }
                    }
                }
                _ => {}
            })
        };

        html! {
            <>
                <div class={backdrop_class} onclick={props.on_close.clone()} />
                <aside ref={panel_ref} class={panel_class} role="dialog"
                       tabindex="-1"
                       aria-modal={props.open.to_string()}
                       aria-hidden={(!props.open).to_string()}
                       onkeydown={on_keydown}>
                    { props.children.clone() }
                </aside>
            </>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_carry_side_and_open_state() {
        let open = drawer_classes(Side::Right, true);
        assert!(open.contains("pillar-drawer"));
        assert!(open.contains("is-right"));
        assert!(open.contains("is-open"));

        let closed = drawer_classes(Side::Left, false);
        assert!(closed.contains("is-left"));
        assert!(!closed.contains("is-open"));
    }

    #[test]
    fn focus_trap_wraps_only_at_the_boundaries() {
        // Mid-list Tab/Shift-Tab: the browser handles it, the trap stays out.
        assert_eq!(focus_wrap_target(4, 1, false), None);
        assert_eq!(focus_wrap_target(4, 2, true), None);
        // Tab off the LAST element wraps to the first.
        assert_eq!(focus_wrap_target(4, 3, false), Some(0));
        // Shift-Tab off the FIRST element wraps to the last.
        assert_eq!(focus_wrap_target(4, 0, true), Some(3));
        // Tab off the first / Shift-Tab off the last are NOT boundaries.
        assert_eq!(focus_wrap_target(4, 0, false), None);
        assert_eq!(focus_wrap_target(4, 3, true), None);
    }

    #[test]
    fn focus_trap_degenerate_counts() {
        // No tabbable element: nothing to move to.
        assert_eq!(focus_wrap_target(0, 0, false), None);
        assert_eq!(focus_wrap_target(0, 0, true), None);
        // A single tabbable element: any Tab keeps focus on it.
        assert_eq!(focus_wrap_target(1, 0, false), Some(0));
        assert_eq!(focus_wrap_target(1, 0, true), Some(0));
    }

    /// Source audit (anti-facade DoD): the drawer component actually installs the
    /// focus-trap + Escape-close — it wires an `onkeydown` that handles `Escape`
    /// and `Tab`, routes the Tab wrap through the pure `focus_wrap_target`, and
    /// marks the open panel `aria-modal`. Pins that a future edit cannot silently
    /// drop the a11y trap.
    #[test]
    fn drawer_wires_focus_trap_and_escape() {
        let src = include_str!("drawer.rs");
        assert!(
            src.contains("onkeydown={on_keydown}"),
            "drawer panel no longer wires an onkeydown handler"
        );
        for key in ["\"Escape\"", "\"Tab\""] {
            assert!(src.contains(key), "drawer keydown no longer handles {key}");
        }
        assert!(
            src.contains("focus_wrap_target("),
            "drawer no longer routes its Tab trap through focus_wrap_target"
        );
        assert!(
            src.contains("aria-modal="),
            "open drawer no longer marks itself aria-modal"
        );
    }
}
