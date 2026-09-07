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

#[cfg(feature = "yew")]
pub use yew_impl::{Drawer, DrawerProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{drawer_classes, Side};
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
    #[function_component(Drawer)]
    pub fn drawer(props: &DrawerProps) -> Html {
        let panel_class = drawer_classes(props.side, props.open);
        let backdrop_class = if props.open {
            "pillar-drawer__backdrop is-open"
        } else {
            "pillar-drawer__backdrop"
        };
        html! {
            <>
                <div class={backdrop_class} onclick={props.on_close.clone()} />
                <aside class={panel_class} role="dialog" aria-hidden={(!props.open).to_string()}>
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
}
