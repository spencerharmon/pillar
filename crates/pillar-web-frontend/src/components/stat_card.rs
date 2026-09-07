//! `StatCard` — a headline metric with an optional trend and sparkline.
//!
//! The trend arithmetic is **pure logic** ([`percent_change`], [`Trend`]) so it
//! is host-tested; the [`StatCard`] Yew component renders the value, delta, and
//! (optionally) a [`super::chart::Sparkline`].

/// The direction a metric moved relative to its previous value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trend {
    /// Increased.
    Up,
    /// Decreased.
    Down,
    /// Unchanged (or no prior value).
    Flat,
}

/// The percentage change from `prev` to `cur`, plus the [`Trend`] direction.
/// A zero (or absent) baseline yields `0.0` change and [`Trend::Flat`] rather
/// than dividing by zero.
#[must_use]
pub fn percent_change(prev: f64, cur: f64) -> (f64, Trend) {
    if prev.abs() < f64::EPSILON {
        return (0.0, Trend::Flat);
    }
    let pct = (cur - prev) / prev.abs() * 100.0;
    let trend = if pct > f64::EPSILON {
        Trend::Up
    } else if pct < -f64::EPSILON {
        Trend::Down
    } else {
        Trend::Flat
    };
    (pct, trend)
}

#[cfg(feature = "yew")]
pub use yew_impl::{StatCard, StatCardProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{percent_change, Trend};
    use crate::components::chart::Sparkline;
    use yew::prelude::*;

    /// Props for [`StatCard`].
    #[derive(Properties, PartialEq)]
    pub struct StatCardProps {
        /// The stat label.
        pub label: AttrValue,
        /// The headline value, already formatted.
        pub value: AttrValue,
        /// Optional `(previous, current)` pair to render a percent-change delta.
        #[prop_or_default]
        pub delta: Option<(f64, f64)>,
        /// Optional recent series to render a sparkline under the value.
        #[prop_or_default]
        pub spark: Vec<f64>,
    }

    /// A headline-metric card: a big value, its label, an optional trend delta,
    /// and an optional sparkline.
    #[function_component(StatCard)]
    pub fn stat_card(props: &StatCardProps) -> Html {
        let delta = props.delta.map(|(p, c)| percent_change(p, c));
        html! {
            <div class="pillar-statcard">
                <div class="pillar-statcard__label">{ props.label.clone() }</div>
                <div class="pillar-statcard__value">{ props.value.clone() }</div>
                if let Some((pct, trend)) = delta {
                    <div class={classes!(
                        "pillar-statcard__delta",
                        match trend {
                            Trend::Up => "is-up",
                            Trend::Down => "is-down",
                            Trend::Flat => "is-flat",
                        }
                    )}>
                        { format!("{}{:.1}%",
                            if pct > 0.0 { "+" } else { "" }, pct) }
                    </div>
                }
                if !props.spark.is_empty() {
                    <Sparkline values={props.spark.clone()} />
                }
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_change_reports_increase() {
        let (pct, trend) = percent_change(100.0, 150.0);
        assert!((pct - 50.0).abs() < 1e-9);
        assert_eq!(trend, Trend::Up);
    }

    #[test]
    fn percent_change_reports_decrease() {
        let (pct, trend) = percent_change(200.0, 150.0);
        assert!((pct - -25.0).abs() < 1e-9);
        assert_eq!(trend, Trend::Down);
    }

    #[test]
    fn percent_change_flat_when_equal_or_no_baseline() {
        assert_eq!(percent_change(50.0, 50.0).1, Trend::Flat);
        // Zero baseline never divides by zero.
        assert_eq!(percent_change(0.0, 99.0), (0.0, Trend::Flat));
    }
}
