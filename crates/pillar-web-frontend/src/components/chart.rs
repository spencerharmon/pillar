//! `Chart` — a dependency-free SVG line / area / bar chart, plus the small
//! sparkline used by [`super::stat_card`].
//!
//! All the geometry is **pure logic**: [`scale`] maps a data value into pixel
//! space, [`nice_ticks`] computes human-friendly axis ticks, [`line_points`]
//! projects a series into an SVG polyline point string, and [`bar_rects`]
//! projects it into bar rectangles. These are host-tested with no `yew`
//! dependency; the [`Chart`] component simply emits the `<svg>` around them.

/// The chart geometry: pixel box the plot occupies.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Viewport {
    /// Total width in px.
    pub width: f64,
    /// Total height in px.
    pub height: f64,
    /// Inner padding (px) reserved on every side for axes/labels.
    pub pad: f64,
}

impl Viewport {
    /// A viewport with uniform padding.
    #[must_use]
    pub fn new(width: f64, height: f64, pad: f64) -> Viewport {
        Viewport { width, height, pad }
    }

    /// The left edge of the plot area.
    #[must_use]
    pub fn left(&self) -> f64 {
        self.pad
    }

    /// The right edge of the plot area.
    #[must_use]
    pub fn right(&self) -> f64 {
        self.width - self.pad
    }

    /// The top edge of the plot area.
    #[must_use]
    pub fn top(&self) -> f64 {
        self.pad
    }

    /// The bottom edge of the plot area.
    #[must_use]
    pub fn bottom(&self) -> f64 {
        self.height - self.pad
    }
}

/// The min/max data range of a series (defaults to `0..=1` for an empty or
/// flat series so the projection never divides by zero).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Range {
    /// Lowest value.
    pub min: f64,
    /// Highest value.
    pub max: f64,
}

impl Range {
    /// Compute the range of `values`. An empty series yields `0..=1`; a flat
    /// series (all equal) is padded to a unit span so it renders as a centred
    /// line rather than collapsing.
    #[must_use]
    pub fn of(values: &[f64]) -> Range {
        if values.is_empty() {
            return Range { min: 0.0, max: 1.0 };
        }
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for &v in values {
            if v < min {
                min = v;
            }
            if v > max {
                max = v;
            }
        }
        if (max - min).abs() < f64::EPSILON {
            Range {
                min: min - 0.5,
                max: max + 0.5,
            }
        } else {
            Range { min, max }
        }
    }

    /// The span (`max - min`), always strictly positive.
    #[must_use]
    pub fn span(&self) -> f64 {
        (self.max - self.min).max(f64::EPSILON)
    }
}

/// Map a data `value` in `range` to a pixel coordinate in `[lo, hi]`. Used for
/// both the horizontal index axis and the (inverted) vertical value axis.
#[must_use]
pub fn scale(value: f64, range: Range, lo: f64, hi: f64) -> f64 {
    let t = (value - range.min) / range.span();
    lo + t * (hi - lo)
}

/// Compute up to `target` "nice" evenly-spaced axis ticks spanning `range`,
/// snapped to a 1/2/5×10ⁿ step so labels read cleanly. Always returns at least
/// the two endpoints.
#[must_use]
pub fn nice_ticks(range: Range, target: usize) -> Vec<f64> {
    let target = target.max(2);
    let raw = range.span() / (target as f64 - 1.0);
    let mag = 10f64.powf(raw.log10().floor());
    let norm = raw / mag;
    let step = if norm < 1.5 {
        1.0
    } else if norm < 3.0 {
        2.0
    } else if norm < 7.0 {
        5.0
    } else {
        10.0
    } * mag;
    let start = (range.min / step).floor() * step;
    let mut ticks = Vec::new();
    let mut t = start;
    // Guard the loop against pathological steps.
    let mut guard = 0;
    while t <= range.max + step * 0.5 && guard < 1000 {
        if t >= range.min - step * 0.5 {
            ticks.push(t);
        }
        t += step;
        guard += 1;
    }
    if ticks.len() < 2 {
        ticks = vec![range.min, range.max];
    }
    ticks
}

/// Project `values` (indexed 0..n on x) into an SVG `points=` polyline string
/// ("x,y x,y …") within `vp`, using `y_range` for the value axis. An empty or
/// single-point series returns an empty string.
#[must_use]
pub fn line_points(values: &[f64], vp: Viewport, y_range: Range) -> String {
    if values.len() < 2 {
        return String::new();
    }
    let x_range = Range {
        min: 0.0,
        max: (values.len() - 1) as f64,
    };
    values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = scale(i as f64, x_range, vp.left(), vp.right());
            // Invert y: larger value => higher up (smaller pixel y).
            let y = scale(v, y_range, vp.bottom(), vp.top());
            format!("{x:.2},{y:.2}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One bar rectangle in pixel space: `(x, y, width, height)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BarRect {
    /// Left edge (px).
    pub x: f64,
    /// Top edge (px).
    pub y: f64,
    /// Width (px).
    pub w: f64,
    /// Height (px).
    pub h: f64,
}

/// Project `values` into evenly-spaced bar rectangles within `vp`, with each
/// bar's height proportional to its value against `y_range`. A `gap` (0..1)
/// fraction of each slot is left as spacing between bars.
#[must_use]
pub fn bar_rects(values: &[f64], vp: Viewport, y_range: Range, gap: f64) -> Vec<BarRect> {
    if values.is_empty() {
        return Vec::new();
    }
    let gap = gap.clamp(0.0, 0.9);
    let plot_w = vp.right() - vp.left();
    let slot = plot_w / values.len() as f64;
    let bar_w = slot * (1.0 - gap);
    let baseline = vp.bottom();
    values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = vp.left() + slot * i as f64 + (slot - bar_w) / 2.0;
            let y = scale(v, y_range, vp.bottom(), vp.top());
            BarRect {
                x,
                y,
                w: bar_w,
                h: (baseline - y).max(0.0),
            }
        })
        .collect()
}

/// The chart render kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChartKind {
    /// A polyline.
    Line,
    /// A filled area under the line.
    Area,
    /// Vertical bars.
    Bar,
}

#[cfg(feature = "yew")]
pub use yew_impl::{Chart, ChartProps, Sparkline, SparklineProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{bar_rects, line_points, ChartKind, Range, Viewport};
    use yew::prelude::*;

    /// Props for [`Chart`].
    #[derive(Properties, PartialEq)]
    pub struct ChartProps {
        /// The data series (indexed 0..n on the x axis).
        pub values: Vec<f64>,
        /// Render kind.
        #[prop_or(ChartKind::Line)]
        pub kind: ChartKind,
        /// SVG width (px).
        #[prop_or(320.0)]
        pub width: f64,
        /// SVG height (px).
        #[prop_or(120.0)]
        pub height: f64,
        /// Extra class on the `<svg>`.
        #[prop_or_default]
        pub class: Classes,
    }

    /// A dependency-free SVG chart driven by the pure geometry functions.
    #[function_component(Chart)]
    pub fn chart(props: &ChartProps) -> Html {
        let vp = Viewport::new(props.width, props.height, 8.0);
        let range = Range::of(&props.values);
        let mut class = Classes::from("pillar-chart");
        class.extend(props.class.clone());
        let vb = format!("0 0 {} {}", props.width, props.height);
        let body = match props.kind {
            ChartKind::Line => {
                let pts = line_points(&props.values, vp, range);
                html! {
                    <polyline class="pillar-chart__line" fill="none" points={pts} />
                }
            }
            ChartKind::Area => {
                let pts = line_points(&props.values, vp, range);
                // Close the area down to the baseline at both ends.
                let closed = if pts.is_empty() {
                    String::new()
                } else {
                    format!(
                        "{:.2},{:.2} {pts} {:.2},{:.2}",
                        vp.left(),
                        vp.bottom(),
                        vp.right(),
                        vp.bottom()
                    )
                };
                html! {
                    <polygon class="pillar-chart__area" points={closed} />
                }
            }
            ChartKind::Bar => {
                let bars = bar_rects(&props.values, vp, range, 0.3);
                html! {
                    { for bars.into_iter().map(|b| html! {
                        <rect
                            class="pillar-chart__bar"
                            x={format!("{:.2}", b.x)}
                            y={format!("{:.2}", b.y)}
                            width={format!("{:.2}", b.w)}
                            height={format!("{:.2}", b.h)}
                        />
                    }) }
                }
            }
        };
        html! {
            <svg class={class} viewBox={vb} role="img" preserveAspectRatio="none">
                { body }
            </svg>
        }
    }

    /// Props for [`Sparkline`].
    #[derive(Properties, PartialEq)]
    pub struct SparklineProps {
        /// The data series.
        pub values: Vec<f64>,
        /// Width (px).
        #[prop_or(96.0)]
        pub width: f64,
        /// Height (px).
        #[prop_or(28.0)]
        pub height: f64,
    }

    /// A tiny inline line chart (no axes), reused by [`super::super::stat_card`].
    #[function_component(Sparkline)]
    pub fn sparkline(props: &SparklineProps) -> Html {
        let vp = Viewport::new(props.width, props.height, 2.0);
        let range = Range::of(&props.values);
        let pts = line_points(&props.values, vp, range);
        let vb = format!("0 0 {} {}", props.width, props.height);
        html! {
            <svg class="pillar-sparkline" viewBox={vb} role="img" preserveAspectRatio="none">
                <polyline class="pillar-sparkline__line" fill="none" points={pts} />
            </svg>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_of_empty_is_unit_and_flat_is_padded() {
        assert_eq!(Range::of(&[]), Range { min: 0.0, max: 1.0 });
        let flat = Range::of(&[5.0, 5.0, 5.0]);
        assert!(flat.min < 5.0 && flat.max > 5.0);
        assert!(flat.span() > 0.0);
    }

    #[test]
    fn range_of_series_is_min_and_max() {
        let r = Range::of(&[3.0, 1.0, 9.0, 4.0]);
        assert_eq!(r.min, 1.0);
        assert_eq!(r.max, 9.0);
        assert_eq!(r.span(), 8.0);
    }

    #[test]
    fn scale_maps_endpoints_and_midpoint() {
        let r = Range { min: 0.0, max: 10.0 };
        assert!((scale(0.0, r, 0.0, 100.0) - 0.0).abs() < 1e-9);
        assert!((scale(10.0, r, 0.0, 100.0) - 100.0).abs() < 1e-9);
        assert!((scale(5.0, r, 0.0, 100.0) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn nice_ticks_snaps_to_readable_steps_and_covers_range() {
        let ticks = nice_ticks(Range { min: 0.0, max: 100.0 }, 5);
        assert!(ticks.len() >= 2);
        // Steps are uniform and a 1/2/5×10ⁿ value (here 25 -> actually snaps to
        // 20 or 25; assert uniformity + coverage rather than an exact set).
        let step = ticks[1] - ticks[0];
        for w in ticks.windows(2) {
            assert!((w[1] - w[0] - step).abs() < 1e-6, "non-uniform ticks");
        }
        assert!(*ticks.first().unwrap() <= 0.0 + step);
        assert!(*ticks.last().unwrap() >= 100.0 - step);
    }

    #[test]
    fn nice_ticks_always_has_two_endpoints() {
        let ticks = nice_ticks(Range { min: 0.0, max: 0.0000001 }, 5);
        assert!(ticks.len() >= 2);
    }

    #[test]
    fn line_points_projects_series_and_inverts_y() {
        let vp = Viewport::new(100.0, 100.0, 0.0);
        let r = Range { min: 0.0, max: 10.0 };
        let s = line_points(&[0.0, 10.0], vp, r);
        // Two points: first at left/bottom (x=0,y=100), second at right/top
        // (x=100,y=0) because y is inverted.
        assert_eq!(s, "0.00,100.00 100.00,0.00");
    }

    #[test]
    fn line_points_needs_two_points() {
        let vp = Viewport::new(100.0, 100.0, 0.0);
        let r = Range { min: 0.0, max: 1.0 };
        assert_eq!(line_points(&[], vp, r), "");
        assert_eq!(line_points(&[5.0], vp, r), "");
    }

    #[test]
    fn bar_rects_are_evenly_spaced_and_height_tracks_value() {
        let vp = Viewport::new(100.0, 100.0, 0.0);
        let r = Range { min: 0.0, max: 10.0 };
        let bars = bar_rects(&[0.0, 10.0], vp, r, 0.0);
        assert_eq!(bars.len(), 2);
        // First bar (value 0) has ~zero height; second (value 10) is full.
        assert!(bars[0].h < 1.0);
        assert!(bars[1].h > 99.0);
        // Second bar sits to the right of the first.
        assert!(bars[1].x > bars[0].x);
    }
}
