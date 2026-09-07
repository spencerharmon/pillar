//! Design-system data-display primitives shared by the console's richer views
//! (resources, topology/trust, observability, overview). Each primitive keeps
//! the pillar rule of a **pure-logic core** that compiles and is unit-tested on
//! the native host, with a thin `yew` component wrapper (gated behind the `yew`
//! feature) that turns that logic into real DOM in the wasm bundle.
//!
//! The pure cores here are the SVG-chart coordinate math, the data-table
//! sort/filter ordering, the status→tone mapping, and the line diff — all
//! host-testable without a browser, so a regression is caught by
//! `cargo test -p pillar-web-frontend` and never only in the deployed app.

// ---------------------------------------------------------------------------
// Chart geometry (pure)
// ---------------------------------------------------------------------------

/// The drawable box a chart renders into, in SVG user units.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ChartBox {
    /// Total width in user units.
    pub width: f64,
    /// Total height in user units.
    pub height: f64,
    /// Inner padding kept clear on every edge so strokes are not clipped.
    pub pad: f64,
}

impl ChartBox {
    /// A conventional wide box with a small gutter.
    #[must_use]
    pub fn new(width: f64, height: f64, pad: f64) -> Self {
        Self { width, height, pad }
    }
}

/// Map a value series onto `(x, y)` coordinates inside `b`.
///
/// `x` spreads the samples evenly across the inner width (a single sample sits
/// on the left edge of the inner box); `y` is inverted (SVG y grows downward)
/// and normalized against the series' own min/max. A flat series (max == min,
/// including the empty and single-point cases) is pinned to the vertical
/// midline instead of dividing by zero.
#[must_use]
pub fn chart_coords(values: &[f64], b: ChartBox) -> Vec<(f64, f64)> {
    let n = values.len();
    if n == 0 {
        return Vec::new();
    }
    let inner_w = (b.width - 2.0 * b.pad).max(0.0);
    let inner_h = (b.height - 2.0 * b.pad).max(0.0);
    let (mut lo, mut hi) = (values[0], values[0]);
    for &v in values {
        lo = lo.min(v);
        hi = hi.max(v);
    }
    let span = hi - lo;
    values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let x = if n == 1 {
                b.pad
            } else {
                b.pad + inner_w * (i as f64) / ((n - 1) as f64)
            };
            let y = if span <= 0.0 {
                b.pad + inner_h / 2.0
            } else {
                // value at hi -> top (pad), at lo -> bottom (height-pad)
                b.pad + inner_h * (1.0 - (v - lo) / span)
            };
            (x, y)
        })
        .collect()
}

/// Format coordinates as an SVG `points="x,y x,y …"` polyline string.
#[must_use]
pub fn polyline_points(coords: &[(f64, f64)]) -> String {
    coords
        .iter()
        .map(|(x, y)| format!("{x:.2},{y:.2}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Build a closed SVG path (`d=`) that fills the area under the line down to the
/// chart's baseline. Empty when there are no points.
#[must_use]
pub fn area_path(coords: &[(f64, f64)], b: ChartBox) -> String {
    if coords.is_empty() {
        return String::new();
    }
    let baseline = b.height - b.pad;
    let mut d = format!("M {:.2},{:.2}", coords[0].0, coords[0].1);
    for (x, y) in &coords[1..] {
        d.push_str(&format!(" L {x:.2},{y:.2}"));
    }
    d.push_str(&format!(
        " L {:.2},{:.2} L {:.2},{:.2} Z",
        coords[coords.len() - 1].0,
        baseline,
        coords[0].0,
        baseline
    ));
    d
}

/// One bar rectangle in user units: `(x, y, width, height)`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BarRect {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Bar width.
    pub w: f64,
    /// Bar height (baseline − top).
    pub h: f64,
}

/// Lay out a bar chart: bars fill the inner width with a fixed inter-bar gap
/// fraction, heights normalized so the tallest bar reaches the top gutter. All
/// values are treated relative to zero (the natural bar-chart baseline), so a
/// zero value renders a zero-height bar rather than a midline.
#[must_use]
pub fn bar_rects(values: &[f64], b: ChartBox, gap_frac: f64) -> Vec<BarRect> {
    let n = values.len();
    if n == 0 {
        return Vec::new();
    }
    let inner_w = (b.width - 2.0 * b.pad).max(0.0);
    let inner_h = (b.height - 2.0 * b.pad).max(0.0);
    let gap = gap_frac.clamp(0.0, 0.9);
    let slot = inner_w / n as f64;
    let bw = slot * (1.0 - gap);
    let hi = values.iter().cloned().fold(0.0_f64, f64::max);
    let baseline = b.height - b.pad;
    values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let h = if hi <= 0.0 {
                0.0
            } else {
                inner_h * (v.max(0.0) / hi)
            };
            BarRect {
                x: b.pad + slot * i as f64 + (slot - bw) / 2.0,
                y: baseline - h,
                w: bw,
                h,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Data-table ordering (pure)
// ---------------------------------------------------------------------------

/// Compute the visible row order for a table: filter first (case-insensitive
/// substring across every cell), then a stable sort by one column when a sort
/// column is given. Numeric cells compare numerically; otherwise
/// case-insensitive lexicographic. Returns indices into `rows`.
#[must_use]
pub fn table_order(
    rows: &[Vec<String>],
    filter: &str,
    sort_col: Option<usize>,
    ascending: bool,
) -> Vec<usize> {
    let needle = filter.trim().to_lowercase();
    let mut idx: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| needle.is_empty() || r.iter().any(|c| c.to_lowercase().contains(&needle)))
        .map(|(i, _)| i)
        .collect();
    if let Some(col) = sort_col {
        idx.sort_by(|&a, &b| {
            let ca = rows[a].get(col).map(String::as_str).unwrap_or("");
            let cb = rows[b].get(col).map(String::as_str).unwrap_or("");
            let ord = match (ca.parse::<f64>(), cb.parse::<f64>()) {
                (Ok(na), Ok(nb)) => na.partial_cmp(&nb).unwrap_or(std::cmp::Ordering::Equal),
                _ => ca.to_lowercase().cmp(&cb.to_lowercase()),
            };
            if ascending {
                ord
            } else {
                ord.reverse()
            }
        });
    }
    idx
}

// ---------------------------------------------------------------------------
// Status tone (pure)
// ---------------------------------------------------------------------------

/// The semantic color family a status badge uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    /// No strong signal (unknown / informational-neutral).
    Neutral,
    /// In-progress / informational.
    Info,
    /// Healthy / succeeded.
    Success,
    /// Degraded / needs attention.
    Warn,
    /// Failed / error.
    Danger,
}

impl Tone {
    /// The CSS modifier suffix (`badge--<suffix>`) for this tone.
    #[must_use]
    pub fn css(self) -> &'static str {
        match self {
            Tone::Neutral => "neutral",
            Tone::Info => "info",
            Tone::Success => "success",
            Tone::Warn => "warn",
            Tone::Danger => "danger",
        }
    }
}

/// Map a free-form status/phase string (Kubernetes-ish, rollout, health) onto a
/// [`Tone`]. Matching is case-insensitive and substring-based so compound
/// phrases (`"Running (2/2 ready)"`, `"Progressing…"`) still classify.
#[must_use]
pub fn status_tone(status: &str) -> Tone {
    let s = status.to_lowercase();
    const DANGER: &[&str] = &[
        "fail",
        "error",
        "crashloop",
        "unhealthy",
        "denied",
        "lost",
        "evicted",
        "backoff",
        "notready",
        "not ready",
    ];
    const WARN: &[&str] = &[
        "warn", "degrad", "pending", "mismatch", "drift", "throttle", "partial",
    ];
    const SUCCESS: &[&str] = &[
        "run",
        "ready",
        "healthy",
        "ok",
        "success",
        "succeed",
        "active",
        "available",
        "synced",
        "bound",
        "complete",
        "verified",
        "trusted",
    ];
    const INFO: &[&str] = &["progress", "updat", "reconcil", "init", "creat", "start"];
    if DANGER.iter().any(|k| s.contains(k)) {
        return Tone::Danger;
    }
    if WARN.iter().any(|k| s.contains(k)) {
        return Tone::Warn;
    }
    if INFO.iter().any(|k| s.contains(k)) {
        return Tone::Info;
    }
    if SUCCESS.iter().any(|k| s.contains(k)) {
        return Tone::Success;
    }
    Tone::Neutral
}

// ---------------------------------------------------------------------------
// Graph layout (pure)
// ---------------------------------------------------------------------------

/// Lay out `n` nodes evenly on a circle centered at `(cx, cy)` with radius `r`,
/// starting at the top (12 o'clock) and going clockwise. A single node sits at
/// the center; zero nodes yields an empty layout. Used by the node-link graph
/// (trust graph) so the geometry is host-testable without a browser.
#[must_use]
pub fn circle_layout(n: usize, cx: f64, cy: f64, r: f64) -> Vec<(f64, f64)> {
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![(cx, cy)];
    }
    (0..n)
        .map(|i| {
            let theta =
                -std::f64::consts::FRAC_PI_2 + (i as f64) * std::f64::consts::TAU / (n as f64);
            (cx + r * theta.cos(), cy + r * theta.sin())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Line diff (pure)
// ---------------------------------------------------------------------------

/// The classification of a line in a two-sided diff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiffKind {
    /// Present unchanged in both sides.
    Same,
    /// Present only on the new side.
    Added,
    /// Present only on the old side.
    Removed,
}

/// A line-oriented diff of `old` vs `new` using a longest-common-subsequence
/// backtrace, so unchanged blocks are preserved and only genuine insertions /
/// deletions are marked. Used by the "diff before sync" resource preview.
#[must_use]
pub fn diff_lines(old: &str, new: &str) -> Vec<(DiffKind, String)> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    // LCS length table.
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = Vec::with_capacity(n + m);
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            out.push((DiffKind::Same, a[i].to_owned()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push((DiffKind::Removed, a[i].to_owned()));
            i += 1;
        } else {
            out.push((DiffKind::Added, b[j].to_owned()));
            j += 1;
        }
    }
    while i < n {
        out.push((DiffKind::Removed, a[i].to_owned()));
        i += 1;
    }
    while j < m {
        out.push((DiffKind::Added, b[j].to_owned()));
        j += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// Yew components (thin wrappers over the pure cores)
// ---------------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use yew_impl::*;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        area_path, bar_rects, chart_coords, circle_layout, diff_lines, polyline_points,
        status_tone, table_order, ChartBox, DiffKind, Tone,
    };
    use yew::prelude::*;

    /// Which glyph a [`Chart`] draws.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum ChartKind {
        /// A stroked polyline.
        Line,
        /// A stroked polyline with a filled area beneath it.
        Area,
        /// Vertical bars from a zero baseline.
        Bar,
    }

    /// Props for [`Chart`].
    #[derive(Properties, PartialEq)]
    pub struct ChartProps {
        /// The value series (left → right).
        pub values: Vec<f64>,
        /// Which glyph to draw.
        #[prop_or(ChartKind::Line)]
        pub kind: ChartKind,
        /// Viewbox width in user units.
        #[prop_or(320.0)]
        pub width: f64,
        /// Viewbox height in user units.
        #[prop_or(64.0)]
        pub height: f64,
    }

    /// A dependency-free inline SVG chart (line / area / bar) driven entirely by
    /// the host-tested geometry in the parent module.
    #[function_component(Chart)]
    pub fn chart(props: &ChartProps) -> Html {
        let b = ChartBox::new(props.width, props.height, 4.0);
        let vb = format!("0 0 {} {}", props.width, props.height);
        if props.values.is_empty() {
            return html! {
                <svg class="ds-chart" viewBox={vb} preserveAspectRatio="none" role="img" />
            };
        }
        let body = match props.kind {
            ChartKind::Bar => {
                let rects = bar_rects(&props.values, b, 0.3);
                html! { for rects.iter().map(|r| html! {
                    <rect class="ds-chart__bar" x={r.x.to_string()} y={r.y.to_string()}
                          width={r.w.to_string()} height={r.h.to_string()} />
                }) }
            }
            kind => {
                let coords = chart_coords(&props.values, b);
                let pts = polyline_points(&coords);
                let area = if matches!(kind, ChartKind::Area) {
                    let d = area_path(&coords, b);
                    html! { <path class="ds-chart__area" d={d} /> }
                } else {
                    Html::default()
                };
                html! {
                    <>
                        { area }
                        <polyline class="ds-chart__line" fill="none" points={pts} />
                    </>
                }
            }
        };
        html! {
            <svg class="ds-chart" viewBox={vb} preserveAspectRatio="none" role="img">
                { body }
            </svg>
        }
    }

    /// Props for [`StatCard`].
    #[derive(Properties, PartialEq)]
    pub struct StatCardProps {
        /// The metric caption.
        pub label: String,
        /// The primary value (already formatted).
        pub value: String,
        /// Optional trailing sparkline series.
        #[prop_or_default]
        pub spark: Vec<f64>,
        /// Optional status string, rendered as a tone-colored dot.
        #[prop_or_default]
        pub status: Option<String>,
    }

    /// A single KPI tile: big value, caption, optional sparkline and status dot.
    #[function_component(StatCard)]
    pub fn stat_card(props: &StatCardProps) -> Html {
        let dot = props.status.as_ref().map(|s| {
            let tone = status_tone(s);
            html! { <span class={classes!("ds-dot", format!("ds-dot--{}", tone.css()))}
            title={s.clone()} /> }
        });
        html! {
            <div class="ds-stat">
                <div class="ds-stat__head">
                    <span class="ds-stat__label">{ &props.label }</span>
                    { for dot }
                </div>
                <div class="ds-stat__value">{ &props.value }</div>
                if !props.spark.is_empty() {
                    <Chart values={props.spark.clone()} kind={ChartKind::Area}
                           width={140.0} height={28.0} />
                }
            </div>
        }
    }

    /// Props for [`Badge`].
    #[derive(Properties, PartialEq)]
    pub struct BadgeProps {
        /// The label text (also used to derive the tone when `tone` is absent).
        pub label: String,
        /// Force a tone; otherwise it is derived from `label` via `status_tone`.
        #[prop_or_default]
        pub tone: Option<Tone>,
    }

    /// A small status pill; color follows [`status_tone`] unless overridden.
    #[function_component(Badge)]
    pub fn badge(props: &BadgeProps) -> Html {
        let tone = props.tone.unwrap_or_else(|| status_tone(&props.label));
        html! {
            <span class={classes!("ds-badge", format!("ds-badge--{}", tone.css()))}>
                { &props.label }
            </span>
        }
    }

    /// Props for [`Tabs`].
    #[derive(Properties, PartialEq)]
    pub struct TabsProps {
        /// The ordered tab captions.
        pub tabs: Vec<String>,
        /// The index of the active tab.
        pub selected: usize,
        /// Fired with the clicked tab's index.
        pub onselect: Callback<usize>,
    }

    /// A reusable tab strip; the parent owns the selected index.
    #[function_component(Tabs)]
    pub fn tabs(props: &TabsProps) -> Html {
        html! {
            <div class="ds-tabs" role="tablist">
                { for props.tabs.iter().enumerate().map(|(i, label)| {
                    let onselect = props.onselect.clone();
                    let onclick = Callback::from(move |_: MouseEvent| onselect.emit(i));
                    let active = i == props.selected;
                    html! {
                        <button class={classes!("ds-tab", active.then_some("is-active"))}
                                role="tab" aria-selected={active.to_string()} {onclick}>
                            { label }
                        </button>
                    }
                }) }
            </div>
        }
    }

    /// Props for [`DataTable`].
    #[derive(Properties, PartialEq)]
    pub struct DataTableProps {
        /// Column headers (also the sort handles).
        pub columns: Vec<String>,
        /// Row cells, each row parallel to `columns`.
        pub rows: Vec<Vec<String>>,
        /// Show the filter box.
        #[prop_or(true)]
        pub filterable: bool,
    }

    /// A sortable, filterable table over string cells. Sort/filter ordering is
    /// the host-tested [`table_order`]; the component only owns UI state.
    #[function_component(DataTable)]
    pub fn data_table(props: &DataTableProps) -> Html {
        let filter = use_state(String::new);
        let sort = use_state(|| None::<(usize, bool)>);

        let on_filter = {
            let filter = filter.clone();
            Callback::from(move |e: InputEvent| {
                use wasm_bindgen::JsCast;
                if let Some(t) = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                {
                    filter.set(t.value());
                }
            })
        };

        let (sort_col, asc) = match *sort {
            Some((c, a)) => (Some(c), a),
            None => (None, true),
        };
        let order = table_order(&props.rows, &filter, sort_col, asc);

        html! {
            <div class="ds-table-wrap">
                if props.filterable {
                    <input class="ds-table__filter" type="text" placeholder="Filter…"
                           value={(*filter).clone()} oninput={on_filter} />
                }
                <table class="ds-table">
                    <thead>
                        <tr>
                            { for props.columns.iter().enumerate().map(|(c, h)| {
                                let arrow = match *sort {
                                    Some((col, a)) if col == c => {
                                        if a { " ▲" } else { " ▼" }
                                    }
                                    _ => "",
                                };
                                let sort = sort.clone();
                                let onclick = Callback::from(move |_: MouseEvent| {
                                    sort.set(Some(match *sort {
                                        Some((col, a)) if col == c => (c, !a),
                                        _ => (c, true),
                                    }));
                                });
                                html! { <th {onclick}>{ h }{ arrow }</th> }
                            }) }
                        </tr>
                    </thead>
                    <tbody>
                        { for order.iter().map(|&r| html! {
                            <tr>
                                { for props.rows[r].iter().map(|cell| html! {
                                    <td>{ cell }</td>
                                }) }
                            </tr>
                        }) }
                    </tbody>
                </table>
                if order.is_empty() {
                    <p class="ds-empty">{ "No rows." }</p>
                }
            </div>
        }
    }

    /// Props for [`Drawer`].
    #[derive(Properties, PartialEq)]
    pub struct DrawerProps {
        /// Whether the drawer is shown.
        pub open: bool,
        /// The drawer title.
        pub title: String,
        /// Fired when the scrim or close control is clicked.
        pub onclose: Callback<()>,
        /// The drawer body.
        #[prop_or_default]
        pub children: Html,
    }

    /// A right-side slide-over panel with a dimming scrim.
    #[function_component(Drawer)]
    pub fn drawer(props: &DrawerProps) -> Html {
        if !props.open {
            return Html::default();
        }
        let close = props.onclose.clone();
        let on_scrim = Callback::from(move |_: MouseEvent| close.emit(()));
        let close2 = props.onclose.clone();
        let on_x = Callback::from(move |_: MouseEvent| close2.emit(()));
        html! {
            <div class="ds-drawer">
                <div class="ds-drawer__scrim" onclick={on_scrim} />
                <aside class="ds-drawer__panel" role="dialog" aria-label={props.title.clone()}>
                    <header class="ds-drawer__head">
                        <h3>{ &props.title }</h3>
                        <button class="ds-drawer__x" onclick={on_x} aria-label="Close">
                            { "✕" }
                        </button>
                    </header>
                    <div class="ds-drawer__body">{ props.children.clone() }</div>
                </aside>
            </div>
        }
    }

    /// Props for [`CodeBlock`].
    #[derive(Properties, PartialEq)]
    pub struct CodeBlockProps {
        /// The monospace text.
        pub text: String,
    }

    /// A monospace, scrollable code/log block.
    #[function_component(CodeBlock)]
    pub fn code_block(props: &CodeBlockProps) -> Html {
        html! { <pre class="ds-code"><code>{ &props.text }</code></pre> }
    }

    /// Props for [`DiffView`].
    #[derive(Properties, PartialEq)]
    pub struct DiffViewProps {
        /// The current/old text.
        pub old: String,
        /// The proposed/new text.
        pub new: String,
    }

    /// A two-color line diff (the "diff before sync" preview), classified by the
    /// host-tested [`diff_lines`].
    #[function_component(DiffView)]
    pub fn diff_view(props: &DiffViewProps) -> Html {
        let lines = diff_lines(&props.old, &props.new);
        if lines.iter().all(|(k, _)| *k == DiffKind::Same) {
            return html! { <p class="ds-empty">{ "No changes — identical." }</p> };
        }
        html! {
            <pre class="ds-diff">
                { for lines.iter().map(|(k, l)| {
                    let (cls, sign) = match k {
                        DiffKind::Added => ("is-add", "+"),
                        DiffKind::Removed => ("is-del", "-"),
                        DiffKind::Same => ("is-same", " "),
                    };
                    html! { <div class={classes!("ds-diff__line", cls)}>
                        <span class="ds-diff__sign">{ sign }</span>{ l }
                    </div> }
                }) }
            </pre>
        }
    }

    /// A node in a [`Tree`].
    #[derive(Clone, PartialEq)]
    pub struct TreeNode {
        /// The node label.
        pub label: String,
        /// Optional status string → tone dot.
        pub status: Option<String>,
        /// Child nodes.
        pub children: Vec<TreeNode>,
    }

    impl TreeNode {
        /// A leaf with just a label.
        #[must_use]
        pub fn leaf(label: impl Into<String>) -> Self {
            Self {
                label: label.into(),
                status: None,
                children: Vec::new(),
            }
        }
    }

    /// Props for [`Tree`].
    #[derive(Properties, PartialEq)]
    pub struct TreeProps {
        /// The root nodes.
        pub roots: Vec<TreeNode>,
    }

    /// A nested, indented tree with per-node status dots (topology / failure
    /// domains). Rendered with `<details>` so each branch is collapsible with no
    /// JavaScript state.
    #[function_component(Tree)]
    pub fn tree(props: &TreeProps) -> Html {
        html! { <ul class="ds-tree">{ for props.roots.iter().map(render_node) }</ul> }
    }

    fn render_node(n: &TreeNode) -> Html {
        let dot = n.status.as_ref().map(|s| {
            let tone = super::status_tone(s);
            html! { <span class={classes!("ds-dot", format!("ds-dot--{}", tone.css()))}
            title={s.clone()} /> }
        });
        if n.children.is_empty() {
            return html! {
                <li class="ds-tree__leaf">{ for dot }<span>{ &n.label }</span></li>
            };
        }
        html! {
            <li class="ds-tree__branch">
                <details open=true>
                    <summary>{ for dot }<span>{ &n.label }</span></summary>
                    <ul>{ for n.children.iter().map(render_node) }</ul>
                </details>
            </li>
        }
    }

    /// One edge of a [`Graph`]: endpoint node indices plus a label.
    #[derive(Clone, PartialEq)]
    pub struct GraphEdge {
        /// Index into the `nodes` vec of the source.
        pub from: usize,
        /// Index into the `nodes` vec of the target.
        pub to: usize,
        /// The edge label (e.g. the trust relation).
        pub label: String,
    }

    /// Props for [`Graph`].
    #[derive(Properties, PartialEq)]
    pub struct GraphProps {
        /// Node labels; positions are derived by [`circle_layout`].
        pub nodes: Vec<String>,
        /// Directed, labeled edges between nodes.
        pub edges: Vec<GraphEdge>,
    }

    /// A dependency-free node-link graph on a circular layout: edges as lines
    /// (with an arrowhead marker), nodes as labeled dots. The layout math is the
    /// host-tested [`circle_layout`].
    #[function_component(Graph)]
    pub fn graph(props: &GraphProps) -> Html {
        let (w, h) = (520.0_f64, 360.0_f64);
        if props.nodes.is_empty() {
            return html! { <p class="ds-empty">{ "No edges to graph." }</p> };
        }
        let pos = circle_layout(props.nodes.len(), w / 2.0, h / 2.0, h / 2.0 - 48.0);
        let vb = format!("0 0 {w} {h}");
        html! {
            <svg class="ds-graph" viewBox={vb} role="img">
                <defs>
                    <marker id="ds-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                            markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" class="ds-graph__arrow" />
                    </marker>
                </defs>
                { for props.edges.iter().filter_map(|e| {
                    let (a, b) = (pos.get(e.from)?, pos.get(e.to)?);
                    let (mx, my) = ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0);
                    Some(html! {
                        <>
                            <line class="ds-graph__edge" x1={a.0.to_string()} y1={a.1.to_string()}
                                  x2={b.0.to_string()} y2={b.1.to_string()} marker-end="url(#ds-arrow)" />
                            <text class="ds-graph__elabel" x={mx.to_string()} y={my.to_string()}>
                                { &e.label }
                            </text>
                        </>
                    })
                }) }
                { for props.nodes.iter().enumerate().map(|(i, label)| {
                    let (x, y) = pos[i];
                    html! {
                        <>
                            <circle class="ds-graph__node" cx={x.to_string()} cy={y.to_string()} r="7" />
                            <text class="ds-graph__nlabel" x={x.to_string()}
                                  y={(y - 12.0).to_string()}>{ label }</text>
                        </>
                    }
                }) }
            </svg>
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chart_coords_spread_and_invert() {
        let b = ChartBox::new(100.0, 40.0, 0.0);
        let c = chart_coords(&[0.0, 5.0, 10.0], b);
        // x spreads 0 .. width across 3 samples.
        assert_eq!(c[0].0, 0.0);
        assert!((c[1].0 - 50.0).abs() < 1e-9);
        assert_eq!(c[2].0, 100.0);
        // y is inverted: max value -> top (0), min -> bottom (height).
        assert_eq!(c[2].1, 0.0);
        assert_eq!(c[0].1, 40.0);
        assert!((c[1].1 - 20.0).abs() < 1e-9);
    }

    #[test]
    fn chart_flat_and_empty_series_never_divide_by_zero() {
        let b = ChartBox::new(100.0, 40.0, 0.0);
        assert!(chart_coords(&[], b).is_empty());
        let flat = chart_coords(&[7.0, 7.0, 7.0], b);
        // all pinned to the midline.
        for (_, y) in flat {
            assert!((y - 20.0).abs() < 1e-9);
        }
        let single = chart_coords(&[42.0], b);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].0, 0.0);
    }

    #[test]
    fn area_path_closes_to_baseline() {
        let b = ChartBox::new(100.0, 40.0, 0.0);
        let coords = chart_coords(&[1.0, 2.0], b);
        let d = area_path(&coords, b);
        assert!(d.starts_with("M "));
        assert!(d.ends_with(" Z"));
        // baseline is height - pad = 40.
        assert!(d.contains(",40.00"));
        assert!(area_path(&[], b).is_empty());
    }

    #[test]
    fn bars_are_zero_based_and_gapped() {
        let b = ChartBox::new(100.0, 40.0, 0.0);
        let bars = bar_rects(&[0.0, 10.0], b, 0.2);
        assert_eq!(bars.len(), 2);
        // zero value -> zero height, at baseline.
        assert_eq!(bars[0].h, 0.0);
        assert_eq!(bars[0].y, 40.0);
        // tallest reaches full inner height.
        assert!((bars[1].h - 40.0).abs() < 1e-9);
        // gap shrinks bar width below its slot (slot = 50).
        assert!(bars[0].w < 50.0);
    }

    #[test]
    fn table_order_filters_then_sorts_numerically() {
        let rows = vec![
            vec!["web".into(), "10".into()],
            vec!["db".into(), "2".into()],
            vec!["cache".into(), "30".into()],
        ];
        // filter keeps only the substring match.
        let f = table_order(&rows, "web", None, true);
        assert_eq!(f, vec![0]);
        // numeric sort ascending by column 1 -> 2,10,30 => rows 1,0,2.
        let asc = table_order(&rows, "", Some(1), true);
        assert_eq!(asc, vec![1, 0, 2]);
        // descending reverses.
        let desc = table_order(&rows, "", Some(1), false);
        assert_eq!(desc, vec![2, 0, 1]);
    }

    #[test]
    fn table_order_lexicographic_when_non_numeric() {
        let rows = vec![
            vec!["Beta".into()],
            vec!["alpha".into()],
            vec!["Gamma".into()],
        ];
        let asc = table_order(&rows, "", Some(0), true);
        // case-insensitive: alpha, Beta, Gamma.
        assert_eq!(asc, vec![1, 0, 2]);
    }

    #[test]
    fn status_tone_classifies_common_phases() {
        assert_eq!(status_tone("Running (2/2 ready)"), Tone::Success);
        assert_eq!(status_tone("CrashLoopBackOff"), Tone::Danger);
        assert_eq!(status_tone("Pending"), Tone::Warn);
        assert_eq!(status_tone("Progressing…"), Tone::Info);
        assert_eq!(status_tone("Synced"), Tone::Success);
        assert_eq!(status_tone("weird-custom-state"), Tone::Neutral);
        // danger wins over an incidental success word.
        assert_eq!(status_tone("readiness probe failed"), Tone::Danger);
    }

    #[test]
    fn diff_lines_marks_insertions_and_deletions() {
        let old = "a\nb\nc\n";
        let new = "a\nB\nc\nd\n";
        let d = diff_lines(old, new);
        // 'a' same, 'b' removed, 'B' added, 'c' same, 'd' added.
        assert_eq!(d[0], (DiffKind::Same, "a".to_owned()));
        assert!(d.contains(&(DiffKind::Removed, "b".to_owned())));
        assert!(d.contains(&(DiffKind::Added, "B".to_owned())));
        assert!(d.contains(&(DiffKind::Same, "c".to_owned())));
        assert_eq!(d.last().unwrap(), &(DiffKind::Added, "d".to_owned()));
    }

    #[test]
    fn diff_identical_is_all_same() {
        let d = diff_lines("x\ny\n", "x\ny\n");
        assert!(d.iter().all(|(k, _)| *k == DiffKind::Same));
    }

    #[test]
    fn circle_layout_places_nodes_on_the_ring() {
        assert!(circle_layout(0, 0.0, 0.0, 10.0).is_empty());
        // one node sits at the center.
        assert_eq!(circle_layout(1, 5.0, 6.0, 10.0), vec![(5.0, 6.0)]);
        // first of many starts at 12 o'clock: same x as center, y = cy - r.
        let p = circle_layout(4, 0.0, 0.0, 10.0);
        assert_eq!(p.len(), 4);
        assert!((p[0].0 - 0.0).abs() < 1e-9);
        assert!((p[0].1 - -10.0).abs() < 1e-9);
        // every node is at radius r from the center.
        for (x, y) in p {
            assert!(((x * x + y * y).sqrt() - 10.0).abs() < 1e-9);
        }
    }

    /// Mount-audit guard (anti-facade DoD): the global stylesheet must carry the
    /// primitives' CSS classes, so a primitive rendered in a mounted view is
    /// actually styled rather than silently orphaned.
    #[test]
    fn primitive_styles_are_emitted_in_the_global_sheet() {
        let css = crate::styles::global(&crate::theme::Theme::dark(), crate::theme::Motion::Full);
        for class in [
            ".ds-chart",
            ".ds-stat",
            ".ds-badge",
            ".ds-tabs",
            ".ds-table",
            ".ds-drawer",
            ".ds-code",
            ".ds-diff",
            ".ds-tree",
            ".ds-graph",
        ] {
            assert!(css.contains(class), "global sheet missing {class}");
        }
    }
}
