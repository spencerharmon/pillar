//! `DataTable` — a sortable / filterable / paginated table primitive.
//!
//! The sort / filter / paginate work is **pure logic** ([`sort_rows`],
//! [`filter_rows`], [`paginate`], [`page_count`]) with NO `yew` dependency, so it
//! is host-tested in isolation by `cargo test -p pillar-web-frontend`. The
//! [`DataTable`] Yew component (behind the `yew` feature) is a thin rendering
//! wrapper that drives those functions from component state.
//!
//! A table is described by a set of [`Column`]s plus a list of row records; each
//! row is a `Vec<String>` of cells positioned to match the columns. This keeps
//! the primitive generic — a caller maps its own record type onto column cells
//! (see `obs_console.rs`, the first real consumer, mapping a `DashSignal` onto
//! the signal/kind/payload columns).

/// The sort direction for a [`Column`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortDir {
    /// Ascending (A→Z, 0→9).
    Asc,
    /// Descending (Z→A, 9→0).
    Desc,
}

impl SortDir {
    /// The opposite direction (used to toggle on a repeat header click).
    #[must_use]
    pub fn toggled(self) -> SortDir {
        match self {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        }
    }
}

/// A table column definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    /// The column header label.
    pub label: String,
    /// Whether this column is user-sortable.
    pub sortable: bool,
    /// Whether cells in this column compare **numerically** when sorting
    /// (falls back to string order when a cell does not parse as a number).
    pub numeric: bool,
}

impl Column {
    /// A plain, sortable, string-ordered column.
    #[must_use]
    pub fn text(label: impl Into<String>) -> Column {
        Column {
            label: label.into(),
            sortable: true,
            numeric: false,
        }
    }

    /// A numerically-sorted column.
    #[must_use]
    pub fn numeric(label: impl Into<String>) -> Column {
        Column {
            label: label.into(),
            sortable: true,
            numeric: true,
        }
    }

    /// A column that cannot be sorted (e.g. a free-form payload).
    #[must_use]
    pub fn unsortable(label: impl Into<String>) -> Column {
        Column {
            label: label.into(),
            sortable: false,
            numeric: false,
        }
    }
}

/// A row of cells, one per column (by position).
pub type Row = Vec<String>;

/// Filter `rows` to those with ANY cell containing `needle`
/// (case-insensitive). An empty needle keeps every row (order preserved).
#[must_use]
pub fn filter_rows(rows: &[Row], needle: &str) -> Vec<Row> {
    let needle = needle.trim().to_lowercase();
    if needle.is_empty() {
        return rows.to_vec();
    }
    rows.iter()
        .filter(|row| {
            row.iter()
                .any(|cell| cell.to_lowercase().contains(&needle))
        })
        .cloned()
        .collect()
}

/// Sort a copy of `rows` by `col` in direction `dir`.
///
/// When `numeric` is set the cells are compared as `f64` (a non-numeric cell
/// sorts as if `-inf`, keeping the comparison total); otherwise a
/// case-insensitive string comparison is used. The sort is **stable**, so rows
/// equal on the sort key keep their original relative order. An out-of-range
/// `col` returns the rows unchanged.
#[must_use]
pub fn sort_rows(rows: &[Row], col: usize, dir: SortDir, numeric: bool) -> Vec<Row> {
    let mut out = rows.to_vec();
    if out.iter().any(|r| col >= r.len()) || out.is_empty() {
        // A ragged/empty set: only sort if every row has the column.
        if out.iter().any(|r| col >= r.len()) {
            return out;
        }
    }
    out.sort_by(|a, b| {
        let (ca, cb) = (a.get(col).map_or("", String::as_str), b.get(col).map_or("", String::as_str));
        let ord = if numeric {
            let pa = ca.trim().parse::<f64>().unwrap_or(f64::NEG_INFINITY);
            let pb = cb.trim().parse::<f64>().unwrap_or(f64::NEG_INFINITY);
            pa.partial_cmp(&pb).unwrap_or(std::cmp::Ordering::Equal)
        } else {
            ca.to_lowercase().cmp(&cb.to_lowercase())
        };
        match dir {
            SortDir::Asc => ord,
            SortDir::Desc => ord.reverse(),
        }
    });
    out
}

/// The number of pages for `total` rows at `page_size` rows per page
/// (at least 1; a zero `page_size` is treated as "all on one page").
#[must_use]
pub fn page_count(total: usize, page_size: usize) -> usize {
    if page_size == 0 {
        return 1;
    }
    ((total + page_size - 1) / page_size).max(1)
}

/// The slice of `rows` visible on page `page` (0-based) at `page_size` rows per
/// page. A `page` past the end yields an empty slice; a zero `page_size` yields
/// every row.
#[must_use]
pub fn paginate(rows: &[Row], page: usize, page_size: usize) -> Vec<Row> {
    if page_size == 0 {
        return rows.to_vec();
    }
    let start = page.saturating_mul(page_size);
    if start >= rows.len() {
        return Vec::new();
    }
    let end = (start + page_size).min(rows.len());
    rows[start..end].to_vec()
}

#[cfg(feature = "yew")]
pub use yew_impl::{DataTable, DataTableProps};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{filter_rows, page_count, paginate, sort_rows, Column, Row, SortDir};
    use yew::prelude::*;

    /// Props for [`DataTable`].
    #[derive(Properties, PartialEq)]
    pub struct DataTableProps {
        /// The column definitions (header + sort behaviour).
        pub columns: Vec<Column>,
        /// The full row set (each a cell-per-column vector).
        pub rows: Vec<Row>,
        /// Rows per page. `0` disables pagination (all rows on one page).
        #[prop_or(0)]
        pub page_size: usize,
        /// Whether to render the filter input.
        #[prop_or(true)]
        pub filterable: bool,
        /// Optional extra class on the wrapping element.
        #[prop_or_default]
        pub class: Classes,
    }

    /// A sortable / filterable / paginated table over [`DataTableProps`]. Header
    /// clicks on a sortable column toggle its sort; the filter input narrows to
    /// matching rows; pagination controls page through the result. All three
    /// operations run through the host-tested pure functions in the parent
    /// module — the component only holds UI state and renders.
    #[function_component(DataTable)]
    pub fn data_table(props: &DataTableProps) -> Html {
        let sort = use_state(|| None::<(usize, SortDir)>);
        let query = use_state(String::new);
        let page = use_state(|| 0usize);

        // filter → sort → paginate, all via the pure functions.
        let filtered = filter_rows(&props.rows, &query);
        let sorted = match *sort {
            Some((col, dir)) => {
                let numeric = props.columns.get(col).is_some_and(|c| c.numeric);
                sort_rows(&filtered, col, dir, numeric)
            }
            None => filtered,
        };
        let pages = page_count(sorted.len(), props.page_size);
        let cur = (*page).min(pages.saturating_sub(1));
        let visible = paginate(&sorted, cur, props.page_size);

        let on_filter = {
            let query = query.clone();
            let page = page.clone();
            Callback::from(move |e: InputEvent| {
                use wasm_bindgen::JsCast;
                if let Some(t) = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                {
                    query.set(t.value());
                    page.set(0);
                }
            })
        };

        let header = props
            .columns
            .iter()
            .enumerate()
            .map(|(i, col)| {
                let sortable = col.sortable;
                let cur_dir = match *sort {
                    Some((c, d)) if c == i => Some(d),
                    _ => None,
                };
                let aria_sort = match cur_dir {
                    Some(SortDir::Asc) => "ascending",
                    Some(SortDir::Desc) => "descending",
                    None => "none",
                };
                let onclick = {
                    let sort = sort.clone();
                    Callback::from(move |_: MouseEvent| {
                        if !sortable {
                            return;
                        }
                        sort.set(Some(match *sort {
                            Some((c, d)) if c == i => (i, d.toggled()),
                            _ => (i, SortDir::Asc),
                        }));
                    })
                };
                let mut class = Classes::from("pillar-datatable__th");
                if sortable {
                    class.push("is-sortable");
                }
                let indicator = match cur_dir {
                    Some(SortDir::Asc) => " \u{25B2}",
                    Some(SortDir::Desc) => " \u{25BC}",
                    None => "",
                };
                html! {
                    <th class={class} aria-sort={aria_sort} onclick={onclick}>
                        { col.label.clone() }{ indicator }
                    </th>
                }
            })
            .collect::<Html>();

        let body = visible
            .iter()
            .map(|row| {
                html! {
                    <tr class="pillar-datatable__row">
                        { for row.iter().map(|cell| html! {
                            <td class="pillar-datatable__td">{ cell.clone() }</td>
                        }) }
                    </tr>
                }
            })
            .collect::<Html>();

        let mut wrap = Classes::from("pillar-datatable");
        wrap.extend(props.class.clone());

        html! {
            <div class={wrap}>
                if props.filterable {
                    <input
                        class="pillar-datatable__filter"
                        type="text"
                        placeholder="Filter\u{2026}"
                        value={(*query).clone()}
                        oninput={on_filter}
                    />
                }
                <table class="pillar-datatable__table">
                    <thead><tr>{ header }</tr></thead>
                    <tbody>{ body }</tbody>
                </table>
                if props.page_size > 0 && pages > 1 {
                    <div class="pillar-datatable__pager">
                        <button
                            type="button"
                            class="pillar-datatable__page-prev"
                            disabled={cur == 0}
                            onclick={{
                                let page = page.clone();
                                Callback::from(move |_: MouseEvent| page.set(cur.saturating_sub(1)))
                            }}
                        >{ "Prev" }</button>
                        <span class="pillar-datatable__page-status">
                            { format!("Page {} of {}", cur + 1, pages) }
                        </span>
                        <button
                            type="button"
                            class="pillar-datatable__page-next"
                            disabled={cur + 1 >= pages}
                            onclick={{
                                let page = page.clone();
                                Callback::from(move |_: MouseEvent| page.set(cur + 1))
                            }}
                        >{ "Next" }</button>
                    </div>
                }
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Row> {
        vec![
            vec!["s3".into(), "trace".into(), "10".into()],
            vec!["s1".into(), "log".into(), "2".into()],
            vec!["s2".into(), "metric".into(), "30".into()],
        ]
    }

    #[test]
    fn filter_is_case_insensitive_and_matches_any_cell() {
        let rows = sample();
        // Matches the "trace" cell regardless of case.
        let got = filter_rows(&rows, "TRACE");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0][0], "s3");
        // An empty needle keeps every row, order preserved.
        assert_eq!(filter_rows(&rows, "   "), rows);
        // No match => empty.
        assert!(filter_rows(&rows, "zzz").is_empty());
    }

    #[test]
    fn sort_orders_text_ascending_and_descending() {
        let rows = sample();
        let asc = sort_rows(&rows, 0, SortDir::Asc, false);
        assert_eq!(
            asc.iter().map(|r| r[0].as_str()).collect::<Vec<_>>(),
            vec!["s1", "s2", "s3"]
        );
        let desc = sort_rows(&rows, 0, SortDir::Desc, false);
        assert_eq!(
            desc.iter().map(|r| r[0].as_str()).collect::<Vec<_>>(),
            vec!["s3", "s2", "s1"]
        );
    }

    #[test]
    fn numeric_sort_compares_as_numbers_not_strings() {
        let rows = sample();
        // Column 2 holds "10","2","30" — numeric asc must be 2,10,30 (string
        // order would wrongly give 10,2,30 -> "10","2","30").
        let asc = sort_rows(&rows, 2, SortDir::Asc, true);
        assert_eq!(
            asc.iter().map(|r| r[2].as_str()).collect::<Vec<_>>(),
            vec!["2", "10", "30"]
        );
    }

    #[test]
    fn numeric_sort_treats_non_numbers_as_lowest() {
        let rows = vec![
            vec!["5".into()],
            vec!["notanum".into()],
            vec!["1".into()],
        ];
        let asc = sort_rows(&rows, 0, SortDir::Asc, true);
        assert_eq!(
            asc.iter().map(|r| r[0].as_str()).collect::<Vec<_>>(),
            vec!["notanum", "1", "5"]
        );
    }

    #[test]
    fn sort_is_stable_for_equal_keys() {
        let rows = vec![
            vec!["a".into(), "first".into()],
            vec!["a".into(), "second".into()],
            vec!["b".into(), "third".into()],
        ];
        let asc = sort_rows(&rows, 0, SortDir::Asc, false);
        // Both "a" rows keep their original relative order.
        assert_eq!(asc[0][1], "first");
        assert_eq!(asc[1][1], "second");
    }

    #[test]
    fn out_of_range_sort_column_leaves_rows_unchanged() {
        let rows = sample();
        assert_eq!(sort_rows(&rows, 9, SortDir::Asc, false), rows);
    }

    #[test]
    fn page_count_rounds_up_and_is_at_least_one() {
        assert_eq!(page_count(0, 10), 1);
        assert_eq!(page_count(10, 10), 1);
        assert_eq!(page_count(11, 10), 2);
        assert_eq!(page_count(25, 10), 3);
        // page_size 0 => single page.
        assert_eq!(page_count(100, 0), 1);
    }

    #[test]
    fn paginate_returns_the_right_window_and_empties_past_end() {
        let rows: Vec<Row> = (0..25).map(|n| vec![n.to_string()]).collect();
        let p0 = paginate(&rows, 0, 10);
        assert_eq!(p0.len(), 10);
        assert_eq!(p0[0][0], "0");
        let p2 = paginate(&rows, 2, 10);
        assert_eq!(p2.len(), 5);
        assert_eq!(p2[0][0], "20");
        // Past the end.
        assert!(paginate(&rows, 5, 10).is_empty());
        // page_size 0 => all rows.
        assert_eq!(paginate(&rows, 0, 0).len(), 25);
    }

    #[test]
    fn toggled_flips_direction() {
        assert_eq!(SortDir::Asc.toggled(), SortDir::Desc);
        assert_eq!(SortDir::Desc.toggled(), SortDir::Asc);
    }
}
