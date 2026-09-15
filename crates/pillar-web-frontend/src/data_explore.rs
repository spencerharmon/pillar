//! The **Explore** console: read-only browse panels over the SAME live
//! `WebAuthContext::keyed_store` substrate the `pillar kv`/`pillar doc`/
//! `pillar sql` query-tier CLI verbs already read (see
//! `pillar-cli`'s `data_query_tier_remote_surface` acceptance suite for the
//! CLI half). One panel per primitive — K/V browse, Document browse, and a
//! materialized SQL-view panel — each fetching its own
//! `/portal/data/{kv,doc,sql}/*` route (see `web_serve.rs`'s
//! `dispatch_data_*` handlers). The query tier stays the ONE authoritative
//! path for writes; these panels never mutate.
//!
//! Every response-line parser here is a pure, host-tested function (no
//! `web-sys`/DOM); only the `yew` component wiring is wasm-gated.

/// One row rendered in a table: `<id/key>\t<field>=<value>,…` or a bare id
/// (materialized-view row / doc id / kv key with no attached fields).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataRow {
    /// The row's id (a doc id, a materialized-view row id, or a kv key).
    pub id: String,
    /// `field=value` pairs parsed off the row, in the order they appeared.
    pub fields: Vec<(String, String)>,
}

/// Parse a one-name-per-line browse response (`GET .../collections`,
/// `.../keys`, `.../ids`, `.../fields`, `.../views`) into a `Vec<String>`,
/// skipping blank lines.
#[must_use]
pub fn parse_name_list(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parse a materialized SQL-view response body (one
/// `<id>\t<field>=<value>,…` line per row, exactly `render_rows` in
/// `web_serve.rs`) into [`DataRow`]s.
#[must_use]
pub fn parse_view_rows(body: &str) -> Vec<DataRow> {
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| {
            let mut parts = line.split('\t');
            let id = parts.next().unwrap_or("").to_owned();
            let fields = parts
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
            DataRow { id, fields }
        })
        .collect()
}

/// Decode a lowercase-hex K/V value (the `.../kv/get` response body) to a
/// display string: UTF-8 if it round-trips, else the hex verbatim.
#[must_use]
pub fn decode_kv_value(hex: &str) -> String {
    let hex = hex.trim();
    if hex.is_empty() || hex.len() % 2 != 0 {
        return hex.to_owned();
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let raw = hex.as_bytes();
    for chunk in raw.chunks(2) {
        let (Some(hi), Some(lo)) = (
            (chunk[0] as char).to_digit(16),
            (chunk[1] as char).to_digit(16),
        ) else {
            return hex.to_owned();
        };
        bytes.push(((hi << 4) | lo) as u8);
    }
    match std::str::from_utf8(&bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => hex.to_owned(),
    }
}

/// One field parsed off a `key: value\n` ack body (`log info`/`log show`/
/// `log verify`/`object stat`/`object verify` all render this shape) — a
/// pure, host-tested parser shared by every drill-down layer below.
#[must_use]
pub fn parse_field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
}

/// The storage-layout panel's discriminated shape: a document collection's
/// snapshot marker + tail count, or a TSDB collection's retention-block
/// ribbon (horizon, retained block count, pruned count) — parsed off
/// `/portal/data/log/blocks`'s response body (see `log_blocks` in
/// `web_serve.rs`). The two variants render visibly different panels.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum StorageLayout {
    /// No live layout report yet (nothing fetched, or the collection is
    /// unknown).
    #[default]
    Unknown,
    /// Document/keyed: a snapshot (or `none` if never compacted) plus a
    /// bounded op tail.
    Document {
        /// `none`, or the snapshot CID.
        snapshot: String,
        /// How many ops sit in the uncompacted tail.
        tail_ops: usize,
    },
    /// TSDB: an immutable retention-block ribbon back to the horizon, with
    /// older data pruned.
    Tsdb {
        /// The retained-block window size.
        retention_horizon: usize,
        /// How many blocks are still retained.
        retained: usize,
        /// How many ops aged out past the horizon.
        pruned: usize,
    },
}

/// Parse a `/portal/data/log/blocks` response body into a [`StorageLayout`].
#[must_use]
pub fn parse_storage_layout(body: &str) -> StorageLayout {
    if body.contains("kind: tsdb") {
        let horizon = parse_field(body, "retention_horizon")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let pruned = parse_field(body, "pruned")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let retained = body
            .lines()
            .filter(|l| l.starts_with("  ") && !l.trim_start().starts_with("pruned"))
            .count();
        StorageLayout::Tsdb {
            retention_horizon: horizon,
            retained,
            pruned,
        }
    } else if body.contains("kind: document") {
        let snapshot = parse_field(body, "snapshot").unwrap_or("none").to_owned();
        let tail_ops = parse_field(body, "tail")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        StorageLayout::Document { snapshot, tail_ops }
    } else {
        StorageLayout::Unknown
    }
}

#[cfg(feature = "yew")]
pub use yew_impl::{CollectionExplorerPanel, ExploreDataConsole};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        decode_kv_value, parse_field, parse_name_list, parse_storage_layout, parse_view_rows,
        DataRow, StorageLayout,
    };
    use crate::auth::use_auth;
    use crate::components::{Column, DataTable, TabItem, Tabs};
    use crate::portal::{get_url, http, input_value};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// `GET <path>?token=<t>&<extra>` and hand the response body to `apply` on
    /// success; a failed/non-2xx fetch leaves the prior state untouched.
    fn refresh(token: String, path: &'static str, extra: Vec<(String, String)>, apply: Callback<String>) {
        spawn_local(async move {
            let extra_ref: Vec<(&str, &str)> =
                extra.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let url = get_url(path, &token, &extra_ref);
            if let Ok(r) = http("GET", &url, None).await {
                if r.ok() {
                    apply.emit(r.body);
                }
            }
        });
    }

    /// The **K/V browse** panel: pick a collection, list its live keys, click
    /// one to reveal its live decoded value.
    #[function_component(KvBrowsePanel)]
    fn kv_browse_panel() -> Html {
        let auth = use_auth();
        let collection = use_state(String::new);
        let collections = use_state(Vec::<String>::new);
        let keys = use_state(Vec::<String>::new);
        let selected_key = use_state(String::new);
        let value = use_state(String::new);

        {
            let (auth, collections) = (auth.clone(), collections.clone());
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let collections = collections.clone();
                    refresh(
                        token,
                        "/portal/data/kv/collections",
                        vec![],
                        Callback::from(move |body: String| collections.set(parse_name_list(&body))),
                    );
                }
                || ()
            });
        }

        let load_keys = {
            let (auth, keys) = (auth.clone(), keys.clone());
            Callback::from(move |col: String| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let keys = keys.clone();
                refresh(
                    token,
                    "/portal/data/kv/keys",
                    vec![("collection".to_owned(), col)],
                    Callback::from(move |body: String| keys.set(parse_name_list(&body))),
                );
            })
        };

        let on_pick_collection = {
            let (collection, load_keys, selected_key, value) =
                (collection.clone(), load_keys.clone(), selected_key.clone(), value.clone());
            Callback::from(move |e: InputEvent| {
                let v = input_value(&e);
                collection.set(v.clone());
                selected_key.set(String::new());
                value.set(String::new());
                load_keys.emit(v);
            })
        };

        let on_pick_key = {
            let (auth, collection, selected_key, value) =
                (auth.clone(), collection.clone(), selected_key.clone(), value.clone());
            Callback::from(move |key: String| {
                selected_key.set(key.clone());
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let value = value.clone();
                refresh(
                    token,
                    "/portal/data/kv/get",
                    vec![
                        ("collection".to_owned(), (*collection).clone()),
                        ("key".to_owned(), key),
                    ],
                    Callback::from(move |body: String| value.set(decode_kv_value(&body))),
                );
            })
        };

        html! {
            <div class="explore-kv" id="explore-kv-panel">
                <label>{ "Collection" }
                    <select oninput={on_pick_collection} id="kv-collection-select">
                        <option value="">{ "select…" }</option>
                        { for collections.iter().map(|c| html! { <option value={c.clone()}>{ c }</option> }) }
                    </select>
                </label>
                <ul class="explore-kv__keys" id="kv-key-list">
                    { for keys.iter().map(|k| {
                        let onclick = {
                            let on_pick_key = on_pick_key.clone();
                            let k2 = k.clone();
                            Callback::from(move |_: MouseEvent| on_pick_key.emit(k2.clone()))
                        };
                        html! { <li><button type="button" onclick={onclick}>{ k }</button></li> }
                    }) }
                </ul>
                if !selected_key.is_empty() {
                    <p class="explore-kv__value" id="kv-value">
                        { format!("{}: {}", *selected_key, *value) }
                    </p>
                }
            </div>
        }
    }

    /// The **Document browse** panel: pick a collection, list its live
    /// document ids, click one to reveal its live fields.
    #[function_component(DocBrowsePanel)]
    fn doc_browse_panel() -> Html {
        let auth = use_auth();
        let collection = use_state(String::new);
        let ids = use_state(Vec::<String>::new);
        let selected_id = use_state(String::new);
        let fields = use_state(Vec::<(String, String)>::new);

        let load_ids = {
            let (auth, ids) = (auth.clone(), ids.clone());
            Callback::from(move |col: String| {
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let ids = ids.clone();
                refresh(
                    token,
                    "/portal/data/doc/ids",
                    vec![("collection".to_owned(), col)],
                    Callback::from(move |body: String| ids.set(parse_name_list(&body))),
                );
            })
        };

        let on_collection_input = {
            let (collection, load_ids) = (collection.clone(), load_ids.clone());
            Callback::from(move |e: InputEvent| {
                let v = input_value(&e);
                collection.set(v.clone());
                load_ids.emit(v);
            })
        };

        let on_pick_id = {
            let (auth, collection, selected_id, fields) =
                (auth.clone(), collection.clone(), selected_id.clone(), fields.clone());
            Callback::from(move |id: String| {
                selected_id.set(id.clone());
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let (auth2, collection2, id2, fields2) =
                    (auth.clone(), (*collection).clone(), id.clone(), fields.clone());
                // First list the field NAMES, then fetch each one's live value.
                spawn_local(async move {
                    let names_url = crate::portal::get_url(
                        "/portal/data/doc/fields",
                        &token,
                        &[("collection", &collection2), ("id", &id2)],
                    );
                    let Ok(names_resp) = crate::portal::http("GET", &names_url, None).await else {
                        return;
                    };
                    if !names_resp.ok() {
                        return;
                    }
                    let names = parse_name_list(&names_resp.body);
                    let mut out = Vec::with_capacity(names.len());
                    for name in names {
                        let Some(t2) = auth2.token.clone() else {
                            continue;
                        };
                        let value_url = crate::portal::get_url(
                            "/portal/data/doc/get",
                            &t2,
                            &[("collection", &collection2), ("id", &id2), ("field", &name)],
                        );
                        if let Ok(r) = crate::portal::http("GET", &value_url, None).await {
                            if r.ok() {
                                out.push((name, r.body.trim().to_owned()));
                            }
                        }
                    }
                    fields2.set(out);
                });
            })
        };

        html! {
            <div class="explore-doc" id="explore-doc-panel">
                <label>{ "Collection" }
                    <input type="text" oninput={on_collection_input} id="doc-collection-input" />
                </label>
                <ul class="explore-doc__ids" id="doc-id-list">
                    { for ids.iter().map(|i| {
                        let onclick = {
                            let on_pick_id = on_pick_id.clone();
                            let i2 = i.clone();
                            Callback::from(move |_: MouseEvent| on_pick_id.emit(i2.clone()))
                        };
                        html! { <li><button type="button" onclick={onclick}>{ i }</button></li> }
                    }) }
                </ul>
                if !selected_id.is_empty() {
                    <div id="doc-fields">
                        <p>{ format!("Document {}", *selected_id) }</p>
                        <ul>
                            { for fields.iter().map(|(k, v)| html! { <li>{ format!("{k} = {v}") }</li> }) }
                        </ul>
                    </div>
                }
            </div>
        }
    }

    /// The **SQL-view** panel: list declared views, click one to materialize
    /// it live and render the rows in a [`DataTable`].
    #[function_component(SqlViewPanel)]
    fn sql_view_panel() -> Html {
        let auth = use_auth();
        let views = use_state(Vec::<String>::new);
        let selected_view = use_state(String::new);
        let rows = use_state(Vec::<DataRow>::new);

        {
            let (auth, views) = (auth.clone(), views.clone());
            use_effect_with(auth.token.clone(), move |_| {
                if let Some(token) = auth.token.clone() {
                    let views = views.clone();
                    refresh(
                        token,
                        "/portal/data/sql/views",
                        vec![],
                        Callback::from(move |body: String| views.set(parse_name_list(&body))),
                    );
                }
                || ()
            });
        }

        let on_pick_view = {
            let (auth, selected_view, rows) = (auth.clone(), selected_view.clone(), rows.clone());
            Callback::from(move |name: String| {
                selected_view.set(name.clone());
                let Some(token) = auth.token.clone() else {
                    return;
                };
                let rows = rows.clone();
                refresh(
                    token,
                    "/portal/data/sql/view",
                    vec![("name".to_owned(), name)],
                    Callback::from(move |body: String| rows.set(parse_view_rows(&body))),
                );
            })
        };

        // Union every field name seen across the materialized rows into a
        // stable column set (id first) for the DataTable.
        let mut columns = vec!["id".to_owned()];
        for row in rows.iter() {
            for (field, _) in &row.fields {
                if !columns.contains(field) {
                    columns.push(field.clone());
                }
            }
        }
        let table_rows: Vec<Vec<String>> = rows
            .iter()
            .map(|row| {
                columns
                    .iter()
                    .map(|c| {
                        if c == "id" {
                            row.id.clone()
                        } else {
                            row.fields
                                .iter()
                                .find(|(f, _)| f == c)
                                .map(|(_, v)| v.clone())
                                .unwrap_or_default()
                        }
                    })
                    .collect()
            })
            .collect();

        html! {
            <div class="explore-sql" id="explore-sql-panel">
                <ul class="explore-sql__views" id="sql-view-list">
                    { for views.iter().map(|v| {
                        let onclick = {
                            let on_pick_view = on_pick_view.clone();
                            let v2 = v.clone();
                            Callback::from(move |_: MouseEvent| on_pick_view.emit(v2.clone()))
                        };
                        html! { <li><button type="button" onclick={onclick}>{ v }</button></li> }
                    }) }
                </ul>
                if !selected_view.is_empty() {
                    if table_rows.is_empty() {
                        <p class="ds-empty">{ "No live rows in this view." }</p>
                    } else {
                        <DataTable columns={columns.iter().map(|c| Column::text(c.clone())).collect::<Vec<_>>()} rows={table_rows} />
                    }
                }
            </div>
        }
    }

    /// The four-layer **Collection Explorer** drill-down: folded view (a
    /// live K/V collection browse, layer 1) -> op log/DAG (layer 2, over
    /// `/portal/data/log/*`, layered on `pillar-log-inspection-tier`) ->
    /// storage-layout panel (layer 3, the SAME `log/blocks` report rendered
    /// as a distinct shape per storage kind) -> object inspector (layer 4,
    /// over `/portal/data/object/*`, layered on
    /// `pillar-object-inspection-tier`), with a `Collection ▸ op log ▸ op
    /// <cid> ▸ object <cid>` breadcrumb — never a separate portal-only fold
    /// path (`docs/data-inspection.md`'s "Exploring in the portal").
    #[function_component(CollectionExplorerPanel)]
    pub fn collection_explorer_panel() -> Html {
        let auth = use_auth();
        let collection = use_state(String::new);
        let log_info = use_state(String::new);
        let log_ids = use_state(Vec::<String>::new);
        let selected_event = use_state(String::new);
        let log_show = use_state(String::new);
        let log_verify = use_state(String::new);
        let log_dag = use_state(String::new);
        let layout = use_state(StorageLayout::default);
        let object_cid = use_state(String::new);
        let object_stat = use_state(String::new);
        let object_links = use_state(Vec::<String>::new);
        let object_cat = use_state(String::new);
        let object_verify = use_state(String::new);

        // Loading a collection re-fetches op-log info/list/dag and the
        // storage-layout panel, and clears any deeper breadcrumb selection.
        let load_collection = {
            let (auth, log_info, log_ids, log_dag, layout, selected_event, log_show, log_verify, object_cid, object_stat, object_links, object_cat, object_verify) = (
                auth.clone(),
                log_info.clone(),
                log_ids.clone(),
                log_dag.clone(),
                layout.clone(),
                selected_event.clone(),
                log_show.clone(),
                log_verify.clone(),
                object_cid.clone(),
                object_stat.clone(),
                object_links.clone(),
                object_cat.clone(),
                object_verify.clone(),
            );
            Callback::from(move |col: String| {
                selected_event.set(String::new());
                log_show.set(String::new());
                log_verify.set(String::new());
                object_cid.set(String::new());
                object_stat.set(String::new());
                object_links.set(Vec::new());
                object_cat.set(String::new());
                object_verify.set(String::new());
                let Some(token) = auth.token.clone() else {
                    return;
                };
                refresh(
                    token.clone(),
                    "/portal/data/log/info",
                    vec![("collection".to_owned(), col.clone())],
                    Callback::from({
                        let log_info = log_info.clone();
                        move |body: String| log_info.set(body)
                    }),
                );
                refresh(
                    token.clone(),
                    "/portal/data/log/list",
                    vec![("collection".to_owned(), col.clone())],
                    Callback::from({
                        let log_ids = log_ids.clone();
                        move |body: String| log_ids.set(parse_name_list(&body))
                    }),
                );
                refresh(
                    token.clone(),
                    "/portal/data/log/dag",
                    vec![("collection".to_owned(), col.clone())],
                    Callback::from({
                        let log_dag = log_dag.clone();
                        move |body: String| log_dag.set(body)
                    }),
                );
                refresh(
                    token,
                    "/portal/data/log/blocks",
                    vec![("collection".to_owned(), col)],
                    Callback::from({
                        let layout = layout.clone();
                        move |body: String| layout.set(parse_storage_layout(&body))
                    }),
                );
            })
        };

        let on_collection_input = {
            let (collection, load_collection) = (collection.clone(), load_collection.clone());
            Callback::from(move |e: InputEvent| {
                let v = input_value(&e);
                collection.set(v.clone());
                if !v.is_empty() {
                    load_collection.emit(v);
                }
            })
        };

        // Expand an op-log row: decode it and fetch its real verify badge.
        let on_pick_event = {
            let (auth, collection, selected_event, log_show, log_verify) = (
                auth.clone(),
                collection.clone(),
                selected_event.clone(),
                log_show.clone(),
                log_verify.clone(),
            );
            Callback::from(move |event_id: String| {
                selected_event.set(event_id.clone());
                let Some(token) = auth.token.clone() else {
                    return;
                };
                refresh(
                    token.clone(),
                    "/portal/data/log/show",
                    vec![
                        ("collection".to_owned(), (*collection).clone()),
                        ("event_id".to_owned(), event_id.clone()),
                    ],
                    Callback::from({
                        let log_show = log_show.clone();
                        move |body: String| log_show.set(body)
                    }),
                );
                refresh(
                    token,
                    "/portal/data/log/verify",
                    vec![
                        ("collection".to_owned(), (*collection).clone()),
                        ("event_id".to_owned(), event_id),
                    ],
                    Callback::from({
                        let log_verify = log_verify.clone();
                        move |body: String| log_verify.set(body)
                    }),
                );
            })
        };

        // Descend the CID breadcrumb into the object inspector layer.
        let on_pick_cid = {
            let (auth, object_cid, object_stat, object_links, object_cat, object_verify) = (
                auth.clone(),
                object_cid.clone(),
                object_stat.clone(),
                object_links.clone(),
                object_cat.clone(),
                object_verify.clone(),
            );
            Callback::from(move |cid: String| {
                object_cid.set(cid.clone());
                let Some(token) = auth.token.clone() else {
                    return;
                };
                refresh(
                    token.clone(),
                    "/portal/data/object/stat",
                    vec![("cid".to_owned(), cid.clone())],
                    Callback::from({
                        let object_stat = object_stat.clone();
                        move |body: String| object_stat.set(body)
                    }),
                );
                refresh(
                    token.clone(),
                    "/portal/data/object/links",
                    vec![("cid".to_owned(), cid.clone())],
                    Callback::from({
                        let object_links = object_links.clone();
                        move |body: String| object_links.set(parse_name_list(&body))
                    }),
                );
                refresh(
                    token.clone(),
                    "/portal/data/object/cat",
                    vec![("cid".to_owned(), cid.clone())],
                    Callback::from({
                        let object_cat = object_cat.clone();
                        move |body: String| object_cat.set(body)
                    }),
                );
                refresh(
                    token,
                    "/portal/data/object/verify",
                    vec![("cid".to_owned(), cid)],
                    Callback::from({
                        let object_verify = object_verify.clone();
                        move |body: String| object_verify.set(body)
                    }),
                );
            })
        };

        let payload_cid = parse_field(&log_show, "payload-cid").unwrap_or("").to_owned();
        let log_verified = log_verify.contains("hash-matches-id: true")
            && log_verify.contains("signature-valid: true");
        let object_verified = object_verify.contains("hash-matches-cid: true")
            && object_verify.contains("signature-valid: true");

        html! {
            <div class="collection-explorer" id="collection-explorer-panel">
                <nav class="collection-explorer__breadcrumb" id="collection-explorer-breadcrumb">
                    { (*collection).clone() }
                    if !selected_event.is_empty() {
                        { " ▸ op " } { format!("{:.12}", *selected_event) }
                    }
                    if !object_cid.is_empty() {
                        { " ▸ object " } { format!("{:.12}", *object_cid) }
                    }
                </nav>
                <label>{ "Collection" }
                    <input type="text" oninput={on_collection_input} id="ce-collection-input" placeholder="widgets" />
                </label>
                if !collection.is_empty() {
                    <section class="collection-explorer__layout" id="ce-storage-layout">
                        <h4>{ "Storage layout" }</h4>
                        {
                            match &*layout {
                                StorageLayout::Document { snapshot, tail_ops } => html! {
                                    <p class="ce-layout-document">
                                        { format!("snapshot+tail — snapshot: {snapshot}, tail: {tail_ops} ops") }
                                    </p>
                                },
                                StorageLayout::Tsdb { retention_horizon, retained, pruned } => html! {
                                    <p class="ce-layout-tsdb">
                                        { format!(
                                            "retention-block ribbon — horizon: {retention_horizon}, retained: {retained}, pruned: {pruned}"
                                        ) }
                                    </p>
                                },
                                StorageLayout::Unknown => html! { <p>{ "no layout report yet" }</p> },
                            }
                        }
                    </section>
                    <section class="collection-explorer__log" id="ce-op-log">
                        <h4>{ "Op log" }</h4>
                        <pre id="ce-log-info">{ (*log_info).clone() }</pre>
                        <ul id="ce-log-list">
                            { for log_ids.iter().map(|id| {
                                let onclick = {
                                    let on_pick_event = on_pick_event.clone();
                                    let id2 = id.clone();
                                    Callback::from(move |_: MouseEvent| on_pick_event.emit(id2.clone()))
                                };
                                html! { <li><button type="button" onclick={onclick}>{ id }</button></li> }
                            }) }
                        </ul>
                        <details id="ce-log-dag">
                            <summary>{ "DAG" }</summary>
                            <pre>{ (*log_dag).clone() }</pre>
                        </details>
                    </section>
                    if !selected_event.is_empty() {
                        <section class="collection-explorer__op" id="ce-op-detail">
                            <h4>{ "Op detail" }</h4>
                            <pre id="ce-log-show">{ (*log_show).clone() }</pre>
                            <p id="ce-log-verify-badge" class={if log_verified { "verify-ok" } else { "verify-fail" }}>
                                { if log_verified { "✓ verified" } else { "verification unavailable" } }
                            </p>
                            if !payload_cid.is_empty() {
                                <button type="button" id="ce-follow-payload-cid" onclick={
                                    let on_pick_cid = on_pick_cid.clone();
                                    let cid = payload_cid.clone();
                                    Callback::from(move |_: MouseEvent| on_pick_cid.emit(cid.clone()))
                                }>{ format!("View object {payload_cid}") }</button>
                            }
                            <label>{ "Follow CID" }
                                <input type="text" id="ce-cid-input" onchange={
                                    let on_pick_cid = on_pick_cid.clone();
                                    Callback::from(move |e: Event| {
                                        if let Some(input) = e.target_dyn_into::<web_sys::HtmlInputElement>() {
                                            on_pick_cid.emit(input.value());
                                        }
                                    })
                                } />
                            </label>
                        </section>
                    }
                    if !object_cid.is_empty() {
                        <section class="collection-explorer__object" id="ce-object-inspector">
                            <h4>{ "Object inspector" }</h4>
                            <pre id="ce-object-stat">{ (*object_stat).clone() }</pre>
                            <pre id="ce-object-cat">{ (*object_cat).clone() }</pre>
                            <ul id="ce-object-links">
                                { for object_links.iter().map(|l| {
                                    let onclick = {
                                        let on_pick_cid = on_pick_cid.clone();
                                        let l2 = l.clone();
                                        Callback::from(move |_: MouseEvent| on_pick_cid.emit(l2.clone()))
                                    };
                                    html! { <li><button type="button" onclick={onclick}>{ l }</button></li> }
                                }) }
                            </ul>
                            <p id="ce-object-verify-badge" class={if object_verified { "verify-ok" } else { "verify-fail" }}>
                                { if object_verified { "✓ verified" } else { "verification unavailable" } }
                            </p>
                        </section>
                    }
                }
            </div>
        }
    }

    /// The Explore section: four tabs — three data primitives plus the
    /// Collection Explorer drill-down — all reading the SAME live substrate
    /// the query-tier CLI verbs read. Never mutates — the query tier
    /// (`pillar kv`/`doc`/`sql`/`log`/`object` over pillar-UDP) stays the one
    /// authoritative write path.
    #[function_component(ExploreDataConsole)]
    pub fn explore_data_console() -> Html {
        let tabs = vec![
            TabItem {
                label: "K/V".into(),
                panel: html! { <KvBrowsePanel /> },
            },
            TabItem {
                label: "Documents".into(),
                panel: html! { <DocBrowsePanel /> },
            },
            TabItem {
                label: "SQL Views".into(),
                panel: html! { <SqlViewPanel /> },
            },
            TabItem {
                label: "Collection Explorer".into(),
                panel: html! { <CollectionExplorerPanel /> },
            },
        ];
        html! {
            <div id="explore-data-console">
                <Tabs tabs={tabs} />
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_list_skips_blank_lines() {
        let body = "config\n\nusers\n  \n";
        assert_eq!(parse_name_list(body), vec!["config", "users"]);
    }

    #[test]
    fn parse_name_list_is_empty_for_empty_body() {
        assert_eq!(parse_name_list(""), Vec::<String>::new());
    }

    #[test]
    fn parse_view_rows_splits_id_and_fields() {
        let body = "u1\tname=alice\tstatus=on\nu3\tname=carol\tstatus=on\n";
        let rows = parse_view_rows(body);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].id, "u1");
        assert_eq!(
            rows[0].fields,
            vec![
                ("name".to_owned(), "alice".to_owned()),
                ("status".to_owned(), "on".to_owned())
            ]
        );
        assert_eq!(rows[1].id, "u3");
    }

    #[test]
    fn parse_view_rows_handles_a_bare_id_with_no_fields() {
        let rows = parse_view_rows("only-an-id\n");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "only-an-id");
        assert!(rows[0].fields.is_empty());
    }

    #[test]
    fn decode_kv_value_prefers_utf8() {
        // "hello" hex-encoded.
        assert_eq!(decode_kv_value("68656c6c6f"), "hello");
    }

    #[test]
    fn decode_kv_value_falls_back_to_hex_for_non_utf8_or_malformed_input() {
        // Odd-length hex is not valid — falls back to the raw string.
        assert_eq!(decode_kv_value("abc"), "abc");
        // A non-hex digit falls back too.
        assert_eq!(decode_kv_value("zz"), "zz");
    }

    #[test]
    fn parse_field_reads_a_key_value_line() {
        let body = "event: abc\nauthor: did:pillar:x\nhlc: 1.2.3\n";
        assert_eq!(parse_field(body, "author"), Some("did:pillar:x"));
        assert_eq!(parse_field(body, "missing"), None);
    }

    #[test]
    fn parse_storage_layout_reads_a_document_report() {
        let body = "collection: widgets\nkind: document\nsnapshot: none\ntail: 3 ops (uncompacted)\n  abcd\n  ef01\n  1234\n";
        let layout = parse_storage_layout(body);
        assert_eq!(
            layout,
            StorageLayout::Document {
                snapshot: "none".to_owned(),
                tail_ops: 3,
            }
        );
    }

    #[test]
    fn parse_storage_layout_reads_a_tsdb_report() {
        let body = "collection: __objects\nkind: tsdb\nretention_horizon: 4\nblocks:\n  aa\n  bb\n  cc\n  dd\npruned: 2\n  pruned ee\n  pruned ff\n";
        let layout = parse_storage_layout(body);
        assert_eq!(
            layout,
            StorageLayout::Tsdb {
                retention_horizon: 4,
                retained: 4,
                pruned: 2,
            }
        );
    }

    #[test]
    fn parse_storage_layout_is_unknown_for_an_unrecognized_body() {
        assert_eq!(parse_storage_layout("garbage"), StorageLayout::Unknown);
    }
}
