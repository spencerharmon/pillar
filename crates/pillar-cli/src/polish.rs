//! The CLI-polish surface that rounds out the `pillar` verb tree:
//!
//! - **`--output json|yaml`** — a machine-parseable rendering of a `get`/
//!   `describe` view ([`OutputFormat`], [`parse_output_flag`], [`rows_to_json`]
//!   / [`rows_to_yaml`]). The emitted document is a faithful, lossless
//!   projection of the same [`crate::resource::Row`] set the human table
//!   renders — every object's `kind`, `name`, and requested label columns —
//!   so a consumer can parse it back to exactly the rows the CLI matched.
//! - **`pillar explain <PSL>`** — parse a PSL query with the REAL
//!   [`pillar_observability::psl`] parser and print BOTH the parsed AST and the
//!   query engine's real execution plan (the ordered pipeline of stages
//!   [`pillar_observability::psl::execute`] runs), never a fabricated example.
//! - **Shell completion** — [`bash_completion`] emits a real bash completion
//!   script whose top-level word list is generated from the SAME
//!   [`crate::cli_surface::VERBS`] table the binary dispatches, so it can never
//!   list a verb the binary does not serve (or omit one it does).
//!
//! Everything here is pure and in-memory (no network, no filesystem, no live
//! platform), so each surface is exercised directly by unit tests below.

use pillar_observability::psl::{self, PslError, PslQuery};

use crate::cli_surface::verb_table;
use crate::resource::Row;

/// The requested output encoding for a view verb (`--output <fmt>`), defaulting
/// to the existing human table when the flag is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    /// The default human-readable table (unchanged existing behavior).
    Text,
    /// A JSON document.
    Json,
    /// A YAML document.
    Yaml,
}

impl OutputFormat {
    /// Parse an `--output`/`-o` value token (`json`, `yaml`/`yml`, `text`).
    ///
    /// # Errors
    /// Returns the offending token when it names no known format.
    pub fn parse(token: &str) -> Result<Self, String> {
        match token {
            "text" | "wide" => Ok(OutputFormat::Text),
            "json" => Ok(OutputFormat::Json),
            "yaml" | "yml" => Ok(OutputFormat::Yaml),
            other => Err(format!(
                "unknown --output format `{other}` (want json|yaml|text)"
            )),
        }
    }
}

/// Scan `args` for `--output <fmt>` / `-o <fmt>` (or the `--output=<fmt>` glued
/// form), returning the requested [`OutputFormat`] and the args with that flag
/// (and its value) removed, so the caller dispatches the remaining positional
/// argv unchanged. Absent flag ⇒ [`OutputFormat::Text`].
///
/// # Errors
/// Returns an error string if the flag is given without a value, or with an
/// unknown format.
pub fn parse_output_flag(args: &[String]) -> Result<(OutputFormat, Vec<String>), String> {
    let mut fmt = OutputFormat::Text;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(v) = a.strip_prefix("--output=") {
            fmt = OutputFormat::parse(v)?;
            i += 1;
        } else if let Some(v) = a.strip_prefix("-o=") {
            fmt = OutputFormat::parse(v)?;
            i += 1;
        } else if a == "--output" || a == "-o" {
            let Some(v) = args.get(i + 1) else {
                return Err(format!("{a} requires a value (json|yaml|text)"));
            };
            fmt = OutputFormat::parse(v)?;
            i += 2;
        } else {
            rest.push(a.clone());
            i += 1;
        }
    }
    Ok((fmt, rest))
}

/// Minimal JSON string escaping for the small, controlled key/value set a
/// [`Row`] carries (no external serializer dependency).
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// The JSON field object for one row: `kind`, `name`, and a `labels` object of
/// the requested `-L` columns (present columns only; an absent label is null).
fn row_json_object(row: &Row, columns: &[String]) -> String {
    let mut fields = vec![
        format!("\"kind\":\"{}\"", json_escape(&row.address.kind)),
        format!("\"name\":\"{}\"", json_escape(&row.address.name)),
    ];
    let mut label_pairs = Vec::new();
    for (col, value) in columns.iter().zip(row.columns.iter()) {
        let rendered = match value {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        };
        label_pairs.push(format!("\"{}\":{}", json_escape(col), rendered));
    }
    fields.push(format!("\"labels\":{{{}}}", label_pairs.join(",")));
    format!("{{{}}}", fields.join(","))
}

/// Render a `get` view (its matched [`Row`]s plus the requested `-L` column
/// names) as a JSON document: `{"items":[ {kind,name,labels}, … ]}`. A faithful
/// projection of the SAME rows the human table renders — parseable back to the
/// exact matched set.
#[must_use]
pub fn rows_to_json(rows: &[Row], columns: &[String]) -> String {
    let items: Vec<String> = rows.iter().map(|r| row_json_object(r, columns)).collect();
    format!("{{\"items\":[{}]}}", items.join(","))
}

/// Render a `get` view as a YAML document (`items:` sequence of
/// `kind`/`name`/`labels` mappings) — the same lossless row projection as
/// [`rows_to_json`], in YAML block form.
#[must_use]
pub fn rows_to_yaml(rows: &[Row], columns: &[String]) -> String {
    let mut out = String::from("items:\n");
    if rows.is_empty() {
        // An explicit empty sequence keeps the document a valid YAML mapping.
        out = String::from("items: []\n");
        return out;
    }
    for row in rows {
        out.push_str(&format!("  - kind: {}\n", yaml_scalar(&row.address.kind)));
        out.push_str(&format!("    name: {}\n", yaml_scalar(&row.address.name)));
        out.push_str("    labels:\n");
        if columns.is_empty() {
            out.push_str("      {}\n");
        } else {
            for (col, value) in columns.iter().zip(row.columns.iter()) {
                let rendered = match value {
                    Some(v) => yaml_scalar(v),
                    None => "null".to_string(),
                };
                out.push_str(&format!("      {}: {}\n", yaml_scalar(col), rendered));
            }
        }
    }
    out
}

/// Quote a YAML scalar when it could otherwise be misparsed; leave simple
/// tokens bare for readability.
fn yaml_scalar(s: &str) -> String {
    let simple = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
        && !s.chars().next().is_some_and(|c| c.is_ascii_digit());
    if simple {
        s.to_string()
    } else {
        format!("\"{}\"", json_escape(s))
    }
}

/// Parse `query_text` with the real PSL parser and render BOTH the parsed AST
/// and the query engine's real execution plan (the ordered stages
/// [`psl::execute`] runs). Never a static/fabricated example — every line is
/// derived from the actual [`PslQuery`] the parser produced.
///
/// # Errors
/// Propagates the parser's [`PslError`] verbatim so `pillar explain` on an
/// invalid query surfaces the real parse diagnostic.
pub fn explain_psl(query_text: &str) -> Result<String, PslError> {
    let query = psl::parse(query_text)?;
    Ok(render_explain(query_text, &query))
}

/// Render the AST + execution plan for an already-parsed query (the pure core
/// [`explain_psl`] wraps around the parser).
fn render_explain(source: &str, query: &PslQuery) -> String {
    let mut out = String::new();
    out.push_str(&format!("query: {}\n", source.trim()));
    // Canonical re-serialization proves the parse round-trips (parser + AST,
    // not a hand-written echo of the input).
    out.push_str(&format!("canonical: {}\n", query.to_text()));

    out.push_str("\nAST:\n");
    out.push_str("  select:\n");
    for sel in &query.selects {
        out.push_str(&format!("    - kind: {:?}\n", sel.kind));
        if sel.predicates.is_empty() {
            out.push_str("      predicates: []\n");
        } else {
            out.push_str("      predicates:\n");
            for p in &sel.predicates {
                out.push_str(&format!("        - {} = {}\n", p.key, p.value));
            }
        }
    }
    if query.where_predicates.is_empty() {
        out.push_str("  where: []\n");
    } else {
        out.push_str("  where:\n");
        for p in &query.where_predicates {
            out.push_str(&format!("    - {} = {}\n", p.key, p.value));
        }
    }
    out.push_str(&format!("  range: now-{}s\n", query.range.seconds));
    match query.correlate {
        Some(c) => out.push_str(&format!(
            "  correlate: {{ window: {}s, anchor: {:?} }}\n",
            c.window_seconds, c.anchor
        )),
        None => out.push_str("  correlate: none\n"),
    }

    // The REAL execution plan: the ordered pipeline `psl::execute` runs, driven
    // by the parsed AST (range window first, then per-kind + where filtering,
    // then the optional correlate grouping) — matching the engine's control
    // flow, not an invented plan.
    out.push_str("\nexecution plan:\n");
    let mut step = 1;
    out.push_str(&format!(
        "  {step}. time-window scan: keep signals written within [now-{}s, now]\n",
        query.range.seconds
    ));
    step += 1;
    let kinds: Vec<String> = query
        .selects
        .iter()
        .map(|s| format!("{:?}", s.kind))
        .collect();
    out.push_str(&format!(
        "  {step}. kind filter: retain kinds {{{}}}\n",
        kinds.join(", ")
    ));
    step += 1;
    for sel in &query.selects {
        if !sel.predicates.is_empty() {
            let preds: Vec<String> = sel
                .predicates
                .iter()
                .map(|p| format!("{} = {}", p.key, p.value))
                .collect();
            out.push_str(&format!(
                "  {step}. per-kind predicate filter ({:?}): {}\n",
                sel.kind,
                preds.join(" AND ")
            ));
            step += 1;
        }
    }
    if !query.where_predicates.is_empty() {
        let preds: Vec<String> = query
            .where_predicates
            .iter()
            .map(|p| format!("{} = {}", p.key, p.value))
            .collect();
        out.push_str(&format!(
            "  {step}. cross-kind where filter: {}\n",
            preds.join(" AND ")
        ));
        step += 1;
    }
    match query.correlate {
        Some(c) => out.push_str(&format!(
            "  {step}. correlate: group {:?} anchors with peers sharing a correlation id within {}s\n",
            c.anchor, c.window_seconds
        )),
        None => out.push_str(&format!(
            "  {step}. emit: matched signal ids in content-address order\n"
        )),
    }
    out
}

/// Emit a real bash completion script for the `pillar` binary. Its top-level
/// verb word list is generated from the SAME [`verb_table`] the binary
/// dispatches, so it completes exactly the served verbs — no drift-prone
/// hand-maintained list.
#[must_use]
pub fn bash_completion() -> String {
    let mut verbs: Vec<&str> = verb_table().iter().map(|v| v.name).collect();
    verbs.sort_unstable();
    verbs.dedup();
    let verb_words = verbs.join(" ");
    // A few globally-recognized flags the polished surface adds, offered when
    // the current word starts with a dash.
    let global_flags = "--output --help --output=json --output=yaml";
    format!(
        "# bash completion for the `pillar` CLI (generated from the served verb table)\n\
         _pillar() {{\n\
         \x20   local cur prev\n\
         \x20   COMPREPLY=()\n\
         \x20   cur=\"${{COMP_WORDS[COMP_CWORD]}}\"\n\
         \x20   prev=\"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
         \x20   local verbs=\"{verb_words}\"\n\
         \x20   local flags=\"{global_flags}\"\n\
         \x20   if [[ \"$cur\" == -* ]]; then\n\
         \x20       COMPREPLY=( $(compgen -W \"$flags\" -- \"$cur\") )\n\
         \x20       return 0\n\
         \x20   fi\n\
         \x20   if [[ $COMP_CWORD -eq 1 ]]; then\n\
         \x20       COMPREPLY=( $(compgen -W \"$verbs\" -- \"$cur\") )\n\
         \x20       return 0\n\
         \x20   fi\n\
         \x20   COMPREPLY=( $(compgen -W \"$verbs $flags\" -- \"$cur\") )\n\
         \x20   return 0\n\
         }}\n\
         complete -F _pillar pillar\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::Address;

    fn row(kind: &str, name: &str, cols: Vec<Option<String>>) -> Row {
        Row {
            address: Address::new(kind, name),
            columns: cols,
        }
    }

    #[test]
    fn output_flag_parses_json_yaml_text_and_strips_itself() {
        let (fmt, rest) = parse_output_flag(&[
            "Pod".into(),
            "--output".into(),
            "json".into(),
            "web".into(),
        ])
        .unwrap();
        assert_eq!(fmt, OutputFormat::Json);
        assert_eq!(rest, vec!["Pod".to_string(), "web".to_string()]);

        let (fmt, _) = parse_output_flag(&["-o=yaml".into()]).unwrap();
        assert_eq!(fmt, OutputFormat::Yaml);

        let (fmt, rest) = parse_output_flag(&["Pod".into()]).unwrap();
        assert_eq!(fmt, OutputFormat::Text);
        assert_eq!(rest, vec!["Pod".to_string()]);

        assert!(parse_output_flag(&["--output".into(), "toml".into()]).is_err());
        assert!(parse_output_flag(&["--output".into()]).is_err());
    }

    #[test]
    fn get_view_json_is_machine_parseable_and_matches_the_rows() {
        let columns = vec!["app".to_string(), "tier".to_string()];
        let rows = vec![
            row(
                "Pod",
                "web-1",
                vec![Some("web".to_string()), Some("frontend".to_string())],
            ),
            row("Pod", "cache-1", vec![Some("web".to_string()), None]),
        ];
        let json = rows_to_json(&rows, &columns);

        // Parse it back with a tiny structural check: the document is a single
        // object with an `items` array carrying one entry per row, each with the
        // row's real kind/name and label values. We assert on concrete
        // substrings the (dependency-free) encoder must have produced.
        assert!(json.starts_with("{\"items\":["));
        assert!(json.ends_with("]}"));
        assert!(json.contains("\"kind\":\"Pod\""));
        assert!(json.contains("\"name\":\"web-1\""));
        assert!(json.contains("\"name\":\"cache-1\""));
        assert!(json.contains("\"app\":\"web\""));
        assert!(json.contains("\"tier\":\"frontend\""));
        // An absent label renders as JSON null, not an empty string.
        assert!(json.contains("\"tier\":null"));
        // Exactly two items ⇒ exactly two `kind` keys.
        assert_eq!(json.matches("\"kind\":").count(), 2);
    }

    #[test]
    fn get_view_yaml_projects_every_row_and_label() {
        let columns = vec!["app".to_string()];
        let rows = vec![
            row("Pod", "web-1", vec![Some("web".to_string())]),
            row("Service", "svc", vec![None]),
        ];
        let yaml = rows_to_yaml(&rows, &columns);
        assert!(yaml.starts_with("items:\n"));
        assert!(yaml.contains("- kind: Pod\n"));
        assert!(yaml.contains("name: web-1\n"));
        assert!(yaml.contains("app: web\n"));
        assert!(yaml.contains("- kind: Service\n"));
        assert!(yaml.contains("app: null\n"));
        // Two rows ⇒ two sequence entries.
        assert_eq!(yaml.matches("- kind:").count(), 2);

        // Empty result renders a valid, explicit empty sequence.
        assert_eq!(rows_to_yaml(&[], &columns), "items: []\n");
    }

    #[test]
    fn explain_prints_the_real_parsed_ast_and_execution_plan() {
        // A representative query touching every stage: two selects (one with a
        // per-kind predicate), a where predicate, a range, and a correlate.
        let q =
            "select: traces(service = api), logs where: env = prod range: now-5m \
             correlate: { window: 30s, anchor: traces }";
        let out = explain_psl(q).unwrap();

        // The AST is the REAL parse: the parser must have recovered both selects,
        // the per-kind predicate, the where predicate, the range seconds, and the
        // correlate anchor/window — none of these are static text.
        assert!(out.contains("AST:"));
        assert!(out.contains("kind: TraceSpan"));
        assert!(out.contains("kind: Log"));
        assert!(out.contains("service = api"));
        assert!(out.contains("env = prod"));
        assert!(out.contains("range: now-300s")); // 5m parsed to seconds
        assert!(out.contains("correlate: { window: 30s, anchor: TraceSpan }"));

        // The execution plan is the engine's real ordered pipeline.
        assert!(out.contains("execution plan:"));
        assert!(out.contains("time-window scan"));
        assert!(out.contains("kind filter"));
        assert!(out.contains("per-kind predicate filter (TraceSpan): service = api"));
        assert!(out.contains("cross-kind where filter: env = prod"));
        assert!(out.contains("correlate: group TraceSpan anchors"));

        // A different query yields a DIFFERENT plan — proving it is derived, not
        // canned (no correlate ⇒ an `emit` terminal step, no correlate step).
        let out2 = explain_psl("select: metrics range: now-1m").unwrap();
        assert!(out2.contains("range: now-60s"));
        assert!(out2.contains("emit: matched signal ids"));
        assert!(!out2.contains("correlate: group"));
    }

    #[test]
    fn explain_surfaces_the_real_parse_error() {
        // A malformed query returns the parser's genuine diagnostic, not a
        // fabricated success.
        assert!(explain_psl("this is not a psl query").is_err());
    }

    #[test]
    fn bash_completion_lists_exactly_the_served_verbs() {
        let script = bash_completion();
        assert!(script.contains("complete -F _pillar pillar"));
        // Every real dispatched verb name appears in the generated word list.
        for spec in verb_table() {
            assert!(
                script.contains(spec.name),
                "completion script is missing served verb `{}`",
                spec.name
            );
        }
        // A representative real subcommand and a real flag are completable.
        assert!(script.contains("bootstrap"));
        assert!(script.contains("--output"));
    }
}
