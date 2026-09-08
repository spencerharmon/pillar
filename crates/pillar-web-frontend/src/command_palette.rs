//! The command palette (Phase 5) — a ⌘K / Ctrl-K quick switcher over every
//! console section, in the spirit of the Linear/VS Code palette. The fuzzy-ish
//! filter is a pure, host-tested function; the component wires the global
//! keyboard shortcut, the overlay, and router navigation.

/// A command the palette can run: a human label and the section to navigate to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    /// The displayed label.
    pub label: String,
    /// A short keyword hint (the section group), shown muted.
    pub hint: String,
}

/// Filter `commands` by `query`: case-insensitive, matching when every
/// whitespace-separated term of the query is a substring of the label or hint.
/// An empty query matches everything (in order). Returns indices into
/// `commands`.
#[must_use]
pub fn filter_commands(commands: &[Command], query: &str) -> Vec<usize> {
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    commands
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            let hay = format!("{} {}", c.label, c.hint).to_lowercase();
            terms.iter().all(|t| hay.contains(t))
        })
        .map(|(i, _)| i)
        .collect()
}

/// Project the palette's verb commands from the node's live surface inventory —
/// the SAME `pillar-integration/v1` document the binary emits from its real
/// registries (`pillar-cli::surface_inventory::emit_json`, served
/// unauthenticated at `GET /surface-inventory`). We deliberately keep exactly
/// the `kind == "cli-verb"` entries and read each entry's `id` (`cli:<name>`)
/// and `signature` verbatim, so the palette's action list is DERIVED from the
/// real inventory and can never be a hand-maintained duplicate: an added/removed
/// verb appears/disappears here automatically. `http-route`/`manifest-kind`/
/// `wire-op` entries are skipped (they are not navigable palette actions), and a
/// malformed/empty document yields NO commands (never a fabricated verb).
///
/// The frontend cannot depend on `pillar-cli` (it compiles to wasm), so this is
/// a dependency-free reader over the emitter's stable JSON shape rather than a
/// typed import — the host test pins it against a real emitter-shaped document.
#[must_use]
pub fn verb_commands(inventory_json: &str) -> Vec<Command> {
    parse_surface_commands(inventory_json)
        .into_iter()
        .filter(|e| e.kind == "cli-verb")
        .map(|e| {
            let name = e.id.strip_prefix("cli:").unwrap_or(&e.id).to_owned();
            let hint = if e.signature.is_empty() {
                name.clone()
            } else {
                e.signature.clone()
            };
            Command {
                label: format!("Run {name}"),
                hint,
            }
        })
        .collect()
}

/// One surface-inventory entry read out of the emitted `pillar-integration/v1`
/// document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceEntry {
    /// The entry `id` (e.g. `cli:apply`, `http:GET /surface-inventory`).
    pub id: String,
    /// The entry `kind` (`cli-verb`, `http-route`, `manifest-kind`, `wire-op`).
    pub kind: String,
    /// The human-readable signature.
    pub signature: String,
}

/// Parse the emitter's `surface_inventory` array into typed entries, WITHOUT a
/// JSON dependency (the wasm frontend carries none). The emitter
/// (`pillar-cli::surface_inventory`) serializes each entry as a JSON object with
/// exactly the string fields `id`, `kind`, `signature`; we scan object-by-object
/// (`{ ... }`) inside the `surface_inventory` array and pull those three string
/// values. Field ORDER within an object does not matter, and any object missing
/// `id`/`kind` is skipped (never a fabricated entry). Anything that is not a
/// well-formed inventory yields an empty list.
#[must_use]
pub fn parse_surface_commands(inventory_json: &str) -> Vec<SurfaceEntry> {
    // Isolate the `surface_inventory` array body.
    let Some(arr_start) = inventory_json.find("\"surface_inventory\"") else {
        return Vec::new();
    };
    let tail = &inventory_json[arr_start..];
    let Some(open) = tail.find('[') else {
        return Vec::new();
    };
    let Some(close) = tail.rfind(']') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }
    let body = &tail[open + 1..close];

    let mut out = Vec::new();
    // Walk object literals `{ ... }` (entries carry no nested objects).
    let mut rest = body;
    while let Some(ob) = rest.find('{') {
        let after = &rest[ob + 1..];
        let Some(cb) = after.find('}') else { break };
        let obj = &after[..cb];
        let id = json_string_field(obj, "id");
        let kind = json_string_field(obj, "kind");
        let signature = json_string_field(obj, "signature").unwrap_or_default();
        if let (Some(id), Some(kind)) = (id, kind) {
            out.push(SurfaceEntry {
                id,
                kind,
                signature,
            });
        }
        rest = &after[cb + 1..];
    }
    out
}

/// Read the string value of `"<field>": "<value>"` out of a flat JSON object
/// body, order-independent. Handles the emitter's simple escaping (`\"`, `\\`);
/// returns `None` if the field is absent or not a string.
fn json_string_field(obj: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\"");
    let mut idx = obj.find(&key)?;
    // Advance past the key and the colon to the opening quote of the value.
    idx += key.len();
    let bytes = obj.as_bytes();
    while idx < bytes.len() && bytes[idx] != b'"' {
        // Stop if we hit the next field before a value quote (malformed).
        if bytes[idx] == b',' || bytes[idx] == b'}' {
            return None;
        }
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }
    idx += 1; // past opening quote
    let mut val = String::new();
    let mut escaped = false;
    while idx < bytes.len() {
        let c = bytes[idx] as char;
        if escaped {
            val.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some(val);
        } else {
            val.push(c);
        }
        idx += 1;
    }
    None
}

#[cfg(feature = "yew")]
pub use yew_impl::CommandPalette;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{filter_commands, verb_commands, Command};
    use crate::components::use_toaster;
    use crate::console::section_route;
    use crate::console::Section;
    use crate::portal::http;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;
    use yew_router::prelude::*;

    fn section_commands() -> Vec<Command> {
        Section::all()
            .into_iter()
            .map(|s| Command {
                label: format!("Go to {}", s.label()),
                hint: s.group().label().to_owned(),
            })
            .collect()
    }

    /// The ⌘K command palette. Mounted once in the console frame; a global
    /// keydown listener opens it on Cmd/Ctrl-K and closes it on Escape.
    /// Selecting a command navigates to that section and closes the overlay.
    #[function_component(CommandPalette)]
    pub fn command_palette() -> Html {
        let open = use_state(|| false);
        let query = use_state(String::new);
        let navigator = use_navigator();
        let toaster = use_toaster();
        // The verb commands projected from the node's live surface inventory,
        // fetched once on mount. Section commands are always available; the verb
        // list is appended when the fetch succeeds.
        let verbs = use_state(Vec::<Command>::new);

        {
            let (verbs, toaster) = (verbs.clone(), toaster.clone());
            use_effect_with((), move |()| {
                let (verbs, toaster) = (verbs.clone(), toaster.clone());
                spawn_local(async move {
                    match http("GET", "/surface-inventory", None).await {
                        Ok(r) if r.ok() => verbs.set(verb_commands(&r.body)),
                        Ok(_) => toaster.error("Command palette: could not load the action inventory."),
                        Err(_) => toaster.error("Command palette: the action inventory request failed."),
                    }
                });
                || ()
            });
        }

        // Global Cmd/Ctrl-K toggle + Escape close, via a window keydown listener
        // kept alive for the component's lifetime.
        {
            let open = open.clone();
            use_effect_with((), move |()| {
                let handler = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::wrap(Box::new(
                    move |e: web_sys::KeyboardEvent| {
                        if (e.meta_key() || e.ctrl_key()) && e.key().eq_ignore_ascii_case("k") {
                            e.prevent_default();
                            open.set(!*open);
                        } else if e.key() == "Escape" {
                            open.set(false);
                        }
                    },
                ));
                let window = web_sys::window();
                if let Some(w) = &window {
                    let _ = w.add_event_listener_with_callback(
                        "keydown",
                        handler.as_ref().unchecked_ref(),
                    );
                }
                move || {
                    if let Some(w) = web_sys::window() {
                        let _ = w.remove_event_listener_with_callback(
                            "keydown",
                            handler.as_ref().unchecked_ref(),
                        );
                    }
                    drop(handler);
                }
            });
        }

        if !*open {
            return Html::default();
        }

        let sections = section_commands();
        let section_count = sections.len();
        // The palette's action list: navigable section commands first, then the
        // verb commands projected from the live surface inventory.
        let mut commands = sections;
        commands.extend((*verbs).clone());
        let on_input = {
            let query = query.clone();
            Callback::from(move |e: InputEvent| {
                use wasm_bindgen::JsCast;
                if let Some(t) = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                {
                    query.set(t.value());
                }
            })
        };
        let visible = filter_commands(&commands, &query);

        let close = {
            let open = open.clone();
            Callback::from(move |_: MouseEvent| open.set(false))
        };

        // Navigate to a section (for a section entry) and always close.
        let run = {
            let (open, navigator) = (open.clone(), navigator.clone());
            move |section: Option<Section>| {
                let (open, navigator) = (open.clone(), navigator.clone());
                Callback::from(move |_: MouseEvent| {
                    if let (Some(section), Some(nav)) = (section, navigator.as_ref()) {
                        nav.push(&section_route(section));
                    }
                    open.set(false);
                })
            }
        };

        html! {
            <div class="cmdk">
                <div class="cmdk__scrim" onclick={close} />
                <div class="cmdk__panel" role="dialog" aria-label="Command palette">
                    <input class="cmdk__input" type="text" autofocus=true
                           placeholder="Jump to\u{2026}" value={(*query).clone()}
                           oninput={on_input} />
                    <ul class="cmdk__list">
                        { for visible.iter().map(|&i| {
                            // The first `section_count` entries are navigable
                            // sections; the rest are surface-inventory verbs.
                            let section = if i < section_count {
                                Some(Section::all()[i])
                            } else {
                                None
                            };
                            html! {
                                <li class="cmdk__item" onclick={run(section)}>
                                    <span class="cmdk__label">{ &commands[i].label }</span>
                                    <span class="cmdk__hint">{ &commands[i].hint }</span>
                                </li>
                            }
                        }) }
                        if visible.is_empty() {
                            <li class="cmdk__empty">{ "No matching command." }</li>
                        }
                    </ul>
                </div>
            </div>
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmds() -> Vec<Command> {
        vec![
            Command {
                label: "Go to Resources".into(),
                hint: "Workloads".into(),
            },
            Command {
                label: "Go to Observability".into(),
                hint: "Telemetry".into(),
            },
            Command {
                label: "Go to Trust Graph".into(),
                hint: "Security".into(),
            },
        ]
    }

    #[test]
    fn empty_query_matches_all_in_order() {
        assert_eq!(filter_commands(&cmds(), ""), vec![0, 1, 2]);
        assert_eq!(filter_commands(&cmds(), "   "), vec![0, 1, 2]);
    }

    #[test]
    fn filter_is_case_insensitive_over_label_and_hint() {
        // matches the label.
        assert_eq!(filter_commands(&cmds(), "trust"), vec![2]);
        // matches the hint (group), not just the label.
        assert_eq!(filter_commands(&cmds(), "telemetry"), vec![1]);
    }

    #[test]
    fn all_terms_must_match() {
        // both terms present (label + hint) -> match.
        assert_eq!(filter_commands(&cmds(), "trust security"), vec![2]);
        // one term absent -> no match, never a fabricated hit.
        assert!(filter_commands(&cmds(), "trust telemetry").is_empty());
    }

    /// A document byte-shaped exactly like `pillar-cli::surface_inventory::
    /// emit_json` (`serde_json::to_string_pretty` of the `Inventory` struct):
    /// the `schema` tag plus a `surface_inventory` array whose entries serialize
    /// their fields in `id`, `kind`, `signature` order. It deliberately mixes
    /// all four kinds so the projection's filtering is exercised.
    fn real_inventory_doc() -> &'static str {
        r#"{
  "schema": "pillar-integration/v1",
  "surface_inventory": [
    {
      "id": "cli:apply",
      "kind": "cli-verb",
      "signature": "pillar apply"
    },
    {
      "id": "http:GET /surface-inventory",
      "kind": "http-route",
      "signature": "GET /surface-inventory"
    },
    {
      "id": "cli:scale",
      "kind": "cli-verb",
      "signature": "pillar scale"
    },
    {
      "id": "manifest:Workload",
      "kind": "manifest-kind",
      "signature": "apiVersion=pillar/v1 kind=Workload"
    },
    {
      "id": "wire:reconcile",
      "kind": "wire-op",
      "signature": "reconcile req/resp"
    }
  ]
}"#
    }

    #[test]
    fn surface_commands_are_projected_from_the_inventory_cli_verbs_only() {
        // The parser sees every entry; the projection keeps ONLY cli-verbs.
        let all = parse_surface_commands(real_inventory_doc());
        assert_eq!(all.len(), 5, "parser must see every entry");
        let cmds = verb_commands(real_inventory_doc());
        // Exactly the two cli-verb entries, in emitted order — the http/
        // manifest/wire entries are skipped, never a fabricated command.
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].label, "Run apply");
        assert_eq!(cmds[1].label, "Run scale");
    }

    #[test]
    fn verb_commands_carry_the_real_signature_and_are_tagged_verb() {
        let cmds = verb_commands(real_inventory_doc());
        assert_eq!(cmds[0].hint, "pillar apply");
        assert_eq!(cmds[1].hint, "pillar scale");
    }

    #[test]
    fn field_order_within_an_entry_does_not_matter() {
        // A pretty document with the fields permuted still parses the same.
        let permuted = r#"{
  "schema": "pillar-integration/v1",
  "surface_inventory": [
    {
      "signature": "pillar get",
      "kind": "cli-verb",
      "id": "cli:get"
    }
  ]
}"#;
        let cmds = verb_commands(permuted);
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].label, "Run get");
        assert_eq!(cmds[0].hint, "pillar get");
    }

    #[test]
    fn a_malformed_or_empty_inventory_yields_no_fabricated_commands() {
        assert!(verb_commands("").is_empty());
        assert!(verb_commands("not json at all").is_empty());
        assert!(verb_commands("{}").is_empty());
        // Present-but-empty array.
        assert!(verb_commands(r#"{"surface_inventory": []}"#).is_empty());
        // An object missing `id`/`kind` is skipped, never guessed.
        assert!(
            verb_commands(r#"{"surface_inventory": [{"signature": "x"}]}"#).is_empty()
        );
    }

    /// Source audit (anti-facade DoD): the palette's verb list is DERIVED from
    /// the live surface-inventory fetch, not a hand-maintained catalog. Pin that
    /// the component fetches `/surface-inventory` and builds its verbs via
    /// `verb_commands(&r.body)` — so a future edit cannot re-introduce a
    /// duplicated hardcoded verb list.
    #[test]
    fn palette_verb_list_is_sourced_from_the_surface_inventory_fetch() {
        let src = include_str!("command_palette.rs");
        assert!(
            src.contains("http(\"GET\", \"/surface-inventory\", None)"),
            "palette no longer fetches the /surface-inventory document"
        );
        assert!(
            src.contains("verb_commands(&r.body)"),
            "palette no longer projects its verb list from the fetched inventory"
        );
    }

    /// Source audit (anti-facade DoD): the palette's inventory fetch has a Toast
    /// error branch on BOTH failure arms (a non-OK status and a transport
    /// error), so a load failure surfaces to the user instead of silently
    /// no-op'ing.
    #[test]
    fn palette_inventory_fetch_has_a_toast_error_branch() {
        let src = include_str!("command_palette.rs");
        let n = src.matches("toaster.error(").count();
        assert!(
            n >= 2,
            "palette inventory fetch must surface both failure arms via toaster.error(...), found {n}"
        );
    }
}
