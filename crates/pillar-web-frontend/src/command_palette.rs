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

/// Move the palette's highlighted-row index by `delta` over a list of `len`
/// visible rows, wrapping around both ends (Linear/VS-Code palette behavior:
/// ArrowDown past the last row lands on the first, ArrowUp past the first lands
/// on the last). An empty list has no selectable row, so the selection stays at
/// `0` (nothing is highlighted when `len == 0`). This is the keyboard-navigation
/// core, kept pure so the wrap contract is pinned by a host test rather than
/// only exercised in the browser.
#[must_use]
pub fn move_selection(current: usize, len: usize, delta: i32) -> usize {
    if len == 0 {
        return 0;
    }
    let len_i = len as i32;
    // Clamp an out-of-range `current` (e.g. after the visible list shrank on a
    // keystroke) into range before moving, so navigation never indexes past the
    // end.
    let cur = (current.min(len - 1)) as i32;
    let next = (cur + delta).rem_euclid(len_i);
    next as usize
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
    use super::{filter_commands, move_selection, verb_commands, Command};
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
        // The keyboard-highlighted row, an index into the currently-visible
        // (filtered) command list. Reset to 0 whenever the palette opens or the
        // query changes so ArrowDown/ArrowUp always start from the top match.
        let selected = use_state(|| 0usize);
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
            let selected = selected.clone();
            use_effect_with((), move |()| {
                let handler = Closure::<dyn FnMut(web_sys::KeyboardEvent)>::wrap(Box::new(
                    move |e: web_sys::KeyboardEvent| {
                        if (e.meta_key() || e.ctrl_key()) && e.key().eq_ignore_ascii_case("k") {
                            e.prevent_default();
                            // Opening resets the highlight to the top match.
                            selected.set(0);
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
            let (query, selected) = (query.clone(), selected.clone());
            Callback::from(move |e: InputEvent| {
                use wasm_bindgen::JsCast;
                if let Some(t) = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
                {
                    query.set(t.value());
                    // A changed query re-filters the list; drop the highlight
                    // back to the top match so it never dangles off the end.
                    selected.set(0);
                }
            })
        };
        let visible = filter_commands(&commands, &query);
        // Clamp the highlighted row into the visible range for rendering (the
        // list may have shrunk since the last keystroke).
        let active = (*selected).min(visible.len().saturating_sub(1));

        let close = {
            let open = open.clone();
            Callback::from(move |_: MouseEvent| open.set(false))
        };

        // Navigate to a section (for a section entry) and always close. Shared by
        // the click handler and the Enter-key handler.
        let go = {
            let (open, navigator) = (open.clone(), navigator.clone());
            move |section: Option<Section>| {
                if let (Some(section), Some(nav)) = (section, navigator.as_ref()) {
                    nav.push(&section_route(section));
                }
                open.set(false);
            }
        };
        // The Section for a visible-list position, mapping the filtered index
        // back through `visible` to the original command index.
        let section_at = {
            let visible = visible.clone();
            move |pos: usize| -> Option<Section> {
                visible.get(pos).and_then(|&i| {
                    if i < section_count {
                        Some(Section::all()[i])
                    } else {
                        None
                    }
                })
            }
        };
        let run = {
            let (go, section_at) = (go.clone(), section_at.clone());
            move |pos: usize| {
                let (go, section_at) = (go.clone(), section_at.clone());
                Callback::from(move |_: MouseEvent| go(section_at(pos)))
            }
        };

        // Keyboard navigation on the palette input: ArrowDown/ArrowUp move the
        // highlight (wrapping via the pure `move_selection`), Enter runs the
        // highlighted command, Escape closes. Keeping the keys on the always-
        // focused input means the palette is fully operable without a mouse.
        let on_keydown = {
            let (selected, open, go, section_at) =
                (selected.clone(), open.clone(), go.clone(), section_at.clone());
            let len = visible.len();
            Callback::from(move |e: KeyboardEvent| match e.key().as_str() {
                "ArrowDown" => {
                    e.prevent_default();
                    selected.set(move_selection(active, len, 1));
                }
                "ArrowUp" => {
                    e.prevent_default();
                    selected.set(move_selection(active, len, -1));
                }
                "Enter" => {
                    e.prevent_default();
                    if len > 0 {
                        go(section_at(active));
                    }
                }
                "Escape" => open.set(false),
                _ => {}
            })
        };

        html! {
            <div class="cmdk">
                <div class="cmdk__scrim" onclick={close} />
                <div class="cmdk__panel" role="dialog" aria-label="Command palette">
                    <input class="cmdk__input" type="text" autofocus=true
                           placeholder="Jump to\u{2026}" value={(*query).clone()}
                           oninput={on_input} onkeydown={on_keydown} />
                    <ul class="cmdk__list" role="listbox">
                        { for visible.iter().enumerate().map(|(pos, &i)| {
                            let is_active = pos == active;
                            let class = if is_active {
                                "cmdk__item is-active"
                            } else {
                                "cmdk__item"
                            };
                            html! {
                                <li class={class} role="option"
                                    aria-selected={is_active.to_string()}
                                    onclick={run(pos)}>
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

    #[test]
    fn move_selection_advances_and_wraps_both_ends() {
        // Plain forward/backward moves within range.
        assert_eq!(move_selection(0, 4, 1), 1);
        assert_eq!(move_selection(2, 4, 1), 3);
        assert_eq!(move_selection(2, 4, -1), 1);
        // ArrowDown past the last row wraps to the first…
        assert_eq!(move_selection(3, 4, 1), 0);
        // …and ArrowUp past the first wraps to the last.
        assert_eq!(move_selection(0, 4, -1), 3);
    }

    #[test]
    fn move_selection_is_safe_on_empty_and_out_of_range() {
        // No rows: nothing is selectable, selection stays at 0.
        assert_eq!(move_selection(0, 0, 1), 0);
        assert_eq!(move_selection(5, 0, -1), 0);
        // A stale index past the (shrunk) end is clamped before moving, so it
        // never indexes out of bounds: from clamped-2, +1 wraps to 0.
        assert_eq!(move_selection(9, 3, 1), 0);
        assert_eq!(move_selection(9, 3, -1), 1);
    }

    /// Source audit (anti-facade DoD): the palette is operable from the keyboard
    /// — the input wires an `onkeydown` that drives ArrowUp/ArrowDown selection
    /// through the pure `move_selection` and runs the highlighted command on
    /// Enter, and the highlighted row is marked `aria-selected`. This pins that
    /// a future edit cannot silently drop the keyboard navigation.
    #[test]
    fn palette_wires_keyboard_navigation() {
        let src = include_str!("command_palette.rs");
        assert!(
            src.contains("onkeydown={on_keydown}"),
            "palette input no longer wires an onkeydown handler"
        );
        for key in ["\"ArrowDown\"", "\"ArrowUp\"", "\"Enter\""] {
            assert!(
                src.contains(key),
                "palette keyboard handler no longer handles {key}"
            );
        }
        assert!(
            src.contains("move_selection("),
            "palette navigation no longer routes through the pure move_selection"
        );
        assert!(
            src.contains("aria-selected="),
            "palette rows no longer mark the highlighted option aria-selected"
        );
    }
}
