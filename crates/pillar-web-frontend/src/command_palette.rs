//! The command palette (Phase 5) — a ⌘K / Ctrl-K quick switcher over every
//! console section AND every registered manifest resource kind. The fuzzy-ish
//! filter is a pure, host-tested function; the component wires the global
//! keyboard shortcut, the overlay, and router navigation.
//!
//! **Anti-facade sourcing.** The section commands are not a hand-maintained
//! duplicate: they are read straight off [`crate::console::Section::all`],
//! the console's own single source of truth for its routes. The resource
//! commands are read off `pillar_manifest::builtin::register_builtin_schemas`
//! — the SAME builtin schema registry `pillar-cli`'s resource verbs dispatch
//! through and the SAME registry `pillar-surface-inventory`'s canonical
//! `manifest-kind` entries are built from (that crate re-derives its
//! `manifest_kind_entries` from `SchemaRegistry::kinds()` too — see that
//! crate's doc comment). `pillar-web-frontend` cannot depend on
//! `pillar-surface-inventory` itself at RUNTIME (that crate pulls in
//! `pillar-cli`, which is not `wasm32`-portable), so the palette instead
//! depends directly on `pillar-manifest` (already a frontend dependency) for
//! its production kind list, and — NATIVE-test-only, see `Cargo.toml`'s
//! `[dev-dependencies]` — pins that list against
//! `pillar_surface_inventory::emit_production()`'s `manifest-kind` entries in
//! [`tests::resource_commands_match_the_canonical_surface_inventory`], so the
//! two can never silently drift apart.

/// A command the palette can run: a human label and a short keyword hint
/// shown muted (the section group, or "Resources" for a resource-kind jump).
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

/// Build one "Go to `<Kind>` resources" command per manifest kind registered
/// in `registry`, read from the REAL, live schema registry — never a
/// hand-maintained catalog. Every kind navigates to the Resources section
/// (today's `ResourcesConsole` does not yet deep-link a pre-selected kind
/// into the URL; the command still surfaces every real kind rather than
/// omitting them, and `console-a11y-responsive-polish` — deps on THIS task —
/// is the tracked follow-up for the deep link).
#[must_use]
pub fn resource_commands(registry: &pillar_manifest::SchemaRegistry) -> Vec<Command> {
    registry
        .kinds()
        .map(|(_api_version, kind)| Command {
            label: format!("Go to {kind} resources"),
            hint: "Resources".to_owned(),
        })
        .collect()
}

/// The production manifest-kind registry the palette's resource commands are
/// built from — the builtin schemas, registered exactly as the server-side
/// resource plane and `pillar-surface-inventory` register them.
#[must_use]
pub fn production_manifest_registry() -> pillar_manifest::SchemaRegistry {
    let mut registry = pillar_manifest::SchemaRegistry::new();
    pillar_manifest::builtin::register_builtin_schemas(&mut registry);
    registry
}

#[cfg(feature = "yew")]
pub use yew_impl::CommandPalette;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{filter_commands, production_manifest_registry, resource_commands, Command};
    use crate::console::section_route;
    use crate::console::Section;
    use crate::router::Route;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use yew::prelude::*;
    use yew_router::prelude::*;

    /// One command plus where it navigates: `Some(section)` for a real
    /// console section, `None` for a resource-kind command (which today all
    /// land on the Resources section — see [`super::resource_commands`]).
    fn all_commands() -> Vec<(Command, Option<Section>)> {
        let mut out: Vec<(Command, Option<Section>)> = Section::all()
            .into_iter()
            .map(|s| {
                (
                    Command {
                        label: format!("Go to {}", s.label()),
                        hint: s.group().label().to_owned(),
                    },
                    Some(s),
                )
            })
            .collect();
        out.extend(
            resource_commands(&production_manifest_registry())
                .into_iter()
                .map(|c| (c, None)),
        );
        out
    }

    /// The ⌘K command palette. Mounted once in the console frame; a global
    /// keydown listener opens it on Cmd/Ctrl-K and closes it on Escape.
    /// Selecting a command navigates to that section (a resource-kind
    /// command navigates to Resources) and closes the overlay.
    #[function_component(CommandPalette)]
    pub fn command_palette() -> Html {
        let open = use_state(|| false);
        let query = use_state(String::new);
        let navigator = use_navigator();

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

        let commands = all_commands();
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
        let labels: Vec<Command> = commands.iter().map(|(c, _)| c.clone()).collect();
        let visible = filter_commands(&labels, &query);

        let close = {
            let open = open.clone();
            Callback::from(move |_: MouseEvent| open.set(false))
        };

        let run = {
            let (open, navigator) = (open.clone(), navigator.clone());
            move |route: Route| {
                let (open, navigator) = (open.clone(), navigator.clone());
                Callback::from(move |_: MouseEvent| {
                    if let Some(nav) = &navigator {
                        nav.push(&route);
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
                            let route = commands[i].1.map(section_route).unwrap_or(Route::Resources);
                            html! {
                                <li class="cmdk__item" onclick={run(route)}>
                                    <span class="cmdk__label">{ &commands[i].0.label }</span>
                                    <span class="cmdk__hint">{ &commands[i].0.hint }</span>
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

    #[test]
    fn resource_commands_are_read_from_the_live_registry_not_hand_maintained() {
        let registry = production_manifest_registry();
        let expected: Vec<String> = registry.kinds().map(|(_, k)| k.to_owned()).collect();
        let commands = resource_commands(&registry);
        assert_eq!(commands.len(), expected.len());
        for (c, kind) in commands.iter().zip(expected.iter()) {
            assert_eq!(c.label, format!("Go to {kind} resources"));
            assert_eq!(c.hint, "Resources");
        }
        // The registry is non-empty in production — this is a real, populated
        // source, never a dead/no-op list.
        assert!(!commands.is_empty());
    }

    /// NATIVE-test-only pin (see `Cargo.toml`'s `[dev-dependencies]`): the
    /// palette's resource-kind commands must exactly match the canonical
    /// `manifest-kind` entries `pillar_surface_inventory::emit_production()`
    /// emits — the SAME document `GET /surface-inventory` serves and the
    /// `pillar-integration` conformance rig consumes. If a manifest kind is
    /// added/removed anywhere in the real registries, this test fails until
    /// the palette (which reads the SAME registry, see
    /// [`production_manifest_registry`]) is rebuilt — it can never silently
    /// drift into a hand-maintained duplicate.
    #[test]
    fn resource_commands_match_the_canonical_surface_inventory() {
        use pillar_surface_inventory::SurfaceKind;

        let inventory = pillar_surface_inventory::emit_production();
        let canonical_kinds: Vec<String> = inventory
            .surface_inventory
            .iter()
            .filter(|e| e.kind == SurfaceKind::ManifestKind)
            .map(|e| {
                // id is "manifest:<kind>" (see pillar_surface_inventory::manifest_kind_entries).
                e.id.strip_prefix("manifest:").unwrap_or(&e.id).to_owned()
            })
            .collect();

        let registry = production_manifest_registry();
        let palette_kinds: Vec<String> = registry.kinds().map(|(_, k)| k.to_owned()).collect();

        assert_eq!(
            palette_kinds, canonical_kinds,
            "command palette's resource-kind list has drifted from the canonical \
             surface_inventory manifest-kind entries"
        );
        assert!(!canonical_kinds.is_empty());
    }
}
