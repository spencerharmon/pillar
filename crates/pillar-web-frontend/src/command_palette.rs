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

#[cfg(feature = "yew")]
pub use yew_impl::CommandPalette;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{filter_commands, Command};
    use crate::console::section_route;
    use crate::console::Section;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::JsCast;
    use yew::prelude::*;
    use yew_router::prelude::*;

    fn all_commands() -> Vec<Command> {
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
        let visible = filter_commands(&commands, &query);

        let close = {
            let open = open.clone();
            Callback::from(move |_: MouseEvent| open.set(false))
        };

        let run = {
            let (open, navigator) = (open.clone(), navigator.clone());
            move |section: Section| {
                let (open, navigator) = (open.clone(), navigator.clone());
                Callback::from(move |_: MouseEvent| {
                    if let Some(nav) = &navigator {
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
                            let section = Section::all()[i];
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
}
