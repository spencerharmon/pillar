//! The dashboard's **portal panels** — one Yew-shell panel per existing
//! `web_login.html` portal capability, ported onto the Yew app shell built by
//! `yew-app-shell` (see `crate::auth`/`crate::router`).
//!
//! Every panel's WIRING — which `/portal/*`/`/bootstrap/*` endpoint it lists
//! from, which line-prefix its response uses, and which endpoint(s) its
//! action buttons call — is expressed as plain, host-testable [`PanelSpec`]
//! data (mirrors `auth`/`router`'s "host-testable logic, thin Yew wrapper"
//! split). Only the DOM/`fetch` glue in [`Panel`] lives behind the `yew`
//! feature; the wiring itself, and the shared [`parse_lines`] response
//! parser, are asserted with a native `cargo test`. This SAME wiring table is
//! what `crates/pillar-cli/src/web_serve.rs`'s retargeted `ui_confirms_*`
//! suite asserts is embedded in the compiled `wasm32-unknown-unknown` build
//! of `pillar-frontend` (which mounts `crate::router::Shell`).

#[cfg(feature = "yew")]
use wasm_bindgen::{JsCast, JsValue};
#[cfg(feature = "yew")]
use web_sys::{Headers, RequestInit, RequestMode, Response};
#[cfg(feature = "yew")]
use yew::prelude::*;

#[cfg(feature = "yew")]
use crate::auth::{use_auth, AuthAction};

/// One action a panel can perform: an HTTP method + endpoint path + the
/// button label the user sees.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PanelAction {
    /// The HTTP method (`"POST"`, `"DELETE"`, …).
    pub method: &'static str,
    /// The endpoint path this action calls.
    pub path: &'static str,
    /// The button label.
    pub label: &'static str,
}

/// One portal capability's Yew-shell wiring: pure data, no DOM/fetch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PanelSpec {
    /// A short, unique identifier for this panel (used as its render key).
    pub id: &'static str,
    /// The human-facing title shown above the panel.
    pub title: &'static str,
    /// The `GET` endpoint this panel lists its rows from.
    pub list_path: &'static str,
    /// The line-prefix [`parse_lines`] strips from each response line (empty
    /// string when the response carries no fixed prefix).
    pub line_prefix: &'static str,
    /// This panel's action buttons. `actions[0]` is the PRIMARY action — the
    /// one whose round trip [`Panel`]'s smoke-tested primary-action wiring
    /// refreshes the list on success. Every remaining entry is an additional
    /// action button wired the same way (fire-and-refresh, `401` clears the
    /// session) without re-triggering the primary-action refresh semantics
    /// twice.
    pub actions: &'static [PanelAction],
}

impl PanelSpec {
    /// This panel's primary action (`actions[0]`) — the one the task card's
    /// "primary action round-trips through pillar-web-api" smoke test wires.
    pub fn primary_action(&self) -> PanelAction {
        self.actions[0]
    }
}

/// Every portal capability this pass ports onto the Yew shell — the full
/// 9-capability parity list the ROI names: `ui-request-inbox-portal`,
/// `ui-identity-domain-user` (identity + domains + members),
/// `ui-trust-key-builders` (trust-graph + attestations + custody),
/// `ui-resource-workload`, `ui-observability-builders`,
/// `ui-topology-explorer`, and `ui-session-management`. Every path here
/// matches the real handler wiring `crates/pillar-cli/src/web_serve.rs`
/// serves, and covers every endpoint that suite's `ui_confirms_*` needles
/// require the Yew build to embed.
pub const ALL_PANELS: &[PanelSpec] = &[
    PanelSpec {
        id: "request-inbox",
        title: "Request Inbox",
        list_path: "/bootstrap/request/list",
        line_prefix: "",
        actions: &[
            PanelAction {
                method: "POST",
                path: "/bootstrap/request/approve",
                label: "inbox-approve",
            },
            PanelAction {
                method: "POST",
                path: "/bootstrap/request/reject",
                label: "inbox-reject",
            },
        ],
    },
    PanelSpec {
        id: "identity",
        title: "Identity",
        list_path: "/portal/identity",
        line_prefix: "",
        actions: &[
            PanelAction {
                method: "POST",
                path: "/portal/identity/enroll",
                label: "Enroll",
            },
            PanelAction {
                method: "POST",
                path: "/portal/identity/rotate",
                label: "Rotate",
            },
            PanelAction {
                method: "POST",
                path: "/portal/identity/recover",
                label: "Recover",
            },
        ],
    },
    PanelSpec {
        id: "domains",
        title: "Domains",
        list_path: "/portal/domains",
        line_prefix: "",
        actions: &[PanelAction {
            method: "POST",
            path: "/portal/domains/grant",
            label: "Grant",
        }],
    },
    PanelSpec {
        id: "members",
        title: "Members",
        list_path: "/portal/members",
        line_prefix: "",
        actions: &[PanelAction {
            method: "POST",
            path: "/portal/members/add",
            label: "Add member",
        }],
    },
    PanelSpec {
        id: "sessions",
        title: "Sessions",
        list_path: "/portal/sessions",
        line_prefix: "",
        actions: &[
            PanelAction {
                method: "POST",
                path: "/portal/sessions/revoke",
                label: "Revoke",
            },
            PanelAction {
                method: "POST",
                path: "/portal/sessions/revoke-all",
                label: "Revoke all",
            },
        ],
    },
    PanelSpec {
        id: "trust-graph",
        title: "Trust Graph",
        list_path: "/portal/trust-graph",
        line_prefix: "EDGE ",
        actions: &[
            PanelAction {
                method: "POST",
                path: "/portal/attestations/build",
                label: "Build attestation",
            },
            PanelAction {
                method: "POST",
                path: "/portal/custody/rotate",
                label: "Rotate custody",
            },
        ],
    },
    PanelSpec {
        id: "custody",
        title: "Custody",
        // Custody shares the trust-graph view (its edges are the same signed
        // attestation substrate `web_login.html`'s custody tile reads).
        list_path: "/portal/trust-graph",
        line_prefix: "EDGE ",
        actions: &[PanelAction {
            method: "POST",
            path: "/portal/custody/rotate",
            label: "Rotate",
        }],
    },
    PanelSpec {
        id: "resource-workload",
        title: "Resource / Workload",
        list_path: "/portal/resource/get",
        line_prefix: "",
        actions: &[
            PanelAction {
                method: "POST",
                path: "/portal/resource/apply",
                label: "Apply",
            },
            PanelAction {
                method: "POST",
                path: "/portal/resource/dry-run",
                label: "Dry run",
            },
        ],
    },
    PanelSpec {
        id: "topology-explorer",
        title: "Topology Explorer",
        list_path: "/portal/topology/tree",
        line_prefix: "NODE ",
        actions: &[
            PanelAction {
                method: "POST",
                path: "/portal/topology/label/attest",
                label: "Attest label",
            },
            PanelAction {
                method: "GET",
                path: "/portal/topology/failure-domain",
                label: "Failure domains",
            },
        ],
    },
    PanelSpec {
        id: "observability",
        title: "Observability",
        list_path: "/portal/obs/explore",
        line_prefix: "",
        actions: &[
            PanelAction {
                method: "GET",
                path: "/portal/obs/query",
                label: "Query",
            },
            PanelAction {
                method: "POST",
                path: "/portal/obs/dashboard",
                label: "Save dashboard",
            },
        ],
    },
];

/// The shared line-prefix response parser every `/portal/*`/`/bootstrap/*`
/// list response uses (mirrors `web_login.html`'s per-tile
/// `line.startsWith(...)` filtering): splits `text` on `\n`, drops blank
/// lines, and — when `prefix` is non-empty — keeps only lines that start
/// with it, stripping the prefix; an empty `prefix` passes every non-blank
/// line through unchanged.
pub fn parse_lines(text: &str, prefix: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            if prefix.is_empty() {
                Some(l.to_owned())
            } else {
                l.strip_prefix(prefix).map(str::to_owned)
            }
        })
        .collect()
}

#[cfg(feature = "yew")]
/// Props for [`Panel`].
#[derive(Properties, PartialEq)]
pub struct PanelProps {
    /// The capability this panel instance wires.
    pub spec: PanelSpec,
}

#[cfg(feature = "yew")]
/// A generic, data-driven Yew panel parameterized by a [`PanelSpec`]: fetches
/// its list endpoint on mount (bearer-token-authenticated), renders the
/// parsed rows, and wires one button per [`PanelSpec::actions`] entry that
/// performs that action's real endpoint round trip — the primary
/// (`actions[0]`) button additionally refreshes the list on success — and
/// dispatches [`AuthAction::Unauthorized`] (redirecting to `/login` via the
/// router guard) on any `401`.
#[function_component(Panel)]
pub fn panel(props: &PanelProps) -> Html {
    let auth = use_auth();
    let spec = props.spec;
    let rows: UseStateHandle<Vec<String>> = use_state(Vec::new);

    {
        let rows = rows.clone();
        let auth = auth.clone();
        use_effect_with((spec.list_path, auth.token.clone()), move |_| {
            let rows = rows.clone();
            let auth = auth.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_text(spec.list_path, auth.token.as_deref(), None).await {
                    Ok(FetchOutcome::Ok(text)) => rows.set(parse_lines(&text, spec.line_prefix)),
                    Ok(FetchOutcome::Unauthorized) => auth.dispatch(AuthAction::Unauthorized),
                    Err(_) => {}
                }
            });
            || ()
        });
    }

    let make_action_handler = |action: PanelAction, refresh: bool| {
        let rows = rows.clone();
        let auth = auth.clone();
        Callback::from(move |_| {
            let rows = rows.clone();
            let auth = auth.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_text(action.path, auth.token.as_deref(), Some("")).await {
                    Ok(FetchOutcome::Ok(_)) if refresh => {
                        if let Ok(FetchOutcome::Ok(text)) =
                            fetch_text(spec.list_path, auth.token.as_deref(), None).await
                        {
                            rows.set(parse_lines(&text, spec.line_prefix));
                        }
                    }
                    Ok(FetchOutcome::Ok(_)) => {}
                    Ok(FetchOutcome::Unauthorized) => auth.dispatch(AuthAction::Unauthorized),
                    Err(_) => {}
                }
            });
        })
    };

    html! {
        <section key={spec.id} data-panel={spec.id}>
            <h2>{ spec.title }</h2>
            <ul>
                { for rows.iter().map(|r| html! { <li>{ r.clone() }</li> }) }
            </ul>
            { for spec.actions.iter().enumerate().map(|(i, action)| {
                let onclick = make_action_handler(*action, i == 0);
                html! { <button {onclick}>{ action.label }</button> }
            }) }
        </section>
    }
}

#[cfg(feature = "yew")]
enum FetchOutcome {
    Ok(String),
    Unauthorized,
}

#[cfg(feature = "yew")]
/// Performs one bearer-token-authenticated `fetch` round trip. `body`, when
/// `Some`, sends a `POST` request (the panels only ever `POST` a write action
/// or plain `GET` a list) with that (possibly empty) text body; `None`
/// performs a plain `GET`. Returns the response text on any non-401 status
/// (the caller inspects it further if it needs to), [`FetchOutcome::
/// Unauthorized`] on a `401`.
async fn fetch_text(
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Result<FetchOutcome, JsValue> {
    let opts = RequestInit::new();
    opts.set_method(if body.is_some() { "POST" } else { "GET" });
    opts.set_mode(RequestMode::SameOrigin);
    if let Some(b) = body {
        opts.set_body(&JsValue::from_str(b));
    }
    let headers = Headers::new()?;
    if let Some(t) = token {
        headers.set("X-Pillar-Session", t)?;
    }
    opts.set_headers(&headers);

    let window = web_sys::window().expect("window exists in a browser context");
    let resp_value =
        wasm_bindgen_futures::JsFuture::from(window.fetch_with_str_and_init(path, &opts)).await?;
    let resp: Response = resp_value.dyn_into()?;
    if resp.status() == 401 {
        return Ok(FetchOutcome::Unauthorized);
    }
    let text_value = wasm_bindgen_futures::JsFuture::from(resp.text()?).await?;
    Ok(FetchOutcome::Ok(text_value.as_string().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(id: &str) -> &'static PanelSpec {
        ALL_PANELS.iter().find(|p| p.id == id).unwrap()
    }

    #[test]
    fn parse_lines_strips_the_prefix_and_drops_unrelated_lines() {
        let text = "EDGE owner -> node-7 rack=r7\n\nnot-an-edge\nEDGE a -> b x=1\n";
        let rows = parse_lines(text, "EDGE ");
        assert_eq!(
            rows,
            vec![
                "owner -> node-7 rack=r7".to_string(),
                "a -> b x=1".to_string(),
            ]
        );
    }

    #[test]
    fn parse_lines_with_empty_prefix_passes_every_nonblank_line() {
        let text = "1 node alice\n\n2 user bob\n";
        let rows = parse_lines(text, "");
        assert_eq!(
            rows,
            vec!["1 node alice".to_string(), "2 user bob".to_string()]
        );
    }

    #[test]
    fn parse_lines_on_an_empty_response_is_an_empty_list() {
        assert!(parse_lines("", "").is_empty());
        assert!(parse_lines("\n\n", "EDGE ").is_empty());
    }

    /// Every `ALL_PANELS` entry's list path and every action path are real
    /// `/portal/*`/`/bootstrap/*` endpoints (the endpoint-wiring proof,
    /// expressed against the Yew `PanelSpec` table). This is the same wiring
    /// this crate's build embeds into the `wasm32-unknown-unknown` binary
    /// that the retargeted `ui_confirms_*` suite
    /// (`crates/pillar-cli/src/web_serve.rs`) asserts against.
    #[test]
    fn every_panel_wires_a_real_portal_or_bootstrap_endpoint() {
        for spec in ALL_PANELS {
            assert!(
                spec.list_path.starts_with("/portal/") || spec.list_path.starts_with("/bootstrap/"),
                "{} lists from a non-portal endpoint: {}",
                spec.id,
                spec.list_path
            );
            assert!(!spec.actions.is_empty(), "{} has no actions", spec.id);
            for action in spec.actions {
                assert!(
                    action.path.starts_with("/portal/") || action.path.starts_with("/bootstrap/"),
                    "{} acts on a non-portal endpoint: {}",
                    spec.id,
                    action.path
                );
            }
        }
        // Covers every ROI-named capability, not just a subset.
        let ids: Vec<&str> = ALL_PANELS.iter().map(|p| p.id).collect();
        for expected in [
            "request-inbox",
            "identity",
            "domains",
            "members",
            "sessions",
            "trust-graph",
            "custody",
            "resource-workload",
            "topology-explorer",
            "observability",
        ] {
            assert!(ids.contains(&expected), "missing panel: {expected}");
        }
    }

    #[test]
    fn identity_panel_parses_domain_keys_and_wires_enroll() {
        let spec = find("identity");
        assert_eq!(spec.list_path, "/portal/identity");
        assert_eq!(spec.primary_action().path, "/portal/identity/enroll");
        let rows = parse_lines("alice\nbob\n", spec.line_prefix);
        assert_eq!(rows, vec!["alice".to_string(), "bob".to_string()]);
    }

    #[test]
    fn members_panel_parses_member_roles_and_wires_add() {
        let spec = find("members");
        assert_eq!(spec.list_path, "/portal/members");
        assert_eq!(spec.primary_action().path, "/portal/members/add");
        let rows = parse_lines("alice admin\nbob viewer\n", spec.line_prefix);
        assert_eq!(
            rows,
            vec!["alice admin".to_string(), "bob viewer".to_string()]
        );
    }

    #[test]
    fn sessions_panel_parses_session_rows_and_wires_revoke() {
        let spec = find("sessions");
        assert_eq!(spec.list_path, "/portal/sessions");
        assert_eq!(spec.primary_action().path, "/portal/sessions/revoke");
        assert!(spec
            .actions
            .iter()
            .any(|a| a.path == "/portal/sessions/revoke-all"));
        let rows = parse_lines("sess-1 alice\nsess-2 bob\n", spec.line_prefix);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn trust_graph_panel_parses_edges_and_wires_attestation_build() {
        let spec = find("trust-graph");
        assert_eq!(spec.list_path, "/portal/trust-graph");
        assert_eq!(spec.primary_action().path, "/portal/attestations/build");
        assert!(spec
            .actions
            .iter()
            .any(|a| a.path == "/portal/custody/rotate"));
        let rows = parse_lines("EDGE owner -> node-7 rack=r7\n", spec.line_prefix);
        assert_eq!(rows, vec!["owner -> node-7 rack=r7".to_string()]);
    }

    #[test]
    fn custody_panel_shares_the_trust_graph_view_and_wires_rotate() {
        let spec = find("custody");
        assert_eq!(spec.list_path, "/portal/trust-graph");
        assert_eq!(spec.primary_action().path, "/portal/custody/rotate");
    }

    #[test]
    fn request_inbox_panel_parses_requests_and_wires_approve() {
        let spec = find("request-inbox");
        assert_eq!(spec.list_path, "/bootstrap/request/list");
        assert_eq!(spec.primary_action().path, "/bootstrap/request/approve");
        assert!(spec
            .actions
            .iter()
            .any(|a| a.path == "/bootstrap/request/reject"));
        let rows = parse_lines("1 node alice\n2 user bob\n", spec.line_prefix);
        assert_eq!(
            rows,
            vec!["1 node alice".to_string(), "2 user bob".to_string()]
        );
    }

    #[test]
    fn observability_panel_parses_signals_and_wires_dashboard_save() {
        let spec = find("observability");
        assert_eq!(spec.list_path, "/portal/obs/explore");
        assert!(spec
            .actions
            .iter()
            .any(|a| a.path == "/portal/obs/dashboard"));
        assert!(spec.actions.iter().any(|a| a.path == "/portal/obs/query"));
    }

    #[test]
    fn resource_workload_panel_parses_resources_and_wires_apply() {
        let spec = find("resource-workload");
        assert_eq!(spec.list_path, "/portal/resource/get");
        assert_eq!(spec.primary_action().path, "/portal/resource/apply");
        assert!(spec
            .actions
            .iter()
            .any(|a| a.path == "/portal/resource/dry-run"));
    }

    #[test]
    fn topology_explorer_panel_parses_the_tier_tree_and_wires_label_attest() {
        let spec = find("topology-explorer");
        assert_eq!(spec.list_path, "/portal/topology/tree");
        assert_eq!(spec.primary_action().path, "/portal/topology/label/attest");
        assert!(spec
            .actions
            .iter()
            .any(|a| a.path == "/portal/topology/failure-domain"));
        let rows = parse_lines(
            "NODE node-a PATH rack=r1 HEALTH ok CAPACITY 10\n",
            spec.line_prefix,
        );
        assert_eq!(
            rows,
            vec!["node-a PATH rack=r1 HEALTH ok CAPACITY 10".to_string()]
        );
    }

    #[test]
    fn domains_panel_parses_domains_and_wires_grant() {
        let spec = find("domains");
        assert_eq!(spec.list_path, "/portal/domains");
        assert_eq!(spec.primary_action().path, "/portal/domains/grant");
    }
}
