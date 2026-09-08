//! Component style builders — the design system's heart. Each function takes the
//! [`Theme`] and a [`Motion`] preference and returns a scoped `stylist` [`Style`]
//! whose emitted CSS carries the design tokens. These are pure and host-testable:
//! the tests build a style and assert the expected token strings appear (and,
//! under [`Motion::Reduced`], that no `transition`/`animation` is emitted).
//!
//! The Yew components in [`crate::components`] simply attach the class these
//! functions produce, so the visual language is defined ONCE here.

use crate::theme::{Motion, Theme};
use stylist::Style;

/// The portal-wide **global stylesheet**, built from the same [`Theme`] tokens
/// as every scoped component style so the "Linear/modern" dark aesthetic is
/// applied uniformly to the whole app — the authenticated dashboard panels
/// (`portal.rs`) AND the login/bootstrap entry surface (`portal_entry.rs`),
/// both of which render semantic class names (`.portal`, `.tile`,
/// `.pillar-login`, `.member-row`, …) rather than per-component scoped
/// classes. Mounted once at the app [`crate::router::Shell`] via
/// `stylist::yew::Global`, it dresses those bare class names in the design
/// tokens (near-black layered surfaces, the indigo accent, multi-layer
/// shadows/glows, focus-glow inputs, accent buttons) so no panel renders
/// unstyled.
///
/// The interactive transition is gated on [`Motion`] exactly like the scoped
/// builders (empty under [`Motion::Reduced`]); an additional
/// `@media (prefers-reduced-motion: reduce)` guard also disables transitions
/// and animations live at the browser level (covering the scoped component
/// styles too), which is the required `prefers-reduced-motion` fallback.
///
/// Returns raw CSS (not a scoped [`Style`]) because a global sheet must NOT be
/// scoped under a generated class — the caller hands it to
/// `stylist::yew::Global`.
#[must_use]
pub fn global(theme: &Theme, motion: Motion) -> String {
    let transition = motion.transition(&theme.micro_transition());
    format!(
        r#"
        html, body {{
            margin: 0;
            padding: 0;
            min-height: 100vh;
            background-color: {surface_base};
            color: {text};
            font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI",
                Roboto, Helvetica, Arial, sans-serif;
            font-size: 15px;
            line-height: 1.5;
            -webkit-font-smoothing: antialiased;
        }}
        * {{ box-sizing: border-box; }}

        a {{ color: {accent}; text-decoration: none; }}
        a:hover {{ color: {accent_hover}; text-decoration: underline; }}

        h1, h2, h3 {{
            color: {text};
            font-weight: 650;
            letter-spacing: -0.01em;
        }}
        h2 {{ font-size: 1.4rem; margin: 0 0 0.25rem; }}
        h3 {{ font-size: 1.05rem; margin: 0 0 0.75rem; }}

        /* ---- Form controls (themed like the Input/Button component styles) ---- */
        input, select, textarea {{
            width: 100%;
            box-sizing: border-box;
            font: inherit;
            color: {text};
            background-color: {surface_base};
            border: 1px solid {border};
            border-radius: {radius};
            padding: 0.55rem 0.75rem;
            {transition}
        }}
        input::placeholder {{ color: {muted}; }}
        input:focus, select:focus, textarea:focus {{
            outline: none;
            border-color: {accent};
            box-shadow: 0 0 0 3px {glow};
        }}
        button {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            font: inherit;
            font-weight: 600;
            line-height: 1;
            padding: 0.55rem 0.95rem;
            border-radius: {radius};
            border: 1px solid {accent};
            background-color: {accent};
            color: #ffffff;
            cursor: pointer;
            {transition}
        }}
        button:hover {{ background-color: {accent_hover}; transform: translateY(-1px); }}
        button:active {{ transform: translateY(0); }}
        button:disabled {{ opacity: 0.5; cursor: not-allowed; transform: none; }}
        button:focus-visible {{ outline: 2px solid {accent}; outline-offset: 2px; }}

        /* ---- Auth surfaces: login + bootstrap, a centered raised card ---- */
        .pillar-login, .pillar-bootstrap {{
            display: flex;
            flex-direction: column;
            gap: 0.55rem;
            max-width: 26rem;
            width: calc(100% - 2rem);
            margin: 7vh auto;
            padding: 1.75rem;
            background-color: {surface_raised};
            border: 1px solid {border};
            border-radius: {radius};
            box-shadow: {shadow_resting};
        }}
        .pillar-login h2 {{ margin: 0 0 0.5rem; }}
        .pillar-login label, .pillar-bootstrap label {{
            font-size: 0.8rem;
            color: {muted};
            margin-top: 0.35rem;
        }}
        .step {{ font-size: 1.15rem; font-weight: 650; margin-bottom: 0.4rem; }}
        .pillar-loading {{ color: {muted}; text-align: center; margin: 22vh auto; }}

        /* ---- Dashboard: a responsive grid of raised tiles ---- */
        .portal {{
            max-width: 1120px;
            margin: 0 auto;
            padding: 2rem 1.25rem 4rem;
            display: grid;
            gap: 1rem;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            align-items: start;
        }}
        .portal > h2, .portal > .who, .portal > .signout {{ grid-column: 1 / -1; }}
        .who {{ color: {muted}; margin: 0 0 0.5rem; }}

        .tile {{
            background-color: {surface_raised};
            border: 1px solid {border};
            border-radius: {radius};
            box-shadow: {shadow_resting};
            color: {text};
            padding: 1.25rem;
            {transition}
        }}
        .tile:hover {{ box-shadow: {shadow_elevated}; border-color: {glow}; }}

        /* ---- List rows across every panel ---- */
        .member-row, .resource-row, .row, .obs-row, .trust-edge, .attest-line,
        .domain-row, .topology-fd-row, .topology-mismatch, .identity-domain-key,
        .session-row, .result {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.85rem;
            padding: 0.4rem 0.55rem;
            margin: 0.3rem 0;
            border-radius: 6px;
            background-color: {surface_base};
            border: 1px solid {border};
            word-break: break-word;
        }}
        .topology-mismatch {{ border-color: rgba(248, 113, 113, 0.4); }}
        .current-marker {{ color: {accent}; }}

        /* ---- Messages, hints, explainers ---- */
        .msg {{ margin: 0.5rem 0 0; font-size: 0.9rem; }}
        .msg.ok, .field-hint.ok {{ color: #4ade80; }}
        .msg.err, .field-hint.err, .error {{ color: #f87171; }}
        .hint, .explainer, .field-hint, .pillar-login__fallback-hint {{
            color: {muted};
            font-size: 0.85rem;
            line-height: 1.5;
        }}
        .explainer {{
            background-color: {surface_base};
            border: 1px solid {border};
            border-radius: {radius};
            padding: 0.75rem;
            margin-top: 0.5rem;
        }}
        .explainer strong {{ color: {text}; }}

        /* ---- Copy control + sign-out (quiet, secondary surface) ---- */
        .copyable {{ color: {text}; }}
        .copy-btn {{
            background-color: transparent;
            border-color: {border};
            color: {muted};
            padding: 0.12rem 0.5rem;
            font-size: 0.75rem;
        }}
        .copy-btn:hover {{ color: {text}; background-color: {surface_overlay}; }}
        .copy-btn.copied {{ color: {accent}; }}
        .signout {{
            background-color: {surface_overlay};
            border-color: {border};
            color: {text};
            width: fit-content;
            margin-top: 0.5rem;
        }}
        .signout:hover {{ background-color: {surface_raised}; }}

        /* ---- Security-key controls ---- */
        .pillar-security-key {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        .pillar-security-key__error {{ color: #f87171; width: 100%; margin: 0.25rem 0 0; }}

        /* ---- Observability guided PSL builders (explore.rs markup) ---- */
        .obs-builder {{ margin-top: 0.75rem; }}
        [data-panel^="explore-"] {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
            margin-top: 0.5rem;
            padding: 0.85rem;
            background-color: {surface_base};
            border: 1px solid {border};
            border-radius: {radius};
        }}
        [data-panel^="explore-"] h2 {{ font-size: 1rem; margin: 0; }}
        [data-role="predicate-builder"] {{ display: flex; flex-wrap: wrap; gap: 0.4rem; align-items: center; }}
        [data-role="predicate-builder"] input {{ width: auto; flex: 1 1 8rem; }}
        [data-panel="correlate"] {{
            padding: 0.5rem 0;
            border: none;
            background: transparent;
        }}
        [data-panel="correlate"] h3 {{ font-size: 0.85rem; color: {muted}; margin: 0 0 0.3rem; }}
        [data-role="correlate-kind"] {{
            background-color: {surface_overlay};
            border-color: {border};
            color: {text};
            margin-right: 0.35rem;
        }}
        [data-role="correlate-kind"]:hover {{ background-color: {surface_raised}; }}
        [data-role="predicate-rows"], [data-role="results"] {{
            list-style: none;
            margin: 0.25rem 0 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            gap: 0.2rem;
        }}
        [data-role="predicate-rows"] li, [data-role="results"] li {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.82rem;
            padding: 0.3rem 0.45rem;
            border-radius: 6px;
            background-color: {surface_raised};
            border: 1px solid {border};
            word-break: break-word;
        }}
        [data-role="run-query"] {{ align-self: flex-start; }}

        /* ---- Console shell: sidebar + topbar frame ---- */
        .console {{
            display: grid;
            grid-template-columns: 240px 1fr;
            min-height: 100vh;
            align-items: stretch;
        }}
        .console-sidebar {{
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            padding: 1rem 0.75rem;
            background-color: {surface_raised};
            border-right: 1px solid {border};
            position: sticky;
            top: 0;
            height: 100vh;
            overflow-y: auto;
        }}
        .console-brand {{
            font-weight: 700;
            font-size: 1.1rem;
            letter-spacing: -0.02em;
            color: {text};
            padding: 0.25rem 0.6rem 0.75rem;
        }}
        .console-navgroup {{ display: flex; flex-direction: column; gap: 0.1rem; margin-top: 0.5rem; }}
        .console-navgroup__label {{
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: {muted};
            padding: 0.35rem 0.6rem 0.2rem;
        }}
        .console-navlink {{
            display: flex;
            align-items: center;
            gap: 0.6rem;
            padding: 0.45rem 0.6rem;
            border-radius: {radius};
            color: {text};
            text-decoration: none;
            font-size: 0.9rem;
            {transition}
        }}
        .console-navlink:hover {{ background-color: {surface_overlay}; text-decoration: none; }}
        .console-navlink.is-active {{
            background-color: {accent};
            color: #fff;
            box-shadow: 0 0 0 1px {glow};
        }}
        .console-navlink__glyph {{
            width: 1.2rem;
            text-align: center;
            opacity: 0.9;
            font-size: 0.95rem;
        }}
        .console-main {{ display: flex; flex-direction: column; min-width: 0; }}
        .console-topbar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            padding: 0.85rem 1.5rem;
            background-color: {surface_base};
            border-bottom: 1px solid {border};
            position: sticky;
            top: 0;
            z-index: 5;
        }}
        .console-crumb {{ font-weight: 650; font-size: 1.05rem; color: {text}; }}
        .console-topbar__right {{ display: flex; align-items: center; gap: 1rem; }}
        .console-who {{ color: {muted}; font-size: 0.85rem; }}
        .console-content {{
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            max-width: 1200px;
            width: 100%;
        }}
        @media (max-width: 780px) {{
            .console {{ grid-template-columns: 1fr; }}
            .console-sidebar {{
                position: static;
                height: auto;
                flex-direction: row;
                flex-wrap: wrap;
                border-right: none;
                border-bottom: 1px solid {border};
            }}
        }}

        /* ---- Observability console: tabs, stat cards, panels ---- */
        .obs-tabs {{
            display: flex;
            gap: 0.25rem;
            flex-wrap: wrap;
            border-bottom: 1px solid {border};
            margin: 0.5rem 0 1rem;
        }}
        .obs-tab {{
            background: transparent;
            border: none;
            border-bottom: 2px solid transparent;
            color: {muted};
            padding: 0.45rem 0.7rem;
            font-size: 0.9rem;
            cursor: pointer;
            {transition}
        }}
        .obs-tab:hover {{ color: {text}; }}
        .obs-tab.is-active {{ color: {text}; border-bottom-color: {accent}; }}
        .obs-statgrid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
            gap: 0.75rem;
        }}
        .obs-stat {{
            background-color: {surface_raised};
            border: 1px solid {border};
            border-radius: {radius};
            padding: 0.9rem 1rem;
            box-shadow: {shadow_resting};
        }}
        .obs-stat__value {{ font-size: 1.6rem; font-weight: 700; color: {text}; letter-spacing: -0.02em; }}
        .obs-stat__label {{ font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; color: {muted}; margin-top: 0.2rem; }}
        .obs-subpanel {{ display: flex; flex-direction: column; gap: 0.6rem; }}
        .obs-subpanel input, .obs-subpanel select, .obs-spec {{
            background-color: {surface_base};
            border: 1px solid {border};
            border-radius: {radius};
            color: {text};
            padding: 0.45rem 0.6rem;
            font-size: 0.9rem;
        }}
        .obs-spec {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; resize: vertical; }}
        .obs-run {{ align-self: flex-start; }}
        .obs-panel {{
            margin-top: 0.75rem;
            padding: 0.85rem;
            background-color: {surface_base};
            border: 1px solid {border};
            border-radius: {radius};
        }}
        .obs-panel h4 {{ margin: 0 0 0.5rem; font-size: 0.95rem; color: {text}; }}
        .obs-table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
        .obs-table th, .obs-table td {{
            text-align: left;
            padding: 0.35rem 0.5rem;
            border-bottom: 1px solid {border};
            vertical-align: top;
        }}
        .obs-table th {{ color: {muted}; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; }}
        .obs-payload {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-word; }}
        .obs-results {{ list-style: none; margin: 0.5rem 0 0; padding: 0; display: flex; flex-direction: column; gap: 0.2rem; }}
        .obs-results li {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.82rem;
            padding: 0.3rem 0.45rem;
            border-radius: 6px;
            background-color: {surface_raised};
            border: 1px solid {border};
            word-break: break-word;
        }}
        .obs-empty {{ color: {muted}; font-size: 0.85rem; }}
        .obs-msg {{ font-size: 0.85rem; color: {muted}; }}
        .obs-msg.is-error {{ color: #f87171; }}

        /* ---- design-system primitives (charts, tables, badges, tree, diff) ---- */
        .ds-chart {{ width: 100%; height: auto; display: block; overflow: visible; }}
        .ds-chart__line {{ stroke: {accent}; stroke-width: 1.5; vector-effect: non-scaling-stroke; }}
        .ds-chart__area {{ fill: {glow}; opacity: 0.5; }}
        .ds-chart__bar {{ fill: {accent}; opacity: 0.85; }}

        .ds-stat {{
            padding: 0.75rem 0.9rem;
            background-color: {surface_raised};
            border: 1px solid {border};
            border-radius: {radius};
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
        }}
        .ds-stat__head {{ display: flex; align-items: center; gap: 0.4rem; justify-content: space-between; }}
        .ds-stat__label {{ color: {muted}; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .ds-stat__value {{ color: {text}; font-size: 1.6rem; font-weight: 650; letter-spacing: -0.02em; }}

        .ds-dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex: none; }}
        .ds-badge {{
            display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px;
            font-size: 0.72rem; font-weight: 600; border: 1px solid transparent;
            white-space: nowrap;
        }}
        .ds-dot--neutral, .ds-badge--neutral {{ background-color: rgba(148,163,184,0.18); color: #cbd5e1; border-color: rgba(148,163,184,0.35); }}
        .ds-dot--neutral {{ background-color: #94a3b8; }}
        .ds-dot--info, .ds-badge--info {{ background-color: rgba(94,106,210,0.18); color: #a5b4fc; border-color: rgba(94,106,210,0.4); }}
        .ds-dot--info {{ background-color: {accent}; }}
        .ds-dot--success, .ds-badge--success {{ background-color: rgba(34,197,94,0.16); color: #86efac; border-color: rgba(34,197,94,0.4); }}
        .ds-dot--success {{ background-color: #22c55e; }}
        .ds-dot--warn, .ds-badge--warn {{ background-color: rgba(234,179,8,0.16); color: #fde047; border-color: rgba(234,179,8,0.4); }}
        .ds-dot--warn {{ background-color: #eab308; }}
        .ds-dot--danger, .ds-badge--danger {{ background-color: rgba(248,113,113,0.16); color: #fca5a5; border-color: rgba(248,113,113,0.4); }}
        .ds-dot--danger {{ background-color: #f87171; }}

        .ds-tabs {{ display: flex; gap: 0.25rem; border-bottom: 1px solid {border}; margin-bottom: 0.9rem; flex-wrap: wrap; }}
        .ds-tab {{
            background: none; border: none; border-bottom: 2px solid transparent;
            color: {muted}; padding: 0.5rem 0.85rem; cursor: pointer; font-size: 0.85rem;
            font-weight: 550; {transition}
        }}
        .ds-tab:hover {{ color: {text}; }}
        .ds-tab.is-active {{ color: {text}; border-bottom-color: {accent}; }}

        .wizard-steps {{
            display: flex; gap: 0.5rem; flex-wrap: wrap; list-style: none;
            padding: 0; margin: 0 0 0.9rem 0; font-size: 0.8rem;
        }}
        .wizard-step {{
            color: {muted}; padding: 0.25rem 0.6rem; border-radius: 999px;
            border: 1px solid {border}; {transition}
        }}
        .wizard-step.is-done {{ color: {text}; border-color: {accent}; opacity: 0.75; }}
        .wizard-step.is-active {{ color: {text}; border-color: {accent}; background: {glow}; font-weight: 600; }}

        .ds-table-wrap {{ display: flex; flex-direction: column; gap: 0.5rem; }}
        .ds-table__filter {{
            align-self: flex-start; min-width: 12rem; padding: 0.4rem 0.6rem;
            background-color: {surface_base}; color: {text};
            border: 1px solid {border}; border-radius: 8px; font-size: 0.82rem;
        }}
        .ds-table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
        .ds-table th, .ds-table td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid {border}; vertical-align: top; }}
        .ds-table th {{ color: {muted}; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; cursor: pointer; user-select: none; white-space: nowrap; }}
        .ds-table th:hover {{ color: {text}; }}
        .ds-table tbody tr:hover {{ background-color: {surface_raised}; }}
        .ds-empty {{ color: {muted}; font-size: 0.85rem; }}

        .ds-drawer {{ position: fixed; inset: 0; z-index: 40; }}
        .ds-drawer__scrim {{ position: absolute; inset: 0; background: rgba(0,0,0,0.5); }}
        .ds-drawer__panel {{
            position: absolute; top: 0; right: 0; height: 100%; width: min(560px, 92vw);
            background-color: {surface_base}; border-left: 1px solid {border};
            box-shadow: {shadow_elevated}; display: flex; flex-direction: column;
            animation: ds-slide-in 250ms {motion_easing};
        }}
        @keyframes ds-slide-in {{ from {{ transform: translateX(24px); opacity: 0; }} to {{ transform: none; opacity: 1; }} }}
        .ds-drawer__head {{ display: flex; align-items: center; justify-content: space-between; padding: 0.9rem 1.1rem; border-bottom: 1px solid {border}; }}
        .ds-drawer__head h3 {{ margin: 0; font-size: 1rem; }}
        .ds-drawer__x {{ background: none; border: none; color: {muted}; font-size: 1rem; cursor: pointer; }}
        .ds-drawer__x:hover {{ color: {text}; }}
        .ds-drawer__body {{ padding: 1.1rem; overflow: auto; }}

        .ds-code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.8rem; background-color: {surface_base}; border: 1px solid {border};
            border-radius: {radius}; padding: 0.75rem; overflow: auto; max-height: 60vh;
            white-space: pre; color: {text};
        }}
        .ds-diff {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            font-size: 0.8rem; background-color: {surface_base}; border: 1px solid {border};
            border-radius: {radius}; padding: 0.5rem 0; overflow: auto; max-height: 60vh; margin: 0;
        }}
        .ds-diff__line {{ padding: 0 0.75rem; white-space: pre; }}
        .ds-diff__sign {{ display: inline-block; width: 1ch; margin-right: 0.5rem; opacity: 0.7; }}
        .ds-diff__line.is-add {{ background-color: rgba(34,197,94,0.12); color: #bbf7d0; }}
        .ds-diff__line.is-del {{ background-color: rgba(248,113,113,0.12); color: #fecaca; }}
        .ds-diff__line.is-same {{ color: {muted}; }}

        .ds-tree, .ds-tree ul {{ list-style: none; margin: 0; padding-left: 1.1rem; }}
        .ds-tree {{ padding-left: 0; font-size: 0.85rem; }}
        .ds-tree__leaf, .ds-tree summary {{ display: flex; align-items: center; gap: 0.4rem; padding: 0.15rem 0; }}
        .ds-tree summary {{ cursor: pointer; }}
        .ds-tree summary::-webkit-details-marker {{ color: {muted}; }}

        /* ---- resources console ---- */
        .res-toolbar {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; margin-bottom: 0.6rem; }}
        .res-toolbar select {{
            padding: 0.4rem 0.6rem; background-color: {surface_base}; color: {text};
            border: 1px solid {border}; border-radius: 8px; font-size: 0.82rem;
        }}
        .res-openrow {{ display: flex; flex-wrap: wrap; gap: 0.35rem; margin-top: 0.5rem; }}
        .res-change h4 {{ margin: 0.9rem 0 0.4rem; }}
        .res-verdict {{ display: flex; align-items: center; gap: 0.75rem; margin: 0.75rem 0; }}
        .res-health {{ display: flex; align-items: center; gap: 0.6rem; margin: 0 0 0.75rem; }}
        .res-health__summary {{ color: {muted}; font-size: 0.85rem; }}

        /* ---- node-link graph (trust) ---- */
        .ds-graph {{ width: 100%; height: auto; max-height: 60vh; display: block; }}
        .ds-graph__edge {{ stroke: {border}; stroke-width: 1.2; }}
        .ds-graph__arrow {{ fill: {muted}; }}
        .ds-graph__node {{ fill: {accent}; stroke: {surface_base}; stroke-width: 2; }}
        .ds-graph__nlabel {{ fill: {text}; font-size: 11px; text-anchor: middle; }}
        .ds-graph__elabel {{ fill: {muted}; font-size: 9px; text-anchor: middle; }}

        /* ---- overview KPI band ---- */
        .ov-kpis {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.75rem; margin-bottom: 1rem;
        }}

        /* ---- command palette (Cmd/Ctrl-K) ---- */
        .cmdk {{ position: fixed; inset: 0; z-index: 60; display: flex; align-items: flex-start; justify-content: center; }}
        .cmdk__scrim {{ position: absolute; inset: 0; background: rgba(0,0,0,0.55); }}
        .cmdk__panel {{
            position: relative; margin-top: 12vh; width: min(560px, 92vw);
            background-color: {surface_raised}; border: 1px solid {border};
            border-radius: {radius}; box-shadow: {shadow_elevated}; overflow: hidden;
            animation: ds-slide-in 180ms {motion_easing};
        }}
        .cmdk__input {{
            width: 100%; border: none; border-bottom: 1px solid {border};
            background-color: {surface_base}; color: {text}; font-size: 1rem;
            padding: 0.9rem 1.1rem; outline: none;
        }}
        .cmdk__list {{ list-style: none; margin: 0; padding: 0.35rem; max-height: 50vh; overflow: auto; }}
        .cmdk__item {{
            display: flex; align-items: center; justify-content: space-between;
            padding: 0.55rem 0.75rem; border-radius: 8px; cursor: pointer;
        }}
        .cmdk__item:hover {{ background-color: {surface_overlay}; }}
        .cmdk__label {{ color: {text}; font-size: 0.9rem; }}
        .cmdk__hint {{ color: {muted}; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        .cmdk__empty {{ color: {muted}; padding: 0.75rem; font-size: 0.85rem; }}

        /* ---- toast stack (transient notifications, corner overlay) ---- */
        .pillar-toaststack {{
            position: fixed; right: 1rem; bottom: 1rem; z-index: 70;
            display: flex; flex-direction: column; gap: 0.5rem;
            max-width: 24rem;
        }}
        .pillar-toast {{
            display: flex; align-items: flex-start; gap: 0.5rem;
            padding: 0.6rem 0.75rem; border-radius: {radius};
            background: {surface_overlay}; color: {text};
            border: 1px solid {border};
            box-shadow: {shadow_elevated};
            font-size: 0.85rem;
        }}
        .pillar-toast.is-info {{ border-left: 3px solid {accent}; }}
        .pillar-toast.is-success {{ border-left: 3px solid {accent}; }}
        .pillar-toast.is-warning {{ border-left: 3px solid {accent_hover}; }}
        .pillar-toast.is-error {{ border-left: 3px solid #e5484d; }}
        .pillar-toast__text {{ flex: 1; }}
        .pillar-toast__dismiss {{
            background: none; border: none; color: {muted};
            cursor: pointer; font-size: 1rem; line-height: 1; padding: 0;
        }}
        .pillar-toast__dismiss:hover {{ color: {text}; }}

        /* ---- prefers-reduced-motion fallback (covers scoped styles too) ---- */
        @media (prefers-reduced-motion: reduce) {{
            *, *::before, *::after {{
                transition: none !important;
                animation: none !important;
            }}
        }}
        "#,
        surface_base = theme.surface_base,
        surface_raised = theme.surface_raised,
        surface_overlay = theme.surface_overlay,
        border = theme.border_subtle,
        radius = theme.radius,
        text = theme.text_primary,
        muted = theme.text_muted,
        accent = theme.accent,
        accent_hover = theme.accent_hover,
        glow = theme.accent_glow,
        shadow_resting = theme.shadow_resting,
        shadow_elevated = theme.shadow_elevated,
        motion_easing = theme.motion_easing,
        transition = transition,
    )
}

/// A card surface with a mouse-tracking spotlight. The spotlight is a radial
/// gradient positioned from two CSS custom properties (`--spot-x`/`--spot-y`)
/// the component updates on `mousemove`; under reduced motion the tracking
/// transition is dropped (the gradient still renders, it just does not animate).
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn card_spotlight(theme: &Theme, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let css = format!(
        r#"
        position: relative;
        background-color: {surface};
        border: 1px solid {border};
        border-radius: {radius};
        box-shadow: {shadow};
        color: {text};
        padding: 1.25rem;
        overflow: hidden;
        {transition}

        &::before {{
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background: radial-gradient(
                240px circle at var(--spot-x, 50%) var(--spot-y, 50%),
                {glow},
                transparent 60%
            );
            opacity: 0;
            {transition}
        }}

        &:hover {{
            box-shadow: {shadow_hover};
        }}

        &:hover::before {{
            opacity: 1;
        }}
        "#,
        surface = theme.surface_raised,
        border = theme.border_subtle,
        radius = theme.radius,
        shadow = theme.shadow_resting,
        shadow_hover = theme.shadow_elevated,
        text = theme.text_primary,
        glow = theme.accent_glow,
        transition = transition,
    );
    Style::new(css).expect("card_spotlight css parses")
}

/// The visual variants a [`button`] can take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonVariant {
    /// Solid indigo accent — the primary call to action.
    Primary,
    /// A quiet raised surface button.
    Secondary,
    /// Text-only, no fill, for tertiary actions.
    Ghost,
}

/// A button style for the given [`ButtonVariant`]. Every variant shares the
/// radius, the micro-interaction transition, and a subtle lift on hover; the
/// fill/border/text differ per variant. Reduced motion drops the transition.
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn button(theme: &Theme, variant: ButtonVariant, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let (bg, border, text, bg_hover) = match variant {
        ButtonVariant::Primary => (
            theme.accent.to_string(),
            theme.accent.to_string(),
            "#ffffff".to_string(),
            theme.accent_hover.to_string(),
        ),
        ButtonVariant::Secondary => (
            theme.surface_overlay.to_string(),
            theme.border_subtle.to_string(),
            theme.text_primary.to_string(),
            theme.surface_raised.to_string(),
        ),
        ButtonVariant::Ghost => (
            "transparent".to_string(),
            "transparent".to_string(),
            theme.text_muted.to_string(),
            theme.surface_raised.to_string(),
        ),
    };
    let css = format!(
        r#"
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 0.5rem;
        font: inherit;
        font-weight: 600;
        line-height: 1;
        padding: 0.55rem 0.95rem;
        border-radius: {radius};
        border: 1px solid {border};
        background-color: {bg};
        color: {text};
        cursor: pointer;
        {transition}

        &:hover {{
            background-color: {bg_hover};
            transform: translateY(-1px);
        }}

        &:active {{
            transform: translateY(0);
        }}

        &:focus-visible {{
            outline: 2px solid {accent};
            outline-offset: 2px;
        }}

        &:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }}
        "#,
        radius = theme.radius,
        border = border,
        bg = bg,
        text = text,
        bg_hover = bg_hover,
        accent = theme.accent,
        transition = transition,
    );
    Style::new(css).expect("button css parses")
}

/// A text input style: a raised inset field that glows with the accent when
/// focused. Reduced motion drops the focus transition.
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn input(theme: &Theme, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let css = format!(
        r#"
        width: 100%;
        box-sizing: border-box;
        font: inherit;
        color: {text};
        background-color: {surface};
        border: 1px solid {border};
        border-radius: {radius};
        padding: 0.55rem 0.75rem;
        {transition}

        &::placeholder {{
            color: {muted};
        }}

        &:focus {{
            outline: none;
            border-color: {accent};
            box-shadow: 0 0 0 3px {glow};
        }}
        "#,
        text = theme.text_primary,
        surface = theme.surface_base,
        border = theme.border_subtle,
        radius = theme.radius,
        muted = theme.text_muted,
        accent = theme.accent,
        glow = theme.accent_glow,
        transition = transition,
    );
    Style::new(css).expect("input css parses")
}

/// A dialog surface: the topmost overlay layer with the strongest shadow and a
/// scale/fade entrance animation. Reduced motion suppresses the entrance
/// animation entirely (the dialog simply appears).
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn dialog(theme: &Theme, motion: Motion) -> Style {
    // The entrance is an @keyframes animation; under reduced motion we emit no
    // `animation` declaration and no keyframes at all.
    let (animation, keyframes) = match motion {
        Motion::Full => (
            motion.animation(&format!(
                "pillar-dialog-in {} {} both",
                theme.motion_duration, theme.motion_easing
            )),
            r#"
            @keyframes pillar-dialog-in {
                from { opacity: 0; transform: translateY(8px) scale(0.98); }
                to   { opacity: 1; transform: translateY(0) scale(1); }
            }
            "#
            .to_string(),
        ),
        Motion::Reduced => (String::new(), String::new()),
    };
    let css = format!(
        r#"
        background-color: {surface};
        border: 1px solid {border};
        border-radius: {radius};
        box-shadow: {shadow};
        color: {text};
        padding: 1.5rem;
        max-width: 32rem;
        width: 100%;
        {animation}
        {keyframes}
        "#,
        surface = theme.surface_overlay,
        border = theme.border_subtle,
        radius = theme.radius,
        shadow = theme.shadow_elevated,
        text = theme.text_primary,
        animation = animation,
        keyframes = keyframes,
    );
    Style::new(css).expect("dialog css parses")
}

/// A combobox / typeahead popover style: the input plus a floating results list
/// on the overlay layer. The list fades/slides in; reduced motion drops that.
///
/// # Panics
/// Panics only if the internal, static CSS fails to parse (a compile-time bug).
#[must_use]
pub fn combobox(theme: &Theme, motion: Motion) -> Style {
    let transition = motion.transition(&theme.micro_transition());
    let css = format!(
        r#"
        position: relative;

        & .pillar-combobox__list {{
            position: absolute;
            top: calc(100% + 4px);
            left: 0;
            right: 0;
            z-index: 20;
            list-style: none;
            margin: 0;
            padding: 0.25rem;
            background-color: {surface};
            border: 1px solid {border};
            border-radius: {radius};
            box-shadow: {shadow};
            {transition}
        }}

        & .pillar-combobox__option {{
            padding: 0.45rem 0.6rem;
            border-radius: 6px;
            color: {text};
            cursor: pointer;
            {transition}
        }}

        & .pillar-combobox__option[aria-selected="true"],
        & .pillar-combobox__option:hover {{
            background-color: {accent};
            color: #ffffff;
        }}
        "#,
        surface = theme.surface_overlay,
        border = theme.border_subtle,
        radius = theme.radius,
        shadow = theme.shadow_elevated,
        text = theme.text_primary,
        accent = theme.accent,
        transition = transition,
    );
    Style::new(css).expect("combobox css parses")
}

#[cfg(test)]
mod global_parse_tests {
    use super::*;
    use crate::theme::{Motion, Theme};

    /// The global stylesheet is fed to stylist's `<Global>` at runtime, whose
    /// parser is far stricter than a browser's. A rule stylist rejects panics
    /// the whole app on mount (a blank page), and no `format!`/contains test
    /// catches it. So parse the real sheet exactly as the app does.
    #[test]
    fn global_stylesheet_parses_in_stylist() {
        for motion in [Motion::Full, Motion::Reduced] {
            let css = global(&Theme::dark(), motion);
            if let Err(e) = stylist::Style::new(css.clone()) {
                // Surface the offending region to make the failure actionable.
                for (i, line) in css.lines().enumerate() {
                    eprintln!("{:4} | {}", i + 1, line);
                }
                panic!("global() css rejected by stylist ({motion:?}): {e}");
            }
        }
    }
}
