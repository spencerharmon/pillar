//! The **console shell**: the persistent navigable frame (left section-nav
//! sidebar + top bar + a routed content area) that turns the authenticated
//! portal from a single stacked scroll-page into a real multi-section cloud
//! console.
//!
//! The [`Section`] model and its route/label/grouping metadata are **pure,
//! host-testable** Rust (no `web-sys`/DOM): the section list, their URL paths,
//! and the sidebar grouping are asserted with a plain `cargo test`. The
//! [`ConsoleView`] component (behind the `yew` feature) is the thin wiring that
//! renders the frame and mounts the already-built per-capability tiles
//! ([`crate::portal`]) into the active section — every tile is reused verbatim,
//! never reimplemented.

/// A sidebar grouping of related [`Section`]s — the console's top-level
/// navigation structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NavGroup {
    /// Node overview + workload/resource management.
    Compute,
    /// Metrics/logs/traces/profiles/metadata + dashboards + drilldown.
    Observability,
    /// Failure-domain / topology tree.
    Topology,
    /// The signed-in user's OWN account: profile, password, security keys,
    /// sessions, identity. Self-service only.
    Account,
    /// Administering OTHER principals: users, roles, groups, OAuth clients,
    /// trust graph. Gated on `iam:*` capabilities (enforced server-side).
    Administration,
    /// Swarm membership + bootstrap requests — cluster-level admin.
    Cluster,
}

impl NavGroup {
    /// The human-facing group heading shown above its sections in the sidebar.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            NavGroup::Compute => "Compute",
            NavGroup::Observability => "Observability",
            NavGroup::Topology => "Topology",
            NavGroup::Account => "Account",
            NavGroup::Administration => "Administration",
            NavGroup::Cluster => "Cluster",
        }
    }

    /// The groups in sidebar render order.
    #[must_use]
    pub const fn all() -> [NavGroup; 6] {
        [
            NavGroup::Compute,
            NavGroup::Observability,
            NavGroup::Topology,
            NavGroup::Account,
            NavGroup::Administration,
            NavGroup::Cluster,
        ]
    }
}

/// One navigable console section. Each maps 1:1 to a protected route
/// ([`crate::router::Route`]) and to the capability tile mounted in the content
/// area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// Node status + at-a-glance landing (the console home).
    Overview,
    /// Workload / resource inventory + lifecycle (get/apply/scale/rollout).
    Resources,
    /// Declarative resource groups (ArgoCD-Application analog): ResourceSets +
    /// their health/sync + interconnected resource graph.
    ResourceSets,
    /// The five-signal observability console.
    Observability,
    /// Failure-domain / topology explorer.
    Topology,
    /// The signed-in user's OWN account hub: a single tabbed page over the
    /// self-service surfaces (profile, password, security keys, sessions,
    /// identity). Replaces four separate sidebar entries with one "Account"
    /// destination — the folded sections stay routable (deep links) but are
    /// hidden from the sidebar (see [`Section::in_sidebar`]).
    Account,
    /// This user's identity, domains, enrollment.
    Identity,
    /// Cell members administration.
    Members,
    /// Active sessions + revocation.
    Sessions,
    /// This user's WebAuthn security keys / passkeys (list / enroll / revoke).
    Credentials,
    /// Web-of-Trust graph + attestation/custody builders.
    Trust,
    /// libp2p swarm identity + mint.
    Swarm,
    /// Node/user bootstrap request inbox.
    Inbox,
    /// Self-service profile (display name / email).
    Profile,
    /// Admin user directory: invite/list/disable/enable/reset-password/
    /// require-password-change (`pillar-iam::user_record`).
    Users,
    /// Admin roles + managed groups (`pillar-iam::rbac_bridge`).
    RolesGroups,
    /// Admin OAuth client registry + consent (`pillar-oidc::client_registry`).
    OAuthClients,
}

impl Section {
    /// Every section in canonical (sidebar) order.
    #[must_use]
    pub const fn all() -> [Section; 17] {
        [
            Section::Overview,
            Section::Resources,
            Section::ResourceSets,
            Section::Observability,
            Section::Topology,
            Section::Account,
            Section::Identity,
            Section::Members,
            Section::Sessions,
            Section::Credentials,
            Section::Trust,
            Section::Swarm,
            Section::Inbox,
            Section::Profile,
            Section::Users,
            Section::RolesGroups,
            Section::OAuthClients,
        ]
    }

    /// The URL path this section is served at (matches the `#[at(...)]` on the
    /// corresponding [`crate::router::Route`] variant — kept in lock-step by
    /// [`Section::route`] and the round-trip test).
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Section::Overview => "/overview",
            Section::Resources => "/resources",
            Section::ResourceSets => "/resource-sets",
            Section::Observability => "/observability",
            Section::Topology => "/topology",
            Section::Account => "/account",
            Section::Identity => "/identity",
            Section::Members => "/members",
            Section::Sessions => "/sessions",
            Section::Credentials => "/credentials",
            Section::Trust => "/trust",
            Section::Swarm => "/swarm",
            Section::Inbox => "/inbox",
            Section::Profile => "/profile",
            Section::Users => "/users",
            Section::RolesGroups => "/roles-groups",
            Section::OAuthClients => "/oauth-clients",
        }
    }

    /// The sidebar label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Section::Overview => "Overview",
            Section::Resources => "Resources",
            Section::ResourceSets => "Resource Sets",
            Section::Observability => "Observability",
            Section::Topology => "Topology",
            Section::Account => "Account",
            Section::Identity => "Identity",
            Section::Members => "Members",
            Section::Sessions => "Sessions",
            Section::Credentials => "Security Keys",
            Section::Trust => "Trust Graph",
            Section::Swarm => "Swarm",
            Section::Inbox => "Requests",
            Section::Profile => "Profile",
            Section::Users => "Users",
            Section::RolesGroups => "Roles & Groups",
            Section::OAuthClients => "OAuth Clients",
        }
    }

    /// A short monochrome glyph used as the nav icon (no icon-font dependency;
    /// a single Unicode symbol themed by the surrounding CSS).
    #[must_use]
    pub const fn glyph(self) -> &'static str {
        match self {
            Section::Overview => "◎",
            Section::Resources => "▣",
            Section::ResourceSets => "❖",
            Section::Observability => "∿",
            Section::Topology => "⧉",
            Section::Account => "⚙",
            Section::Identity => "⬡",
            Section::Members => "☰",
            Section::Sessions => "⏻",
            Section::Credentials => "⚿",
            Section::Trust => "⤳",
            Section::Swarm => "⟁",
            Section::Inbox => "✉",
            Section::Profile => "☺",
            Section::Users => "◈",
            Section::RolesGroups => "⚑",
            Section::OAuthClients => "⚷",
        }
    }

    /// Which sidebar group this section is filed under.
    #[must_use]
    pub const fn group(self) -> NavGroup {
        match self {
            Section::Overview | Section::Resources => NavGroup::Compute,
            Section::ResourceSets => NavGroup::Compute,
            Section::Observability => NavGroup::Observability,
            Section::Topology => NavGroup::Topology,
            // The signed-in user's own account (self-service).
            Section::Account
            | Section::Identity
            | Section::Sessions
            | Section::Credentials
            | Section::Profile => NavGroup::Account,
            // Administering other principals (capability-gated server-side).
            Section::Members
            | Section::Trust
            | Section::Users
            | Section::RolesGroups
            | Section::OAuthClients => NavGroup::Administration,
            Section::Swarm | Section::Inbox => NavGroup::Cluster,
        }
    }

    /// Whether this section is shown as its OWN link in the sidebar. The four
    /// self-service surfaces (`Profile`, `Identity`, `Sessions`,
    /// `Credentials`) are folded into the single [`Section::Account`] hub as
    /// tabs, so they are hidden here while remaining routable for deep links
    /// (their `#[at(...)]` routes still render the tile standalone). Every
    /// other section is a first-class sidebar entry.
    #[must_use]
    pub const fn in_sidebar(self) -> bool {
        !matches!(
            self,
            Section::Profile | Section::Identity | Section::Sessions | Section::Credentials
        )
    }
}

#[cfg(feature = "yew")]
pub(crate) use yew_impl::section_route;
#[cfg(feature = "yew")]
pub use yew_impl::ConsoleView;

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{NavGroup, Section};
    use crate::attestation_custody_console::{AttestationWizard, CustodyWizard};
    use crate::auth::{use_auth, AuthAction};
    use crate::command_palette::CommandPalette;
    use crate::iam_console::{AccountHub, OAuthClientsTile, ProfileTile, RolesGroupsTile, UsersTile};
    use crate::obs_console::ObservabilityConsole;
    use crate::overview::OverviewConsole;
    use crate::portal::{
        CredentialsTile, IdentityTile, InboxTile, MembersTile, SessionsTile, SwarmTile,
    };
    use crate::resources_console::ResourcesConsole;
    use crate::resourcesets_console::ResourceSetsConsole;
    use crate::router::Route;
    use crate::topology_console::{TopologyConsole, TrustGraphConsole};
    use yew::prelude::*;
    use yew_router::prelude::*;

    /// Props for [`ConsoleView`]: the currently-active section (derived from the
    /// route by the router's switch).
    #[derive(Properties, PartialEq)]
    pub struct ConsoleViewProps {
        /// The section whose content fills the console's main area.
        pub section: Section,
    }

    /// The persistent console frame: a left section-nav sidebar, a top bar
    /// (identity + sign-out), and the active section's content. Rendered by the
    /// router for every authenticated section route, so navigating between
    /// sections swaps only the content area — the frame is stable.
    #[function_component(ConsoleView)]
    pub fn console_view(props: &ConsoleViewProps) -> Html {
        let auth = use_auth();
        let handle = auth.user.clone().unwrap_or_default();
        let active = props.section;
        let signout = {
            let auth = auth.clone();
            Callback::from(move |_: MouseEvent| auth.dispatch(AuthAction::Logout))
        };

        html! {
            <div class="console">
                <nav class="console-sidebar" aria-label="Sections">
                    <div class="console-brand">{ "pillar" }</div>
                    { for NavGroup::all().into_iter().map(|group| render_group(group, active)) }
                </nav>
                <div class="console-main">
                    <header class="console-topbar">
                        <div class="console-crumb">{ active.label() }</div>
                        <div class="console-topbar__right">
                            <span class="console-who" id="portal-who">
                                { format!("Signed in as {handle}") }
                            </span>
                            <button
                                type="button"
                                id="signout"
                                class="signout"
                                onclick={signout}
                            >{ "Sign out" }</button>
                        </div>
                    </header>
                    <main class="console-content" id="portal">
                        { render_section(active) }
                    </main>
                </div>
                <CommandPalette />
            </div>
        }
    }

    /// One sidebar group: its heading plus a nav link per section in the group.
    fn render_group(group: NavGroup, active: Section) -> Html {
        let items: Vec<Section> = Section::all()
            .into_iter()
            .filter(|s| s.group() == group && s.in_sidebar())
            .collect();
        html! {
            <div class="console-navgroup">
                <div class="console-navgroup__label">{ group.label() }</div>
                { for items.into_iter().map(|s| render_nav_link(s, active)) }
            </div>
        }
    }

    /// One sidebar nav link, marked `aria-current` when it is the active
    /// section.
    fn render_nav_link(section: Section, active: Section) -> Html {
        let is_active = section == active;
        let mut class = Classes::from("console-navlink");
        if is_active {
            class.push("is-active");
        }
        let current = if is_active { Some("page") } else { None };
        html! {
            <Link<Route> to={section_route(section)} classes={class}>
                <span class="console-navlink__glyph" aria-hidden="true">{ section.glyph() }</span>
                <span class="console-navlink__label" aria-current={current}>
                    { section.label() }
                </span>
            </Link<Route>>
        }
    }

    /// The active section's content: the already-built capability tile(s),
    /// mounted verbatim. The Overview pairs the node-status tile with a short
    /// orientation note; every other section mounts its one capability tile.
    fn render_section(section: Section) -> Html {
        match section {
            Section::Overview => html! { <OverviewConsole /> },
            Section::Resources => html! { <ResourcesConsole /> },
            Section::ResourceSets => html! { <ResourceSetsConsole /> },
            Section::Observability => html! { <ObservabilityConsole /> },
            Section::Topology => html! { <TopologyConsole /> },
            Section::Account => html! { <AccountHub /> },
            Section::Identity => html! { <IdentityTile /> },
            Section::Members => html! { <MembersTile /> },
            Section::Sessions => html! { <SessionsTile /> },
            Section::Credentials => html! { <CredentialsTile /> },
            Section::Trust => html! {
                <>
                    <TrustGraphConsole />
                    <AttestationWizard />
                    <CustodyWizard />
                </>
            },
            Section::Swarm => html! { <SwarmTile /> },
            Section::Inbox => html! { <InboxTile /> },
            Section::Profile => html! { <ProfileTile /> },
            Section::Users => html! { <UsersTile /> },
            Section::RolesGroups => html! { <RolesGroupsTile /> },
            Section::OAuthClients => html! { <OAuthClientsTile /> },
        }
    }

    /// Map a [`Section`] to its [`Route`] — the single place the two enums are
    /// bridged for `<Link>` targets. The host-side round-trip test
    /// ([`super::tests::section_paths_match_routes`]) pins that this agrees with
    /// [`Section::path`].
    pub(crate) fn section_route(section: Section) -> Route {
        match section {
            Section::Overview => Route::Overview,
            Section::Resources => Route::Resources,
            Section::ResourceSets => Route::ResourceSets,
            Section::Observability => Route::Observability,
            Section::Topology => Route::Topology,
            Section::Account => Route::Account,
            Section::Identity => Route::Identity,
            Section::Members => Route::Members,
            Section::Sessions => Route::Sessions,
            Section::Credentials => Route::Credentials,
            Section::Trust => Route::Trust,
            Section::Swarm => Route::Swarm,
            Section::Inbox => Route::Inbox,
            Section::Profile => Route::Profile,
            Section::Users => Route::Users,
            Section::RolesGroups => Route::RolesGroups,
            Section::OAuthClients => Route::OAuthClients,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NavGroup, Section};

    #[test]
    fn every_section_has_a_unique_path_and_label() {
        let sections = Section::all();
        for (i, a) in sections.iter().enumerate() {
            for b in &sections[i + 1..] {
                assert_ne!(a.path(), b.path(), "duplicate path {a:?}/{b:?}");
                assert_ne!(a.label(), b.label(), "duplicate label {a:?}/{b:?}");
                assert_ne!(a.glyph(), b.glyph(), "duplicate glyph {a:?}/{b:?}");
            }
            assert!(a.path().starts_with('/'), "{a:?} path not absolute");
        }
    }

    #[test]
    fn every_group_has_at_least_one_section_and_all_sections_are_grouped() {
        for group in NavGroup::all() {
            let n = Section::all()
                .into_iter()
                .filter(|s| s.group() == group)
                .count();
            assert!(n >= 1, "group {group:?} has no sections");
        }
        // Every section resolves to a group in the group list (total coverage).
        for s in Section::all() {
            assert!(
                NavGroup::all().contains(&s.group()),
                "section {s:?} group not in NavGroup::all()"
            );
        }
    }

    #[test]
    fn overview_is_the_first_section() {
        assert_eq!(Section::all()[0], Section::Overview);
        assert_eq!(Section::Overview.path(), "/overview");
    }

    #[test]
    fn account_group_shows_only_the_hub_and_hides_the_folded_self_sections() {
        // The four self-service surfaces are folded into the Account hub:
        // grouped under Account but HIDDEN from the sidebar (still routable so
        // their deep-link routes render the tile standalone).
        for s in [
            Section::Profile,
            Section::Identity,
            Section::Sessions,
            Section::Credentials,
        ] {
            assert_eq!(s.group(), NavGroup::Account, "{s:?} must be in the Account group");
            assert!(!s.in_sidebar(), "{s:?} must be hidden (folded into the Account hub)");
        }
        // The hub is the single visible Account entry.
        assert_eq!(Section::Account.group(), NavGroup::Account);
        assert!(Section::Account.in_sidebar());
        let visible = Section::all()
            .into_iter()
            .filter(|s| s.group() == NavGroup::Account && s.in_sidebar())
            .count();
        assert_eq!(visible, 1, "the Account group must show exactly one sidebar link (the hub)");
    }

    #[test]
    fn admin_sections_live_under_administration_and_are_visible() {
        for s in [
            Section::Users,
            Section::RolesGroups,
            Section::OAuthClients,
            Section::Members,
            Section::Trust,
        ] {
            assert_eq!(s.group(), NavGroup::Administration, "{s:?} must be an Administration section");
            assert!(s.in_sidebar(), "{s:?} must be a first-class sidebar link");
        }
    }

    /// Mount-audit (anti-facade DoD): the Account section must mount the
    /// `AccountHub` (the tabbed self-service hub), so a future edit can never
    /// silently drop it and strand the folded self-service tiles.
    #[test]
    fn console_mounts_the_account_hub_for_the_account_section() {
        let src = include_str!("console.rs");
        assert!(
            src.contains("Section::Account => html! { <AccountHub /> }"),
            "console.rs no longer mounts AccountHub for the Account section"
        );
    }

    /// Mount-audit (anti-facade DoD): the Trust section must mount BOTH guided
    /// wizards (`AttestationWizard`, `CustodyWizard`) alongside the trust graph,
    /// so a future edit can never silently drop them and re-orphan the wizard
    /// components built in `attestation_custody_console.rs`.
    #[test]
    fn trust_section_mounts_the_attestation_and_custody_wizards() {
        let src = include_str!("console.rs");
        assert!(
            src.contains("crate::attestation_custody_console::{AttestationWizard, CustodyWizard}"),
            "console.rs no longer imports the attestation/custody wizards"
        );
        assert!(
            src.contains("<AttestationWizard />"),
            "console.rs no longer mounts AttestationWizard in the Trust section"
        );
        assert!(
            src.contains("<CustodyWizard />"),
            "console.rs no longer mounts CustodyWizard in the Trust section"
        );
    }

    /// Mount-audit (anti-facade DoD): the ResourceSets section must mount the
    /// `ResourceSetsConsole` tile, so a future edit can never silently drop it
    /// and strand the DataTable-backed ResourceSet list.
    #[test]
    fn resourcesets_section_mounts_the_resourcesets_console() {
        let src = include_str!("console.rs");
        assert!(
            src.contains("Section::ResourceSets => html! { <ResourceSetsConsole /> }"),
            "console.rs no longer mounts ResourceSetsConsole for the ResourceSets section"
        );
    }
}
