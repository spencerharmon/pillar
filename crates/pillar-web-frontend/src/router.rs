//! The application shell's **client-side router**: the route table plus the
//! auth guard that redirects an unauthenticated request for a protected route
//! to the login screen.
//!
//! [`Route`] and [`guard`] are plain, host-testable logic (no `web-sys`/DOM
//! calls) so the redirect behavior is asserted with a native `cargo test`;
//! [`Shell`] is the thin Yew wiring (behind the `yew` feature) that mounts
//! [`crate::auth::AuthProvider`] + a `yew_router` `BrowserRouter`/`Switch` and
//! applies the guard on every render.

use crate::auth::AuthSession;

#[cfg(feature = "yew")]
use crate::auth::{use_auth, AuthProvider};
#[cfg(feature = "yew")]
use crate::components::LoginPanel;
#[cfg(feature = "yew")]
use crate::components::ToastProvider;
#[cfg(feature = "yew")]
#[cfg(feature = "yew")]
use crate::portal_entry::PortalEntry;
#[cfg(feature = "yew")]
use crate::theme::{Motion, Theme};
#[cfg(feature = "yew")]
use stylist::yew::Global;
#[cfg(feature = "yew")]
use yew::prelude::*;
#[cfg(feature = "yew")]
use yew_router::prelude::*;

/// The app shell's route table. Each authenticated section of the console is
/// its own protected route, so the browser URL reflects the active section and
/// deep-links work; the persistent frame ([`crate::console::ConsoleView`])
/// re-renders only its content area on a section change.
#[cfg_attr(feature = "yew", derive(yew_router::Routable))]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Route {
    /// The public landing page.
    #[cfg_attr(feature = "yew", at("/"))]
    Home,
    /// The login screen.
    #[cfg_attr(feature = "yew", at("/login"))]
    Login,
    /// Node status + at-a-glance console home.
    #[cfg_attr(feature = "yew", at("/overview"))]
    Overview,
    /// Workload / resource inventory + lifecycle.
    #[cfg_attr(feature = "yew", at("/resources"))]
    Resources,
    /// Declarative resource groups (ArgoCD-Application analog).
    #[cfg_attr(feature = "yew", at("/resource-sets"))]
    ResourceSets,
    /// The per-resource detail page (Overview/Manifest/Logs/Exec/Events tabs
    /// over `crate::resources_console::ResourceDetailPage`) — a real,
    /// deep-linkable route distinct from the inventory grid's drawer.
    #[cfg_attr(feature = "yew", at("/resources/:kind/:id"))]
    ResourceDetail {
        /// The resource kind path segment.
        kind: String,
        /// The resource name path segment.
        id: String,
    },
    /// The five-signal observability console.
    #[cfg_attr(feature = "yew", at("/observability"))]
    Observability,
    /// Failure-domain / topology explorer.
    #[cfg_attr(feature = "yew", at("/topology"))]
    Topology,
    /// This user's identity, domains, enrollment.
    #[cfg_attr(feature = "yew", at("/identity"))]
    Identity,
    /// Cell members administration.
    #[cfg_attr(feature = "yew", at("/members"))]
    Members,
    /// Active sessions + revocation.
    #[cfg_attr(feature = "yew", at("/sessions"))]
    Sessions,
    /// This user's WebAuthn security keys / passkeys (list / enroll / revoke).
    #[cfg_attr(feature = "yew", at("/credentials"))]
    Credentials,
    /// Web-of-Trust graph + attestation/custody builders.
    #[cfg_attr(feature = "yew", at("/trust"))]
    Trust,
    /// libp2p swarm identity + mint.
    #[cfg_attr(feature = "yew", at("/swarm"))]
    Swarm,
    /// Node/user bootstrap request inbox.
    #[cfg_attr(feature = "yew", at("/inbox"))]
    Inbox,
    /// Self-service profile (display name / email).
    #[cfg_attr(feature = "yew", at("/profile"))]
    Profile,
    /// Admin user directory (invite/list/disable/enable/reset/require-change).
    #[cfg_attr(feature = "yew", at("/users"))]
    Users,
    /// Admin roles + managed groups (`pillar-iam::rbac_bridge`).
    #[cfg_attr(feature = "yew", at("/roles-groups"))]
    RolesGroups,
    /// Admin OAuth client registry + consent (`pillar-oidc::client_registry`).
    #[cfg_attr(feature = "yew", at("/oauth-clients"))]
    OAuthClients,
    /// The forced password-change interstitial: intercepts every OTHER route
    /// while the session's `force_password_change` is set (see [`guard`]).
    #[cfg_attr(feature = "yew", at("/change-password"))]
    ChangePassword,
    /// Legacy alias for the old single-page portal — redirects to the
    /// [`Route::Overview`] console home so existing links keep working.
    #[cfg_attr(feature = "yew", at("/dashboard"))]
    Dashboard,
    /// Unmatched path.
    #[cfg_attr(feature = "yew", not_found)]
    #[cfg_attr(feature = "yew", at("/404"))]
    NotFound,
}

impl Route {
    /// Whether this route requires an active [`AuthSession`] to render. Every
    /// console section (and the legacy `/dashboard` alias) is protected; only
    /// the public landing, the login screen, and the not-found page are open.
    pub fn requires_auth(&self) -> bool {
        matches!(
            self,
            Route::Overview
                | Route::Resources
                | Route::ResourceSets
                | Route::ResourceDetail { .. }
                | Route::Observability
                | Route::Topology
                | Route::Identity
                | Route::Members
                | Route::Sessions
                | Route::Credentials
                | Route::Trust
                | Route::Swarm
                | Route::Inbox
                | Route::Profile
                | Route::Users
                | Route::RolesGroups
                | Route::OAuthClients
                | Route::ChangePassword
                | Route::Dashboard
        )
    }

    /// The [`crate::console::Section`] this route displays, if it is a console
    /// section route (the legacy `/dashboard` alias resolves to
    /// [`Section::Overview`]). Non-section routes (public/login/404) return
    /// `None`.
    pub fn section(&self) -> Option<crate::console::Section> {
        use crate::console::Section;
        Some(match self {
            Route::Overview | Route::Dashboard => Section::Overview,
            Route::Resources => Section::Resources,
            Route::ResourceSets => Section::ResourceSets,
            Route::Observability => Section::Observability,
            Route::Topology => Section::Topology,
            Route::Identity => Section::Identity,
            Route::Members => Section::Members,
            Route::Sessions => Section::Sessions,
            Route::Credentials => Section::Credentials,
            Route::Trust => Section::Trust,
            Route::Swarm => Section::Swarm,
            Route::Inbox => Section::Inbox,
            Route::Profile => Section::Profile,
            Route::Users => Section::Users,
            Route::RolesGroups => Section::RolesGroups,
            Route::OAuthClients => Section::OAuthClients,
            Route::Home | Route::Login | Route::NotFound | Route::ChangePassword => return None,
            // The detail page is not a `Section` — it renders its own page
            // directly (see `guarded` below), not the `ConsoleView` frame.
            Route::ResourceDetail { .. } => return None,
        })
    }
}

/// The redirect-to-login guard: given the requested route and the current
/// session, returns the EFFECTIVE route to render — `Route::Login` for a
/// protected route with no active session, `Route::ChangePassword` for ANY
/// other route while the session's `force_password_change` is set (the
/// `UserLifecycle.tla` `InvitedForcesChange` invariant, applied to routing:
/// an operator with a pending forced change cannot navigate away from it to
/// any other section), else the requested route unchanged. Applied on every
/// render (including a `401` that cleared the session mid-session, via
/// [`crate::auth::AuthAction::Unauthorized`]).
pub fn guard(route: Route, session: &AuthSession) -> Route {
    if route.requires_auth() && !session.is_authenticated() {
        // A protected route without a session falls back to the login screen.
        Route::Login
    } else if session.is_authenticated()
        && session.force_password_change
        && route != Route::ChangePassword
    {
        // A forced password change intercepts every other destination.
        Route::ChangePassword
    } else if session.is_authenticated() && matches!(route, Route::Home | Route::Login) {
        // An authenticated user has no business on the public entry / login
        // screens — send them to the console home so signing in (or reloading
        // `/`) lands ON the console, not the legacy single-page portal.
        Route::Overview
    } else {
        route
    }
}

#[cfg(feature = "yew")]
fn switch(route: Route) -> Html {
    html! { <Guarded route={route} /> }
}

#[cfg(feature = "yew")]
#[derive(Properties, PartialEq)]
struct GuardedProps {
    route: Route,
}

#[cfg(feature = "yew")]
/// Reads the ambient session, applies [`guard`], and renders the resulting
/// route's panel.
#[function_component(Guarded)]
fn guarded(props: &GuardedProps) -> Html {
    let session = use_auth();
    let effective = guard(props.route.clone(), &session);
    // A console section route renders the persistent frame with that section
    // active; the public/login/404 routes render their standalone screens.
    if let Some(section) = effective.section() {
        return html! { <crate::console::ConsoleView section={section} /> };
    }
    match effective {
        Route::Login => html! { <LoginPanel /> },
        Route::NotFound => html! { <p>{ "not found" }</p> },
        Route::ChangePassword => html! { <crate::iam_console::ChangePasswordPage /> },
        // The resource detail page is a real registered route, mounted
        // directly (not via `ConsoleView`'s `Section` dispatch) so
        // `crate::resources_console::ResourceDetailPage` is reachable at
        // `/resources/:kind/:id` from a plain deep link, not only the
        // inventory drawer.
        Route::ResourceDetail { kind, id } => {
            html! { <crate::resources_console::ResourceDetailPage kind={kind} id={id} /> }
        }
        // `Home` (and any route that resolved to `Login` above) — the public
        // landing / entry surface.
        _ => html! { <PortalEntry /> },
    }
}

#[cfg(feature = "yew")]
/// The application shell: the design-system `Theme`/`Motion` context (so every
/// component resolves the real tokens), the portal-wide [`crate::styles::global`]
/// stylesheet mounted once via `stylist::yew::Global` (so the bare-class
/// dashboard/login markup is themed), and an [`AuthProvider`] wrapping a
/// `yew_router` `BrowserRouter`/`Switch` gated by [`guard`]. Every panel mounts
/// under this.
#[function_component(Shell)]
pub fn shell() -> Html {
    // The dark theme + full motion are the app defaults; the global sheet's
    // `@media (prefers-reduced-motion: reduce)` guard honors the OS preference
    // live for both the global and the scoped component styles.
    let theme = Theme::dark();
    let motion = Motion::Full;
    html! {
        <ContextProvider<Theme> context={theme}>
            <ContextProvider<Motion> context={motion}>
                <Global css={crate::styles::global(&theme, motion)} />
                <AuthProvider>
                    <ToastProvider>
                        <BrowserRouter>
                            <Switch<Route> render={switch} />
                        </BrowserRouter>
                    </ToastProvider>
                </AuthProvider>
            </ContextProvider<Motion>>
        </ContextProvider<Theme>>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{reduce, AuthAction};
    use crate::console::Section;

    #[test]
    fn resource_detail_route_requires_auth_and_is_not_a_console_section() {
        let route = Route::ResourceDetail {
            kind: "Workload".to_owned(),
            id: "web".to_owned(),
        };
        assert!(route.requires_auth());
        // It renders its own page directly (see `guarded`), not a `Section`.
        assert_eq!(route.section(), None);
        let session = AuthSession::default();
        assert_eq!(guard(route, &session), Route::Login);
    }

    #[test]
    fn authenticated_resource_detail_route_preserves_its_kind_and_id() {
        let session = reduce(
            &AuthSession::default(),
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: false,
            },
        );
        let route = Route::ResourceDetail {
            kind: "Workload".to_owned(),
            id: "web".to_owned(),
        };
        assert_eq!(guard(route.clone(), &session), route);
    }

    /// Mount-audit (anti-facade DoD): the ROI's `/resources/:kind/:id` detail
    /// route must be a REAL registered route dispatching to a real component —
    /// not a `Section` shim only reachable from the drawer. This file's
    /// `guarded` match arm mounts `crate::resources_console::ResourceDetailPage`
    /// directly off `Route::ResourceDetail`; assert that reference on this
    /// module's own source so a future edit can never silently drop the mount.
    #[test]
    fn router_mounts_the_resource_detail_page_off_a_real_route() {
        let src = include_str!("router.rs");
        assert!(
            src.contains(r#"at("/resources/:kind/:id")"#),
            "router.rs no longer registers the /resources/:kind/:id route"
        );
        assert!(
            src.contains("crate::resources_console::ResourceDetailPage"),
            "router.rs no longer references ResourceDetailPage"
        );
        assert!(
            src.contains("<crate::resources_console::ResourceDetailPage"),
            "router.rs no longer mounts ResourceDetailPage from a route"
        );
    }

    #[test]
    fn unauthenticated_navigation_to_protected_route_redirects_to_login() {
        let session = AuthSession::default();
        assert_eq!(guard(Route::Dashboard, &session), Route::Login);
        // An unprotected route is unaffected.
        assert_eq!(guard(Route::Home, &session), Route::Home);
    }

    #[test]
    fn authenticated_session_persists_across_a_route_change() {
        let session = AuthSession::default();
        let session = reduce(
            &session,
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: false,
            },
        );
        // Logged in: the protected route now renders as itself.
        assert_eq!(guard(Route::Dashboard, &session), Route::Dashboard);
        // Simulate navigating to a second route: the SAME session object is
        // reused (a route change never re-derives the session), so it is
        // still authenticated for the new route too.
        assert!(session.is_authenticated());
        // An authenticated user on the public Home is sent to the console home
        // (see `authenticated_home_and_login_land_on_the_console`).
        assert_eq!(guard(Route::Home, &session), Route::Overview);
        assert_eq!(guard(Route::Dashboard, &session), Route::Dashboard);
    }

    #[test]
    fn authenticated_home_and_login_land_on_the_console() {
        let session = reduce(
            &AuthSession::default(),
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: false,
            },
        );
        // The public entry (`/`) and the login screen both redirect an
        // authenticated session onto the console home, so signing in — or
        // reloading `/` — lands ON the console, never the legacy single-page
        // portal. Regression guard for the "I don't see the console" facade gap.
        assert_eq!(guard(Route::Home, &session), Route::Overview);
        assert_eq!(guard(Route::Login, &session), Route::Overview);
        // And Overview resolves to the console section (not a redirect loop).
        assert_eq!(Route::Overview.section(), Some(Section::Overview));
    }

    #[test]
    fn unauthenticated_home_and_login_stay_on_their_public_screens() {
        let session = AuthSession::default();
        // No session: the entry and login screens render as themselves (no
        // redirect to the console, which would loop back to Login).
        assert_eq!(guard(Route::Home, &session), Route::Home);
        assert_eq!(guard(Route::Login, &session), Route::Login);
    }

    #[test]
    fn a_401_unauthorized_reverts_a_protected_route_to_login() {
        let session = AuthSession::default();
        let session = reduce(
            &session,
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: false,
            },
        );
        assert_eq!(guard(Route::Dashboard, &session), Route::Dashboard);
        // A 401 anywhere clears the session; the SAME route now redirects.
        let session = reduce(&session, AuthAction::Unauthorized);
        assert_eq!(guard(Route::Dashboard, &session), Route::Login);
    }

    #[test]
    fn a_forced_password_change_intercepts_every_other_route() {
        let session = reduce(
            &AuthSession::default(),
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: true,
            },
        );
        // Every protected destination — including the console home and the
        // legacy dashboard alias — is intercepted to the change-password
        // screen while the flag is set.
        assert_eq!(guard(Route::Overview, &session), Route::ChangePassword);
        assert_eq!(guard(Route::Dashboard, &session), Route::ChangePassword);
        assert_eq!(guard(Route::Users, &session), Route::ChangePassword);
        // Home/Login also resolve there (not to Overview) while forced.
        assert_eq!(guard(Route::Home, &session), Route::ChangePassword);
        assert_eq!(guard(Route::Login, &session), Route::ChangePassword);
        // The change-password route itself renders as itself (no loop).
        assert_eq!(
            guard(Route::ChangePassword, &session),
            Route::ChangePassword
        );
    }

    #[test]
    fn password_changed_lifts_the_forced_change_interception() {
        let session = reduce(
            &AuthSession::default(),
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: true,
            },
        );
        assert_eq!(guard(Route::Overview, &session), Route::ChangePassword);
        let session = reduce(&session, AuthAction::PasswordChanged);
        // The interception lifts; ordinary navigation resumes.
        assert_eq!(guard(Route::Overview, &session), Route::Overview);
        assert_eq!(guard(Route::Users, &session), Route::Users);
    }

    #[test]
    fn an_unauthenticated_session_is_never_forced_to_change_password() {
        // `force_password_change` is only meaningful for an authenticated
        // session; an unauthenticated request for the change-password route
        // still redirects to Login like any other protected route.
        let session = AuthSession::default();
        assert_eq!(guard(Route::ChangePassword, &session), Route::Login);
    }
}
