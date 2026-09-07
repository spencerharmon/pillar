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
use crate::panels::{Panel, ALL_PANELS};
#[cfg(feature = "yew")]
use yew::prelude::*;
#[cfg(feature = "yew")]
use yew_router::prelude::*;

/// The app shell's route table.
#[cfg_attr(feature = "yew", derive(yew_router::Routable))]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Route {
    /// The public landing page.
    #[cfg_attr(feature = "yew", at("/"))]
    Home,
    /// The login screen.
    #[cfg_attr(feature = "yew", at("/login"))]
    Login,
    /// A protected panel — stands in for the real per-panel routes each
    /// panel task adds; every one of them is protected the same way.
    #[cfg_attr(feature = "yew", at("/dashboard"))]
    Dashboard,
    /// Unmatched path.
    #[cfg_attr(feature = "yew", not_found)]
    #[cfg_attr(feature = "yew", at("/404"))]
    NotFound,
}

impl Route {
    /// Whether this route requires an active [`AuthSession`] to render.
    pub fn requires_auth(&self) -> bool {
        matches!(self, Route::Dashboard)
    }
}

/// The redirect-to-login guard: given the requested route and the current
/// session, returns the EFFECTIVE route to render — `Route::Login` for a
/// protected route with no active session, else the requested route
/// unchanged. Applied on every render (including a `401` that cleared the
/// session mid-session, via [`crate::auth::AuthAction::Unauthorized`]).
pub fn guard(route: Route, session: &AuthSession) -> Route {
    if route.requires_auth() && !session.is_authenticated() {
        Route::Login
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
    match guard(props.route.clone(), &session) {
        Route::Home => html! { <p>{ "pillar portal" }</p> },
        Route::Login => html! { <LoginPanel /> },
        Route::Dashboard => html! {
            <div>
                { for ALL_PANELS.iter().map(|spec| html! { <Panel spec={*spec} /> }) }
            </div>
        },
        Route::NotFound => html! { <p>{ "not found" }</p> },
    }
}

#[cfg(feature = "yew")]
/// The application shell: an [`AuthProvider`] wrapping a `yew_router`
/// `BrowserRouter`/`Switch` gated by [`guard`]. Every panel mounts under this.
#[function_component(Shell)]
pub fn shell() -> Html {
    html! {
        <AuthProvider>
            <BrowserRouter>
                <Switch<Route> render={switch} />
            </BrowserRouter>
        </AuthProvider>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{reduce, AuthAction};

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
            },
        );
        // Logged in: the protected route now renders as itself.
        assert_eq!(guard(Route::Dashboard, &session), Route::Dashboard);
        // Simulate navigating to a second route: the SAME session object is
        // reused (a route change never re-derives the session), so it is
        // still authenticated for the new route too.
        assert!(session.is_authenticated());
        assert_eq!(guard(Route::Home, &session), Route::Home);
        assert_eq!(guard(Route::Dashboard, &session), Route::Dashboard);
    }

    #[test]
    fn a_401_unauthorized_reverts_a_protected_route_to_login() {
        let session = AuthSession::default();
        let session = reduce(
            &session,
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
            },
        );
        assert_eq!(guard(Route::Dashboard, &session), Route::Dashboard);
        // A 401 anywhere clears the session; the SAME route now redirects.
        let session = reduce(&session, AuthAction::Unauthorized);
        assert_eq!(guard(Route::Dashboard, &session), Route::Login);
    }
}
