//! The application shell's **auth session context** — login state, the
//! current user, and the reducer every panel dispatches into on login/logout/
//! a `401 Unauthorized` response.
//!
//! [`AuthSession`] is plain, host-testable data (no `web-sys`/DOM calls), so
//! its transition logic is asserted with a native `cargo test`; [`AuthProvider`]
//! and [`use_auth`] are the thin Yew wiring (behind the `yew` feature) that
//! shares one [`AuthSession`] across every route/panel via context, so it
//! survives a route change instead of being re-derived per panel.

#[cfg(feature = "yew")]
use std::rc::Rc;

#[cfg(feature = "yew")]
use yew::prelude::*;

/// The current login state: `None` fields mean "not authenticated". Carries
/// the bearer token every subsequent API call sends as `X-Pillar-Session` and
/// the handle the session was admitted under (mirrors
/// `pillar-web-api::LoginResponse`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct AuthSession {
    /// The `X-Pillar-Session` bearer token, once logged in.
    pub token: Option<String>,
    /// The handle the session was admitted under.
    pub user: Option<String>,
}

impl AuthSession {
    /// Whether this session currently holds an active login.
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }
}

/// Actions every panel dispatches into the shared [`AuthSession`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthAction {
    /// A `POST /login` succeeded: admit the session under `user`/`token`.
    LoginSuccess {
        /// The handle the session was admitted under.
        user: String,
        /// The `X-Pillar-Session` bearer token.
        token: String,
    },
    /// Any API call came back `401 Unauthorized` — the session is no longer
    /// valid (expired/revoked). Clears the session; the router guard then
    /// redirects the current (now-unauthenticated) route to login.
    Unauthorized,
    /// An explicit logout.
    Logout,
}

#[cfg(feature = "yew")]
impl Reducible for AuthSession {
    type Action = AuthAction;

    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        match action {
            AuthAction::LoginSuccess { user, token } => Rc::new(AuthSession {
                token: Some(token),
                user: Some(user),
            }),
            AuthAction::Unauthorized | AuthAction::Logout => Rc::new(AuthSession::default()),
        }
    }
}

/// Applies an [`AuthAction`] to an [`AuthSession`] without a mounted Yew
/// runtime — the same transition [`Reducible::reduce`] performs under
/// `use_reducer`, kept callable directly so it is host-testable. `_session`
/// is unused: every action fully replaces the session rather than patching
/// it, exactly matching the `Reducible` impl above.
pub fn reduce(_session: &AuthSession, action: AuthAction) -> AuthSession {
    match action {
        AuthAction::LoginSuccess { user, token } => AuthSession {
            token: Some(token),
            user: Some(user),
        },
        AuthAction::Unauthorized | AuthAction::Logout => AuthSession::default(),
    }
}

#[cfg(feature = "yew")]
/// The shared auth context handle every panel reads/dispatches through.
pub type AuthContext = UseReducerHandle<AuthSession>;

#[cfg(feature = "yew")]
/// Props for [`AuthProvider`].
#[derive(Properties, PartialEq)]
pub struct AuthProviderProps {
    /// The subtree that shares this session — normally the whole router.
    #[prop_or_default]
    pub children: Html,
}

#[cfg(feature = "yew")]
/// Mounts one shared [`AuthSession`] via [`use_reducer`] and provides it to
/// every descendant through context, so a route change re-renders under the
/// SAME session state rather than a freshly defaulted one.
#[function_component(AuthProvider)]
pub fn auth_provider(props: &AuthProviderProps) -> Html {
    let session = use_reducer(AuthSession::default);
    html! {
        <ContextProvider<AuthContext> context={session}>
            { props.children.clone() }
        </ContextProvider<AuthContext>>
    }
}

#[cfg(feature = "yew")]
/// Reads the ambient [`AuthContext`]. Panics if no [`AuthProvider`] is
/// mounted above the caller — every route renders under one.
#[hook]
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>().expect("AuthProvider not mounted above this component")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_session_is_not_authenticated() {
        assert!(!AuthSession::default().is_authenticated());
    }

    #[test]
    fn login_success_admits_the_session() {
        let session = AuthSession::default();
        let session = reduce(
            &session,
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
            },
        );
        assert!(session.is_authenticated());
        assert_eq!(session.user.as_deref(), Some("alice"));
        assert_eq!(session.token.as_deref(), Some("tok-123"));
    }

    #[test]
    fn unauthorized_clears_an_admitted_session() {
        let session = AuthSession {
            token: Some("tok-123".to_string()),
            user: Some("alice".to_string()),
        };
        let session = reduce(&session, AuthAction::Unauthorized);
        assert!(!session.is_authenticated());
        assert_eq!(session.user, None);
    }

    #[test]
    fn logout_clears_an_admitted_session() {
        let session = AuthSession {
            token: Some("tok-123".to_string()),
            user: Some("alice".to_string()),
        };
        let session = reduce(&session, AuthAction::Logout);
        assert!(!session.is_authenticated());
    }
}
