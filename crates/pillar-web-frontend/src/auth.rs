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
    /// Whether this handle's `UserRecord::force_password_change` is set —
    /// mirrors the `pillar-iam` `UserLifecycle.tla` `InvitedForcesChange`
    /// invariant into the router: while `true`, `crate::router::guard`
    /// intercepts EVERY route to `Route::ChangePassword` regardless of the
    /// requested destination.
    pub force_password_change: bool,
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
    /// A `POST /login` succeeded: admit the session under `user`/`token`,
    /// carrying whether this handle currently has a forced password change
    /// pending (`UserRecord::force_password_change`, from the login
    /// response).
    LoginSuccess {
        /// The handle the session was admitted under.
        user: String,
        /// The `X-Pillar-Session` bearer token.
        token: String,
        /// Whether a password change is currently forced for this handle.
        force_password_change: bool,
    },
    /// Any API call came back `401 Unauthorized` — the session is no longer
    /// valid (expired/revoked). Clears the session; the router guard then
    /// redirects the current (now-unauthenticated) route to login.
    Unauthorized,
    /// An explicit logout.
    Logout,
    /// The forced password change completed: clears
    /// `force_password_change` on the CURRENT session (preserving
    /// `token`/`user`) so `crate::router::guard` stops redirecting to
    /// `Route::ChangePassword`.
    PasswordChanged,
}

#[cfg(feature = "yew")]
impl Reducible for AuthSession {
    type Action = AuthAction;

    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        match action {
            AuthAction::LoginSuccess {
                user,
                token,
                force_password_change,
            } => Rc::new(AuthSession {
                token: Some(token),
                user: Some(user),
                force_password_change,
            }),
            AuthAction::Unauthorized | AuthAction::Logout => Rc::new(AuthSession::default()),
            AuthAction::PasswordChanged => Rc::new(AuthSession {
                force_password_change: false,
                ..(*self).clone()
            }),
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
        AuthAction::LoginSuccess {
            user,
            token,
            force_password_change,
        } => AuthSession {
            token: Some(token),
            user: Some(user),
            force_password_change,
        },
        AuthAction::Unauthorized | AuthAction::Logout => AuthSession::default(),
        AuthAction::PasswordChanged => AuthSession {
            force_password_change: false,
            ..(_session).clone()
        },
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
                force_password_change: false,
            },
        );
        assert!(session.is_authenticated());
        assert_eq!(session.user.as_deref(), Some("alice"));
        assert_eq!(session.token.as_deref(), Some("tok-123"));
        assert!(!session.force_password_change);
    }

    #[test]
    fn login_success_carries_a_forced_password_change_flag() {
        let session = reduce(
            &AuthSession::default(),
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: true,
            },
        );
        assert!(session.force_password_change);
    }

    #[test]
    fn password_changed_clears_the_flag_but_preserves_the_session() {
        let session = reduce(
            &AuthSession::default(),
            AuthAction::LoginSuccess {
                user: "alice".to_string(),
                token: "tok-123".to_string(),
                force_password_change: true,
            },
        );
        let session = reduce(&session, AuthAction::PasswordChanged);
        assert!(!session.force_password_change);
        assert!(session.is_authenticated());
        assert_eq!(session.user.as_deref(), Some("alice"));
    }

    #[test]
    fn unauthorized_clears_an_admitted_session() {
        let session = AuthSession {
            token: Some("tok-123".to_string()),
            user: Some("alice".to_string()),
            force_password_change: false,
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
            force_password_change: false,
        };
        let session = reduce(&session, AuthAction::Logout);
        assert!(!session.is_authenticated());
    }
}
