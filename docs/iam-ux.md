# IAM console UX

How the IAM surface is presented in the web console. Complements
[user-management.md](user-management.md) (the *domain* model — lifecycle,
passwords, roles/groups, OIDC): this doc is the *presentation* contract for the
Yew frontend (`crates/pillar-web-frontend`). It records the information
architecture, the reusable primitives every IAM surface is built on, and the
deliberate deferrals so a reviewer can tell an intentional gap from a bug.

## Why

The first IAM console cut rendered every list as a `key=value` string dump in a
`<p>` tag and drove every mutation from a free-text "type the handle" form
disconnected from the list, with all self-service and administration surfaces
flattened into one nine-item sidebar group. This rework brings it in line with
best-in-class admin consoles (Okta / Entra / Auth0 / AWS IAM / Tailscale): an
object-centric *list → detail → act-in-context* flow, real tables with status
pills and chips, and a hard split between "my account" and "administering
others".

## Information architecture

The single `Identity & Access` sidebar group is split into two:

- **Account** (self-service). One tabbed hub — `Section::Account` at `/account`,
  rendering `AccountHub` — with tabs *Profile*, *Password*, *Security keys*,
  *Sessions*, *Identity*. The four previously-separate self sections
  (`Profile`/`Identity`/`Sessions`/`Credentials`) are **folded** into the hub:
  they stay routable for deep links (`Section::in_sidebar()` is `false` for
  them, so their `#[at(...)]` routes still render the tile standalone) but no
  longer clutter the sidebar. `Password` is a new self-service voluntary change
  (distinct from the forced-change interstitial `ChangePasswordPage`).
- **Administration** (managing other principals). First-class sidebar links:
  *Users*, *Roles & Groups*, *OAuth Clients*, *Members*, *Trust Graph*.

Enforcement of who may use the Administration surfaces stays **server-side**:
every sensitive mutation is gated by the shared `pillar_rbac` decider, surfaced
in the UI as a dry-run *prediction* (see below). The nav is not hidden by
capability (that is a deferral — see below), so a non-admin still sees the
links but the server refuses the acts.

## Reusable primitives

Built on the existing component library (`crates/pillar-web-frontend/src/
components`), extended where needed:

- **`DataTable`** — extended (backward-compatibly) with `render_cell` (custom
  per-cell rendering, e.g. a status column as a `StatusPill`, a roles column as
  chips — while sort/filter still run over the underlying cell *text*),
  `row_actions` (a trailing per-row action cell), `on_row_click` (row-select →
  open a detail drawer), and `empty_label` (a real empty state).
- **`StatusPill` / `Badge`** — status rendered as a toned pill; roles / scopes /
  capabilities as chips. (Design-system CSS for these primitives — and for
  `DataTable` and `Tabs` — was added to the global sheet; they previously
  rendered unstyled, which also improves `obs_console`.)
- **`Drawer`** — the user detail slide-over.
- **`Tabs`** — the Account hub, and the Roles/Groups and Clients/Consents splits.
- **`SecretReveal`** (new) — a show-once secret surface (masked + reveal toggle
  + copy + "shown only once" warning) for an invite/reset temp password and a
  freshly-registered OAuth client secret.
- **`ToastStack` / `use_toaster`** — success/error feedback replaces the old
  trailing `message_line`.
- **`Dialog`** — modal confirms for destructive actions.

## Per-surface behaviour

- **Users** — a filterable `DataTable` (Handle · Status pill · Role chips ·
  Password state); clicking a row (or its *Manage* action) opens a `Drawer`
  with the lifecycle actions (disable / enable / reset password / require
  change). Each destructive action stages a **confirm dialog gated on the
  dry-run prediction** (`predicted == enforced`): the confirm button is enabled
  only when the shared decider returns ALLOW, with the reason shown when it
  would DENY (e.g. the last admin cannot be disabled). *Invite* opens a dialog
  and, on success, reveals the one-time temp password via `SecretReveal`; admin
  *Reset password* reveals likewise.
- **Roles & Groups** — two focused tabs. *Roles*: object table + a creator whose
  capabilities are a checkbox picker over the documented IAM capabilities plus a
  free-text field for any others. *Groups*: object table + create, and
  attach-role via **select pickers seeded from the live role/group lists** (not
  two free-text boxes).
- **OAuth Clients** — a *Clients* tab (registry table + a register dialog that
  reveals the client secret once via `SecretReveal`) and a *Consents* tab
  (revoke a `(client, user)` consent behind a dry-run-gated confirm, client
  chosen from a picker).

## Deliberate deferrals

These are intentional, not bugs. Each is blocked on a backend endpoint the IAM
epic (ROI Priority 0) has not landed yet — the current IAM tiles call
`/portal/users|roles|groups|oauth|profile`, none of which are served yet, so
the whole surface is a pre-wired shell regardless of presentation:

- **`Members` is not retired into `Users`.** `Members` (`/portal/members`) is
  the *working* cell-membership admin today; `Users` (`/portal/users`) is not
  served yet. Retiring the working list into the non-working one would drop
  function, so both are kept under Administration until the Users endpoints land
  and can supersede Members.
- **No role selection at invite.** `invite_user_wire` carries only
  `handle`+`email`; role assignment at invite needs the invite endpoint to
  accept roles. Roles are managed after creation instead. (User→role assignment
  UI itself waits on an assign endpoint — the current wire surface only attaches
  roles to *groups*.)
- **Nav is not hidden by capability.** `AuthSession`/`LoginResponse` carry no
  capability set (login returns only `handle`), so the Administration group is
  shown to every authenticated user and enforcement is left to the server
  decider. Hiding the group for non-admins waits on a capabilities-in-session
  endpoint.

When those endpoints land, the surfaces above light up unchanged.
