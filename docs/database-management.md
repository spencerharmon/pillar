# Database management with the pillar CLI

A user-facing guide to inspecting and managing your cell's data with the `pillar`
CLI: the keyed store (key/value and documents), SQL views, time-series, the catalog
you use to discover them, collections and access control as resources, and how to view
and edit the resources pillar ships by default.

> **Scope / status.** This is the design of record for the data-layer CLI surface. The
> architectural model is fixed in
> [`papers/pillar-data-layer.md`](papers/pillar-data-layer.md); the primitive and
> consistency background is there. Some verbs below land together with the data-layer
> implementation tasks — where a command is not yet available, `pillar` tells you so
> rather than failing silently. Every operation rides the single pillar-message ingest
> path (the HTTP REST interface is deprecated); nothing here uses a separate write path.

---

## The model in one minute

You work with three query interfaces over two storage models, all over one substrate:

- **Keyed store** — your structured state. Two surfaces over one engine:
  - **key/value** (`pillar kv`) for point lookups by key, and
  - **documents** (`pillar doc`) for structured records queried by field.
- **SQL views** (`pillar sql`) — a query layer *over* the keyed store: filter, join,
  aggregate, and build materialized views. It stores nothing of its own.
- **Time series** (`pillar obs`, PSL) — telemetry and signals, queried with the Pillar
  Signal Language.

Everything you write is a signed event on the streaming database; everything you read
is a materialized view folded from it. Reads and writes are authorized by your role and
scoped to your cell (see [Access control](#access-control) and
[What you can see](#what-you-can-see)).

---

## Discovering what's there — the catalog

You don't need to memorize which collection holds what. The catalog is itself queryable,
so you ask it.

```
pillar catalog databases              # list databases
pillar catalog collections [db]       # every collection, with its surface
pillar catalog describe <collection>  # the full card for one collection
pillar catalog views [db]             # materialized views and their sources
```

Because the catalog is ordinary data, the SQL equivalents work too:

```
pillar sql "SHOW TABLES"
pillar sql "DESCRIBE app.users"
pillar sql "SELECT * FROM __catalog WHERE kind = 'table'"
```

`describe` is your answer key. For each collection it reports:

| Field | Tells you |
|-------|-----------|
| **surface** | `keyed` → query with `kv` / `doc` / `sql`; `tsdb` → query with `obs` / PSL |
| **schema** | columns/fields and types (what you can `SELECT`) |
| **consistency** | `AP` (relaxed) or `CP` (strict) |
| **visibility** | `public` / `cell-encrypted` / `recipient-sealed` (what you can read) |
| **placement** | the node tags and the live count and list of participating nodes |

### Which interface do I use?

A keyed collection accepts all three keyed surfaces; pick by access pattern.

| You want to… | Use |
|--------------|-----|
| read one value by its key | `pillar kv get` |
| read one record, or filter by a field | `pillar doc get` / `pillar doc list` |
| join, aggregate, traverse, or run an ad-hoc query | `pillar sql "SELECT …"` |
| query telemetry over a time window | `pillar obs query '<PSL>'` |

---

## Key/value

```
pillar kv put <collection> <key> <value>
pillar kv get <collection> <key>
pillar kv scan <collection> [--prefix <p>] [--limit <n>]
pillar kv del <collection> <key>
pillar kv watch <collection> [--prefix <p>]     # subscribe to changes
```

A `put` appends a signed update carrying only the changed value; a `get` returns the
current folded value.

---

## Documents

```
pillar doc put   <collection> <id> <json>       # write/replace a record
pillar doc patch <collection> <id> <json>       # merge only the given fields
pillar doc get   <collection> <id>
pillar doc list  <collection> [--where <field>=<value>] [--limit <n>]
pillar doc del   <collection> <id>
pillar doc watch <collection> [--where <field>=<value>]
```

A `patch` updates only the fields you name; other fields are untouched, and two people
patching different fields of the same record do not clobber each other. Manifests and
resources are documents too, so `pillar apply -f resource.yaml` is a document write and
`pillar get` / `pillar describe` read the same collection.

---

## SQL: databases, tables, and views

### Define structure (DDL)

```
pillar sql "CREATE DATABASE app"
pillar sql "CREATE TABLE app.users (id TEXT PRIMARY KEY, name TEXT, email TEXT, role TEXT)"
pillar sql "CREATE MATERIALIZED VIEW app.admins AS
              SELECT id, email FROM app.users WHERE role = 'admin'"
```

### Read and write data (DML + queries)

```
pillar sql "INSERT INTO app.users VALUES ('alice','Alice','alice@example.com','admin')"
pillar sql "UPDATE app.users SET email = 'a@example.com' WHERE id = 'alice'"
pillar sql "DELETE FROM app.users WHERE id = 'alice'"

pillar sql "SELECT id, email FROM app.users WHERE role = 'admin' ORDER BY id"
pillar sql "SELECT role, COUNT(*) FROM app.users GROUP BY role"
pillar sql "SELECT u.name, g.name FROM app.users u JOIN app.groups g ON g.id = u.group_id"
pillar sql "SELECT * FROM app.admins" --watch     # stream rows as the view changes
```

An `UPDATE` does not rewrite a stored row in place — it appends a change that the view
folds in. You always read the current materialized result.

### Changing a schema without a migration

To present existing data a new way, create a new view over the same source. Nothing is
copied or migrated; the new view is built from the existing history and coexists with the
old one until you switch over.

```
pillar sql "CREATE MATERIALIZED VIEW app.users_v2 AS
              SELECT id, name AS full_name, email FROM app.users"
```

Point your consumers at `app.users_v2` when ready, then drop the old view.

---

## Time series

Telemetry and signals use the Pillar Signal Language; see
[`query-languages/psl.md`](query-languages/psl.md) for the grammar.

```
pillar obs query '<PSL query>'
```

---

## Collections as resources

A collection is a resource like anything else, but you rarely author one by hand.

- **Implicit.** The first write to a new collection creates it with your cell's default
  settings — placement across the whole cell, cell-encrypted visibility, and access
  control inherited from its parent scope. Those defaults come from an editable
  `CollectionPolicy` resource (see [The default ResourceSet](#the-default-resourceset)),
  not from hardcoded values.
- **Explicit.** Declare a collection when you want to govern it — a fixed schema, node
  isolation, a specific visibility class, or its own access control:

```yaml
apiVersion: data.pillar/v1
kind: Collection
metadata:
  name: app.users
spec:
  visibility: cell-encrypted
  consistency: relaxed          # relaxed (AP) | strict (CP)
```

```
pillar apply -f app-users.collection.yaml
```

### Placing a collection on specific nodes

By default a collection lives on every node in the cell. To isolate it — for
performance, security, or locality — select nodes by tag:

```yaml
apiVersion: data.pillar/v1
kind: CollectionPlacement
metadata:
  name: app-users-eu-db
spec:
  collection: app.users
  nodeSelector:
    tags: { role: db, region: eu }   # omit the selector to use the whole cell
```

See where a collection actually lives:

```
pillar catalog describe app.users     # shows placement tags + participating nodes
```

A materialized view is served from the nodes that hold all of its source collections, so
placing a view co-locates its sources automatically.

---

## Access control

Access is granted with resources, the same three ways as everything else — a manifest,
the CLI verbs, or the portal console — all producing one signed event.

```
pillar rbac grant  --to group/analysts --role reader --collection app.users
pillar rbac grant  --to user/alice     --role reader --view app.admins   # row/column scope
pillar rbac revoke --to user/alice     --role reader --view app.admins
```

The manifest form:

```yaml
apiVersion: rbac.pillar/v1
kind: RoleBinding
metadata:
  name: analysts-read-users
spec:
  subject: { kind: Group, name: analysts }
  role: reader
  scope:
    collection: app.users          # or: view | kind/name | cell
```

Scope a binding to a **view** to grant access to only certain rows/columns: create a view
that projects and filters what a subject may see, and grant on the view rather than the
base collection. You can only grant a capability you hold; an over-reaching grant is
refused.

---

## The default ResourceSet

Pillar ships a set of resources every cell gets automatically — the same mechanism that
creates your initial user and your default time-series retention policies. These are real,
viewable, editable resources; you never deploy them by hand, and pillar notifies you when a
newer version of a default is available so you can adopt it or keep your changes.

The default set includes, among others:

- the **system collections** that hold catalog and resource state,
- the **default rolebindings** (including the seed administrator binding),
- the **`CollectionPolicy`** that sets the defaults implicitly-created collections inherit,
- the **retention policies** for time-series collections.

### Viewing the defaults

```
pillar get resourceset default
pillar get rolebinding --set default
pillar get collectionpolicy default
pillar get retentionpolicy --all
```

### Editing a default

Edit the manifest and apply it, exactly as with any resource:

```
pillar get collectionpolicy default -o yaml > collectionpolicy.yaml
# edit the file …
pillar apply -f collectionpolicy.yaml
```

Your edit is a signed event with full history, so you can review who changed a default and
roll back by re-applying the previous version — or the shipped default from the updated
ResourceSet.

### Guardrails on foundational edits

Most defaults edit like any resource. A few govern the cell's own foundations — the seed
administrator binding, the access control on the system collections, their placement and
visibility — and edits to those carry extra protection so a single change can't lock the
cell out of itself:

- **Dry-run confirmation.** A foundational edit shows you its computed effect — who loses
  access, what would become unreachable — and requires you to confirm before it commits.
- **No-lockout admission.** An edit that would leave the cell with no administrator, or
  remove your own ability to reconcile the catalog, is refused before it is written.
- **Strict revocation.** Access-reducing edits are strongly consistent, so a revocation is
  never half-applied or lost.
- **Higher authority to edit the floor.** Changing a foundational resource requires a
  higher trust threshold than an ordinary resource.
- **Immutable identity.** A system collection's identity and kind, and the cell's genesis
  identity, are read-only even though the resource is viewable; you tune settings
  (placement, visibility, access control, retention), not identity.
- **Break-glass recovery.** The holder of the cell's genesis key can always restore the
  seed administrator binding, so authority is recoverable.

### Retention

A retention policy is an editable default like the others:

```
pillar get retentionpolicy signals -o yaml > retention.yaml
# edit spec.window …
pillar apply -f retention.yaml
```

Shortening a retention window removes data that falls outside the new window and takes
effect on apply, so `pillar` requires a strong confirmation for a shortening edit.

---

## Consistency notes

Most collections are **relaxed (AP)**: writes always succeed and merge automatically, which
is what you want for the large majority of data. A collection that enforces a hard
invariant — uniqueness, exactly-once admission, a hard quota ceiling — is **strict (CP)**;
under a network partition a minority node refuses the exclusive write rather than risk a
split. `pillar catalog describe` shows a collection's policy, and you set it with
`spec.consistency` on a `Collection` resource.

---

## What you can see

Two things gate every read:

1. **Cell membership.** Cell data is encrypted to the cell; you must be a member to read it
   at all. Data in another cell requires a replication grant.
2. **Your role.** Within your cell, the default is deny — you see the collections, rows, and
   columns your rolebindings authorize, and nothing else. `pillar catalog` and every query
   show only what you're allowed.

Sealed material follows its visibility class: secrets and recipient-sealed bodies are opaque
unless you hold the key, so a collection may be listable while its sensitive contents are not
readable to you.

---

## Command reference

| Command | Purpose |
|---------|---------|
| `pillar catalog databases \| collections \| describe \| views` | discover what exists and how to query it |
| `pillar kv put \| get \| scan \| del \| watch` | key/value |
| `pillar doc put \| patch \| get \| list \| del \| watch` | documents |
| `pillar sql "<statement>" [--watch]` | DDL, DML, and queries over the keyed store |
| `pillar obs query '<PSL>'` | time-series queries |
| `pillar apply -f <file>` / `pillar get` / `pillar describe` / `pillar delete` | resources (collections, views, bindings, defaults) |
| `pillar rbac grant \| revoke` | access control |

See also [`cli-surface.md`](cli-surface.md) for the overall CLI conventions and
[`papers/pillar-data-layer.md`](papers/pillar-data-layer.md) for the architecture.
