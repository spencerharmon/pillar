# Plugin surface catalog

> Status: enumeration. This document catalogs the **complete out-of-tree plugin
> surface** of pillar. Every entry here is *optional* and *out-of-tree* unless
> explicitly noted, and every one rides the single core controller interface —
> the `ResourceSpec` trait and the generic `ResourceReconciler<S: ResourceSpec>`
> pipeline in `crates/pillar-controller` (see
> [architecture.md](architecture.md) and the `plugin-interface` work). No plugin
> gets a private path into the platform: each is just another `ResourceSpec`
> client and is subject to the identical non-network safety pipeline
> (identity/capability authorization, target-node match, view-policy admission,
> coordination-lease exclusivity).
>
> This is a *planning* document. It defines each plugin's **interface contract**
> — the shape of the `ResourceSpec` it implements and the authority it requires —
> so that concrete drivers can be filed as separate out-of-tree tasks when they
> are scheduled. It does **not** implement any driver.

## Universal contract (applies to every entry below)

Every plugin, without exception, obeys these platform-level rules. Individual
entries only note *deviations from* or *specializations of* this baseline.

1. **Rides the core controller interface.** A plugin is a type implementing the
   public `ResourceSpec` trait and driven through `ResourceReconciler`. It
   declares its resource type, decodes its manifest, classifies each side effect
   by reversibility (exclusive/non-idempotent vs. convergent/idempotent), and
   performs the effect. It never re-implements authorization, node matching,
   view admission, or lease acquisition — the reconciler owns those.
2. **Authorized against the Web of Trust (WoT) + capability-scoped subkeys.**
   Access is granted by the PGP Web-of-Trust authority (core, fail-closed on
   authority-reducing events) and scoped by capability subkeys
   (compute / network / storage / all, with specific > group > all override). A
   plugin declares the capability class(es) it needs; the reconciler refuses any
   invocation whose signing subkey lacks them. Authority is never a plugin
   concern to enforce — only to *declare*.
3. **Consistency by reversibility.** Exclusive / non-idempotent side effects
   (e.g. "claim this public IP", "create this DNS record", "acquire this cloud
   lease") are **CP-class**: refused under a relaxed (AP) view and gated behind a
   coordination-lease grant. Convergent / idempotent effects may run AP. The
   plugin classifies; the platform enforces.
4. **Out-of-tree and optional.** Unless a note says otherwise, the plugin lives
   in its own repository/crate outside `github.com/spencerharmon/pillar`, is
   compiled/loaded only where deployed, and its absence removes only its own
   capability. Nothing in core depends on any plugin existing.
5. **Concrete drivers are separate scheduled tasks.** Each family below names an
   *interface contract*; each concrete backend (a specific cloud, a specific DNS
   provider, a specific 2FA service) is its own out-of-tree implementation task,
   filed and prioritized when scheduled.

## Catalog

### 1. Kubernetes-API façade / Flux-Argo bridge

- **What.** A translating apiserver that presents a Kubernetes-shaped API so an
  existing flux / argo / kubectl shop can interoperate with pillar. Pillar is
  **deliberately NOT a Kubernetes API server**; this façade is the interop path
  for organizations already coupled to the k8s API and GitOps controllers.
- **Interface contract.** Presents k8s API objects as a **materialized view**
  over pillar's event stream (read side) and translates incoming apply/patch
  operations into `ResourceSpec` manifests submitted through the core interface
  (write side). CRUD on a k8s object becomes a signed pillar event; a
  Flux `Kustomization` / Argo `Application` becomes a stream of such events.
- **Authority / consistency.** Every translated write is signed by a
  capability-scoped subkey and inherits the exact WoT authorization and
  CP/AP classification of the underlying resource type. The façade holds no
  ambient authority of its own.
- **Priority.** LOW, out-of-tree.

### 2. Metadata-privacy transport (Tor / Waku)

- **What.** An onion/mixnet overlay providing sender/recipient metadata privacy
  on top of the libp2p messaging layer. Tor hidden services and Waku are the
  named reference targets.
- **Interface contract.** A **transport/overlay adapter**, not a `ResourceSpec`
  controller in the usual sense: it plugs in beneath the messaging/storage layer
  as an *optional* transport pillar's libp2p stack can dial through. It is an
  OPTIONAL overlay, **never a bootstrap dependency** — core reachability
  (relay/hole-punch over plain libp2p) must always work without it.
- **Authority / consistency.** Carries signed events unchanged; adds no
  authority semantics. Privacy is a transport property, orthogonal to WoT
  authorization of the payload.
- **Priority.** OPTIONAL overlay, out-of-tree.

### 3. Legacy backend adapters (DNS, non-p2p storage)

- **What.** Adapters that let pillar use *traditional* backends where the
  p2p-preferred defaults (IPFS, pillar streaming DB, Tor) are not available or
  not wanted: classic authoritative DNS, non-p2p object/block/file storage, and
  similar legacy infrastructure.
- **Interface contract.** Each is a `ResourceSpec` whose reconcile drives an
  external, non-p2p system (write a DNS zone record; put/get a blob in a
  traditional store). Implements the same read-materialize / write-effect shape,
  but its effect targets legacy infrastructure instead of the p2p substrate.
- **Authority / consistency.** DNS record creation and exclusive storage claims
  are typically **CP/exclusive** (lease-gated); idempotent reads/writes may be
  AP. Requires the relevant `network` or `storage` capability class.
- **Priority.** LOW, out-of-tree.

### 4. Public-provider integrations (S3/R2, DNS, DDoS, GCP/Alibaba, …)

- **What.** Integrations with commercial public providers: object storage
  (AWS S3, Cloudflare R2), managed DNS, DDoS-protection services, and full cloud
  providers (GCP, Alibaba, …). Includes the **generic public-provider credential
  handling** those drivers share.
- **Interface contract.** A **provider framework** (generic credential handling,
  region/endpoint config, ret/backoff) plus per-provider `ResourceSpec` drivers.
  Provider credentials are secrets, stored **PGP-encrypted and readable only by
  the controllers authorized to use them** (per the core secret-handling model),
  never as ambient environment credentials.
- **Authority / consistency.** Provisioning an external resource (a bucket, a
  DNS record, a VM) is **CP/exclusive** and lease-gated; each driver declares its
  capability class. A misclassified idempotent op may run AP.
- **Priority.** LOW, out-of-tree; each concrete provider driver is its own task.

### 5. Network & security resources (firewalls, security groups, routing, primitive adapters, IPFS)

- **What.** Controllers for network- and security-plane resources — firewalls,
  security groups, dynamic routing — **plus** adapters over every pillar-level
  primitive interface (the streaming DB, the messaging layer) and over **IPFS**
  itself as a first-class backend.
- **Interface contract.** Two shapes: (a) `ResourceSpec` controllers that
  reconcile network/security objects against a target (in-cluster or a
  provider's network API); and (b) **primitive adapters** exposing pillar's own
  interfaces (streaming DB, messaging, IPFS) as pluggable backends other
  controllers consume. The IPFS adapter is the p2p-preferred storage backend
  surfaced through this same plugin shape.
- **Authority / consistency.** Firewall/security-group/routing mutations are
  security-sensitive and **CP/exclusive** (authority-reducing changes fail
  closed); require the `network` capability. Primitive-adapter reads are AP.
- **Priority.** LOW, out-of-tree (IPFS is the default storage backend but is
  still surfaced through the plugin interface).

### 6. Auth providers (passkey/WebAuthn, external 2FA)

- **What.** Authentication-provider integrations for the user-facing UI and API:
  passkey / WebAuthn and popular external 2FA services.
- **Interface contract.** An **auth-provider plugin** that the UI/API auth layer
  invokes to verify a user. Open-standard auth (the WebAuthn/passkey path) is in
  **core**; the *specific external 2FA provider* integrations are plugins. A
  port-forwarded, signing-capable UI must **never** be unauthenticated — so this
  is the one plugin family that is **higher-priority within the plugin surface**.
- **Authority / consistency.** Authenticates the *human/user* to the UI; distinct
  from WoT capability authorization of *resource actions* (which still applies
  underneath). Bootstrap auth is localhost-only; post-bootstrap requires a
  configured provider declared in the user's manifests.
- **Priority.** HIGH within the plugin surface (security-critical); provider
  drivers out-of-tree, the open-standard core path in-tree.

### 7. Automata / plugin worker SDK

- **What.** The productized form of the 2020–2021 prototype's "automata / plugin
  worker" model: the **third-party controller SDK** — the public, supported way
  to author an out-of-tree controller.
- **Interface contract.** Packages the public `ResourceSpec` trait, the
  reconciler-client harness, manifest (de)serialization, capability-declaration
  helpers, and the signing/authorization plumbing into an SDK so a third party
  can build a plugin **without** touching pillar internals. This SDK is the
  common substrate every other entry in this catalog is built on top of.
- **Authority / consistency.** Enforces, by construction, that SDK-authored
  controllers declare capabilities and classify side effects; the platform still
  independently enforces both.
- **Priority.** LOW (foundational to the surface), out-of-tree SDK.

## Completeness

This catalog enumerates the full plugin surface named in the record of intent:
(1) Kubernetes-API façade / Flux-Argo bridge, (2) metadata-privacy transport
(Tor/Waku), (3) legacy backend adapters (DNS, non-p2p storage), (4)
public-provider integrations (S3/R2, DNS, DDoS, GCP/Alibaba), (5) network &
security resources (firewalls, security groups, routing, primitive adapters,
IPFS), (6) auth providers (passkey/WebAuthn, external 2FA), and (7) the
automata / plugin worker SDK. Every entry rides the one core controller
interface and is authorized via WoT + capability-scoped subkeys. Concrete
drivers within each family are filed as separate out-of-tree tasks when
scheduled.
