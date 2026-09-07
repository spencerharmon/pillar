//! Guided **attestation** and **custody** wizards for the Trust console
//! (Phase 4 follow-up) — the multi-step replacement for the flat
//! `portal.rs::TrustTile` "Build an attestation" / "Key / offer custody" input
//! stacks.
//!
//! Instead of a single wall of eight raw inputs plus four bare custody buttons,
//! these wizards walk the operator through the same backend contracts
//! (`POST /portal/attestations/build`, `POST /portal/custody/{migrate,rotate,
//! seal,revoke}`) one focused step at a time, validating each step's fields
//! before it can advance and composing the EXACT line-oriented request body the
//! dispatchers already parse.
//!
//! Every non-trivial decision is **pure, host-testable** Rust (no DOM): the
//! step models ([`AttestationStep`], [`CustodyStep`]), the per-step validation
//! ([`attestation_step_valid`], [`custody_step_valid`]), the request-body
//! composition ([`compose_attestation_body`], [`compose_custody_body`]), and the
//! success-response parse ([`parse_attestation_result`]). The `yew` components
//! are thin wrappers over them plus the shared design-system `FieldSet` /
//! `FormField` primitives, so the wizard logic is proven with a plain
//! `cargo test`.

use crate::components::form::{all_valid, FieldRule};

// ---------------------------------------------------------------------------
// Attestation wizard (pure)
// ---------------------------------------------------------------------------

/// The editable fields of the attestation builder, in the backend's body order
/// (`<issuer>\n<capacity>\n<authority>\n<subject>\n<action>\n<resource>\n
/// <quota>\n<scope>`). `capacity` defaults to `self` when left blank;
/// `authority` and `quota` are optional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationFields {
    /// The issuing node (who signs the grant).
    pub issuer: String,
    /// The capacity claimed: `self` or `<role>@<scope>` (blank ⇒ `self`).
    pub capacity: String,
    /// An optional authority-attestation CID this grant chains from.
    pub authority: String,
    /// The subject the grant is about (who is empowered).
    pub subject: String,
    /// The action being granted.
    pub action: String,
    /// The resource the action applies to.
    pub resource: String,
    /// An optional quota budget (`<resource>=<amount>[m]`, e.g. `cpu=1000m`).
    pub quota: String,
    /// The scope the grant is bound to.
    pub scope: String,
}

/// One step of the attestation wizard. Each step gathers a related subset of
/// the fields so the operator is never shown the whole eight-field wall at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationStep {
    /// Who is issuing, and under what capacity/authority.
    Issuer,
    /// The grant itself: subject, action, resource.
    Grant,
    /// Scope + optional quota, then review & sign.
    ScopeReview,
}

impl AttestationStep {
    /// The steps in wizard order.
    #[must_use]
    pub const fn all() -> [AttestationStep; 3] {
        [
            AttestationStep::Issuer,
            AttestationStep::Grant,
            AttestationStep::ScopeReview,
        ]
    }

    /// This step's zero-based index.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            AttestationStep::Issuer => 0,
            AttestationStep::Grant => 1,
            AttestationStep::ScopeReview => 2,
        }
    }

    /// The step at `index`, saturating at the last step.
    #[must_use]
    pub fn from_index(index: usize) -> AttestationStep {
        match index {
            0 => AttestationStep::Issuer,
            1 => AttestationStep::Grant,
            _ => AttestationStep::ScopeReview,
        }
    }

    /// The step title shown in the wizard header.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            AttestationStep::Issuer => "Issuer & capacity",
            AttestationStep::Grant => "The grant",
            AttestationStep::ScopeReview => "Scope & review",
        }
    }

    /// Whether this is the final (submitting) step.
    #[must_use]
    pub const fn is_last(self) -> bool {
        matches!(self, AttestationStep::ScopeReview)
    }
}

/// The `(field-name, value, rules)` triples that gate ADVANCING past `step` —
/// only the REQUIRED fields owned by that step (optional fields carry no rule).
#[must_use]
pub fn attestation_step_rules(
    step: AttestationStep,
    f: &AttestationFields,
) -> Vec<(String, String, Vec<FieldRule>)> {
    match step {
        // `capacity`/`authority` are optional (capacity defaults to `self`), so
        // only `issuer` is required to leave the first step.
        AttestationStep::Issuer => vec![(
            "issuer".to_owned(),
            f.issuer.clone(),
            vec![FieldRule::Required],
        )],
        AttestationStep::Grant => vec![
            (
                "subject".to_owned(),
                f.subject.clone(),
                vec![FieldRule::Required],
            ),
            (
                "action".to_owned(),
                f.action.clone(),
                vec![FieldRule::Required],
            ),
            (
                "resource".to_owned(),
                f.resource.clone(),
                vec![FieldRule::Required],
            ),
        ],
        // `quota` is optional; only `scope` is required to sign.
        AttestationStep::ScopeReview => vec![(
            "scope".to_owned(),
            f.scope.clone(),
            vec![FieldRule::Required],
        )],
    }
}

/// Whether `step`'s required fields are all valid (i.e. the wizard may advance
/// past it — and, on the last step, submit).
#[must_use]
pub fn attestation_step_valid(step: AttestationStep, f: &AttestationFields) -> bool {
    all_valid(&attestation_step_rules(step, f))
}

/// Compose the `POST /portal/attestations/build` request body EXACTLY as the
/// dispatcher parses it: `<token>\n<issuer>\n<capacity>\n<authority>\n
/// <subject>\n<action>\n<resource>\n<quota>\n<scope>`. A blank `capacity`
/// becomes `self` (the dispatcher rejects an empty capacity); every field is
/// trimmed; optional blanks are sent as empty lines.
#[must_use]
pub fn compose_attestation_body(token: &str, f: &AttestationFields) -> String {
    let capacity = if f.capacity.trim().is_empty() {
        "self"
    } else {
        f.capacity.trim()
    };
    [
        token.trim(),
        f.issuer.trim(),
        capacity,
        f.authority.trim(),
        f.subject.trim(),
        f.action.trim(),
        f.resource.trim(),
        f.quota.trim(),
        f.scope.trim(),
    ]
    .join("\n")
}

/// The parsed success response of the attestation builder: the composed grant's
/// CID, its human sentence, and the full proof chain of CIDs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestationResult {
    /// The `CID <cid>` line value.
    pub cid: String,
    /// The `SENTENCE <text>` line value.
    pub sentence: String,
    /// Every `CHAIN <cid>` line value, in order.
    pub chain: Vec<String>,
}

/// Parse the builder's `200 OK` body (`CID <cid>`, `SENTENCE <text>`,
/// `CHAIN <cid>` lines). Unknown lines are ignored.
#[must_use]
pub fn parse_attestation_result(body: &str) -> AttestationResult {
    let mut out = AttestationResult::default();
    for line in body.lines() {
        let line = line.trim();
        if let Some(cid) = line.strip_prefix("CID ") {
            out.cid = cid.trim().to_owned();
        } else if let Some(s) = line.strip_prefix("SENTENCE ") {
            out.sentence = s.trim().to_owned();
        } else if let Some(c) = line.strip_prefix("CHAIN ") {
            out.chain.push(c.trim().to_owned());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Custody wizard (pure)
// ---------------------------------------------------------------------------

/// A custody operation the wizard can drive — one per backend custody route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyOp {
    /// `POST /portal/custody/rotate` — new CID for an existing handle.
    Rotate,
    /// `POST /portal/custody/migrate` — new holder + new CID.
    Migrate,
    /// `POST /portal/custody/seal` — seal/escrow the handle.
    Seal,
    /// `POST /portal/custody/revoke` — revoke the handle.
    Revoke,
}

impl CustodyOp {
    /// Every operation in wizard-selector order.
    #[must_use]
    pub const fn all() -> [CustodyOp; 4] {
        [
            CustodyOp::Rotate,
            CustodyOp::Migrate,
            CustodyOp::Seal,
            CustodyOp::Revoke,
        ]
    }

    /// The human label for the operation.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            CustodyOp::Rotate => "Rotate",
            CustodyOp::Migrate => "Migrate",
            CustodyOp::Seal => "Seal / escrow",
            CustodyOp::Revoke => "Revoke",
        }
    }

    /// The backend route this operation POSTs to.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            CustodyOp::Rotate => "/portal/custody/rotate",
            CustodyOp::Migrate => "/portal/custody/migrate",
            CustodyOp::Seal => "/portal/custody/seal",
            CustodyOp::Revoke => "/portal/custody/revoke",
        }
    }

    /// Whether this operation needs a new CID (`rotate`, `migrate`).
    #[must_use]
    pub const fn needs_cid(self) -> bool {
        matches!(self, CustodyOp::Rotate | CustodyOp::Migrate)
    }

    /// Whether this operation needs a new holder (`migrate` only).
    #[must_use]
    pub const fn needs_holder(self) -> bool {
        matches!(self, CustodyOp::Migrate)
    }

    /// A one-line description of the operation's effect, shown on the review
    /// step.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            CustodyOp::Rotate => "Point the handle at a new key CID.",
            CustodyOp::Migrate => "Hand the key to a new holder under a new CID.",
            CustodyOp::Seal => "Seal the handle into escrow.",
            CustodyOp::Revoke => "Revoke the handle's custody record.",
        }
    }
}

/// The editable fields shared by the custody operations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustodyFields {
    /// The custody handle being acted on (always required).
    pub handle: String,
    /// A new key CID (required for rotate/migrate).
    pub cid: String,
    /// A new holder node (required for migrate).
    pub holder: String,
}

/// One step of the custody wizard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustodyStep {
    /// Pick the operation.
    Operation,
    /// Fill the operation's fields.
    Details,
    /// Review & sign.
    Review,
}

impl CustodyStep {
    /// The steps in wizard order.
    #[must_use]
    pub const fn all() -> [CustodyStep; 3] {
        [
            CustodyStep::Operation,
            CustodyStep::Details,
            CustodyStep::Review,
        ]
    }

    /// This step's zero-based index.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            CustodyStep::Operation => 0,
            CustodyStep::Details => 1,
            CustodyStep::Review => 2,
        }
    }

    /// The step at `index`, saturating at the last step.
    #[must_use]
    pub fn from_index(index: usize) -> CustodyStep {
        match index {
            0 => CustodyStep::Operation,
            1 => CustodyStep::Details,
            _ => CustodyStep::Review,
        }
    }

    /// The step title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            CustodyStep::Operation => "Operation",
            CustodyStep::Details => "Details",
            CustodyStep::Review => "Review & sign",
        }
    }

    /// Whether this is the final (submitting) step.
    #[must_use]
    pub const fn is_last(self) -> bool {
        matches!(self, CustodyStep::Review)
    }
}

/// The required `(field-name, value, rules)` triples for the custody `Details`
/// step, keyed off which fields `op` actually consumes — so `seal`/`revoke`
/// require only `handle`, `rotate` also requires `cid`, and `migrate` requires
/// `handle`+`holder`+`cid`.
#[must_use]
pub fn custody_step_rules(
    op: CustodyOp,
    f: &CustodyFields,
) -> Vec<(String, String, Vec<FieldRule>)> {
    let mut rules = vec![(
        "handle".to_owned(),
        f.handle.clone(),
        vec![FieldRule::Required],
    )];
    if op.needs_holder() {
        rules.push((
            "holder".to_owned(),
            f.holder.clone(),
            vec![FieldRule::Required],
        ));
    }
    if op.needs_cid() {
        rules.push(("cid".to_owned(), f.cid.clone(), vec![FieldRule::Required]));
    }
    rules
}

/// Whether the custody `Details` step is valid for `op` (may advance / submit).
#[must_use]
pub fn custody_step_valid(op: CustodyOp, f: &CustodyFields) -> bool {
    all_valid(&custody_step_rules(op, f))
}

/// Compose the custody request body EXACTLY as each dispatcher parses it:
/// - rotate: `<token>\n<handle>\n<cid>`
/// - migrate: `<token>\n<handle>\n<holder>\n<cid>`
/// - seal/revoke: `<token>\n<handle>`
#[must_use]
pub fn compose_custody_body(token: &str, op: CustodyOp, f: &CustodyFields) -> String {
    let token = token.trim();
    let handle = f.handle.trim();
    match op {
        CustodyOp::Rotate => [token, handle, f.cid.trim()].join("\n"),
        CustodyOp::Migrate => [token, handle, f.holder.trim(), f.cid.trim()].join("\n"),
        CustodyOp::Seal | CustodyOp::Revoke => [token, handle].join("\n"),
    }
}

// ---------------------------------------------------------------------------
// Yew components
// ---------------------------------------------------------------------------

#[cfg(feature = "yew")]
pub use yew_impl::{AttestationWizard, CustodyWizard};

#[cfg(feature = "yew")]
mod yew_impl {
    use super::{
        attestation_step_valid, compose_attestation_body, compose_custody_body, custody_step_valid,
        parse_attestation_result, AttestationFields, AttestationResult, AttestationStep, CustodyOp,
        CustodyStep, CustodyFields,
    };
    use crate::auth::use_auth;
    use crate::components::form::{FieldRule, FieldSet, FormField};
    use crate::portal::{http, input_value};
    use crate::primitives::{Badge, Tone};
    use wasm_bindgen_futures::spawn_local;
    use yew::prelude::*;

    /// The guided attestation builder: a three-step wizard over
    /// `POST /portal/attestations/build`.
    #[function_component(AttestationWizard)]
    pub fn attestation_wizard() -> Html {
        let auth = use_auth();
        let step = use_state(|| 0usize);
        let fields = use_state(AttestationFields::default);
        let result = use_state(|| None::<AttestationResult>);
        let error = use_state(|| None::<String>);
        let busy = use_state(|| false);

        let current = AttestationStep::from_index(*step);
        let can_advance = attestation_step_valid(current, &fields);

        // A per-field oninput that updates one field of the shared struct.
        let field_input = {
            let fields = fields.clone();
            move |set: fn(&mut AttestationFields, String)| {
                let fields = fields.clone();
                Callback::from(move |e: InputEvent| {
                    let mut next = (*fields).clone();
                    set(&mut next, input_value(&e));
                    fields.set(next);
                })
            }
        };

        let back = {
            let step = step.clone();
            Callback::from(move |_: MouseEvent| {
                step.set(step.saturating_sub(1));
            })
        };

        let advance_or_submit = {
            let (auth, step, fields, result, error, busy) = (
                auth.clone(),
                step.clone(),
                fields.clone(),
                result.clone(),
                error.clone(),
                busy.clone(),
            );
            Callback::from(move |_: ()| {
                let current = AttestationStep::from_index(*step);
                if !attestation_step_valid(current, &fields) {
                    return;
                }
                if !current.is_last() {
                    step.set(*step + 1);
                    return;
                }
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let body = compose_attestation_body(&token, &fields);
                let (result, error, busy) = (result.clone(), error.clone(), busy.clone());
                busy.set(true);
                error.set(None);
                spawn_local(async move {
                    if let Ok(r) = http("POST", "/portal/attestations/build", Some(&body)).await {
                        if r.ok() {
                            result.set(Some(parse_attestation_result(&r.body)));
                            error.set(None);
                        } else {
                            error.set(Some(
                                r.body
                                    .trim()
                                    .trim_start_matches("DENIED")
                                    .trim_start_matches("MISSING")
                                    .trim()
                                    .to_owned(),
                            ));
                        }
                    }
                    busy.set(false);
                });
            })
        };

        let step_fields = match current {
            AttestationStep::Issuer => html! {
                <>
                    <FormField label="Issuer" placeholder="issuing node"
                        value={fields.issuer.clone()}
                        rules={vec![FieldRule::Required]}
                        oninput={field_input(|f, v| f.issuer = v)} />
                    <FormField label="Capacity" placeholder="self or role@scope (blank = self)"
                        value={fields.capacity.clone()}
                        oninput={field_input(|f, v| f.capacity = v)} />
                    <FormField label="Authority CID (optional)" placeholder="authority attestation cid"
                        value={fields.authority.clone()}
                        oninput={field_input(|f, v| f.authority = v)} />
                </>
            },
            AttestationStep::Grant => html! {
                <>
                    <FormField label="Subject" placeholder="node the grant is about"
                        value={fields.subject.clone()}
                        rules={vec![FieldRule::Required]}
                        oninput={field_input(|f, v| f.subject = v)} />
                    <FormField label="Action" placeholder="granted action"
                        value={fields.action.clone()}
                        rules={vec![FieldRule::Required]}
                        oninput={field_input(|f, v| f.action = v)} />
                    <FormField label="Resource" placeholder="resource"
                        value={fields.resource.clone()}
                        rules={vec![FieldRule::Required]}
                        oninput={field_input(|f, v| f.resource = v)} />
                </>
            },
            AttestationStep::ScopeReview => html! {
                <>
                    <FormField label="Scope" placeholder="binding scope"
                        value={fields.scope.clone()}
                        rules={vec![FieldRule::Required]}
                        oninput={field_input(|f, v| f.scope = v)} />
                    <FormField label="Quota (optional)" placeholder="e.g. cpu=1000m"
                        value={fields.quota.clone()}
                        oninput={field_input(|f, v| f.quota = v)} />
                    <p class="ds-empty">
                        { format!("Ready to sign: {} grants {} \u{2192} {} on {} (scope {}).",
                            trimmed_or(&fields.issuer, "issuer"),
                            trimmed_or(&fields.subject, "subject"),
                            trimmed_or(&fields.action, "action"),
                            trimmed_or(&fields.resource, "resource"),
                            trimmed_or(&fields.scope, "scope")) }
                    </p>
                </>
            },
        };

        let submit_label = if current.is_last() {
            if *busy {
                "Signing\u{2026}"
            } else {
                "Sign attestation"
            }
        } else {
            "Next"
        };

        html! {
            <div class="tile" id="attestation-wizard">
                <h3>{ "Attestation builder" }</h3>
                <p>{ "Compose and sign a capability attestation, one step at a time." }</p>
                { wizard_steps(current.index(), &AttestationStep::all().map(|s| s.title())) }
                <FieldSet
                    legend={current.title()}
                    submit_label={submit_label}
                    can_submit={can_advance && !*busy}
                    onsubmit={advance_or_submit}
                >
                    { step_fields }
                </FieldSet>
                if *step > 0 {
                    <button class="ds-tab" id="attest-back" onclick={back}>{ "Back" }</button>
                }
                if let Some(msg) = (*error).clone() {
                    <div id="attestation-error">
                        <Badge label={format!("Refused: {msg}")} tone={Tone::Danger} />
                    </div>
                }
                if let Some(res) = (*result).clone() {
                    <div id="attestation-result" class="res-change">
                        <Badge label="Attestation signed" tone={Tone::Success} />
                        <p class="attest-line"><strong>{ "CID: " }</strong>{ res.cid }</p>
                        <p class="attest-line">{ res.sentence }</p>
                        if !res.chain.is_empty() {
                            <p class="ds-empty">{ "Proof chain:" }</p>
                            { for res.chain.iter().map(|c| html! {
                                <p class="attest-line">{ c.clone() }</p>
                            }) }
                        }
                    </div>
                }
            </div>
        }
    }

    /// The guided custody wizard: a three-step flow over the four
    /// `POST /portal/custody/*` routes.
    #[function_component(CustodyWizard)]
    pub fn custody_wizard() -> Html {
        let auth = use_auth();
        let step = use_state(|| 0usize);
        let op = use_state(|| CustodyOp::Rotate);
        let fields = use_state(CustodyFields::default);
        let outcome = use_state(|| None::<(String, bool)>);
        let busy = use_state(|| false);

        let current = CustodyStep::from_index(*step);
        let can_advance = match current {
            CustodyStep::Operation => true,
            CustodyStep::Details | CustodyStep::Review => custody_step_valid(*op, &fields),
        };

        let field_input = {
            let fields = fields.clone();
            move |set: fn(&mut CustodyFields, String)| {
                let fields = fields.clone();
                Callback::from(move |e: InputEvent| {
                    let mut next = (*fields).clone();
                    set(&mut next, input_value(&e));
                    fields.set(next);
                })
            }
        };

        let back = {
            let step = step.clone();
            Callback::from(move |_: MouseEvent| step.set(step.saturating_sub(1)))
        };

        let advance_or_submit = {
            let (auth, step, op, fields, outcome, busy) = (
                auth.clone(),
                step.clone(),
                op.clone(),
                fields.clone(),
                outcome.clone(),
                busy.clone(),
            );
            Callback::from(move |_: ()| {
                let current = CustodyStep::from_index(*step);
                let ok = match current {
                    CustodyStep::Operation => true,
                    _ => custody_step_valid(*op, &fields),
                };
                if !ok {
                    return;
                }
                if !current.is_last() {
                    step.set(*step + 1);
                    return;
                }
                if *busy {
                    return;
                }
                let token = auth.token.clone().unwrap_or_default();
                let op_now = *op;
                let body = compose_custody_body(&token, op_now, &fields);
                let (outcome, busy) = (outcome.clone(), busy.clone());
                busy.set(true);
                spawn_local(async move {
                    if let Ok(r) = http("POST", op_now.path(), Some(&body)).await {
                        outcome.set(Some((r.body.trim().to_owned(), r.ok())));
                    }
                    busy.set(false);
                });
            })
        };

        let step_body = match current {
            CustodyStep::Operation => {
                let op_state = op.clone();
                let step2 = step.clone();
                html! {
                    <div class="res-toolbar" id="custody-op-picker">
                        { for CustodyOp::all().into_iter().map(|candidate| {
                            let selected = *op_state == candidate;
                            let op_state = op_state.clone();
                            let step2 = step2.clone();
                            let onclick = Callback::from(move |_: MouseEvent| {
                                op_state.set(candidate);
                                step2.set(1);
                            });
                            let mut class = Classes::from("ds-tab");
                            if selected { class.push("is-active"); }
                            html! { <button class={class} onclick={onclick}>{ candidate.label() }</button> }
                        }) }
                    </div>
                }
            }
            CustodyStep::Details => html! {
                <>
                    <FormField label="Handle" placeholder="custody handle"
                        value={fields.handle.clone()}
                        rules={vec![FieldRule::Required]}
                        oninput={field_input(|f, v| f.handle = v)} />
                    if op.needs_holder() {
                        <FormField label="New holder" placeholder="new holder node"
                            value={fields.holder.clone()}
                            rules={vec![FieldRule::Required]}
                            oninput={field_input(|f, v| f.holder = v)} />
                    }
                    if op.needs_cid() {
                        <FormField label="New CID" placeholder="new key cid"
                            value={fields.cid.clone()}
                            rules={vec![FieldRule::Required]}
                            oninput={field_input(|f, v| f.cid = v)} />
                    }
                </>
            },
            CustodyStep::Review => html! {
                <p class="ds-empty">
                    { format!("{} \u{2014} handle {}{}{}.",
                        op.summary(),
                        trimmed_or(&fields.handle, "handle"),
                        if op.needs_holder() { format!(", holder {}", trimmed_or(&fields.holder, "holder")) } else { String::new() },
                        if op.needs_cid() { format!(", cid {}", trimmed_or(&fields.cid, "cid")) } else { String::new() }) }
                </p>
            },
        };

        let submit_label = if current.is_last() {
            if *busy { "Signing\u{2026}" } else { "Sign & apply" }
        } else if matches!(current, CustodyStep::Operation) {
            "Choose an operation above"
        } else {
            "Next"
        };

        html! {
            <div class="tile" id="custody-wizard">
                <h3>{ "Custody" }</h3>
                <p>{ "Rotate, migrate, seal, or revoke a key handle's custody \u{2014} guided." }</p>
                { wizard_steps(current.index(), &CustodyStep::all().map(|s| s.title())) }
                if matches!(current, CustodyStep::Operation) {
                    { step_body }
                } else {
                    <FieldSet
                        legend={current.title()}
                        submit_label={submit_label}
                        can_submit={can_advance && !*busy}
                        onsubmit={advance_or_submit}
                    >
                        { step_body }
                    </FieldSet>
                }
                if *step > 0 {
                    <button class="ds-tab" id="custody-back" onclick={back}>{ "Back" }</button>
                }
                if let Some((msg, ok)) = (*outcome).clone() {
                    <div id="custody-outcome">
                        <Badge label={msg} tone={if ok { Tone::Success } else { Tone::Danger }} />
                    </div>
                }
            </div>
        }
    }

    /// Render a compact horizontal step indicator, marking the active step.
    fn wizard_steps(active: usize, titles: &[&str]) -> Html {
        html! {
            <ol class="wizard-steps">
                { for titles.iter().enumerate().map(|(i, t)| {
                    let mut class = Classes::from("wizard-step");
                    if i == active { class.push("is-active"); }
                    if i < active { class.push("is-done"); }
                    html! { <li class={class}>{ format!("{}. {}", i + 1, t) }</li> }
                }) }
            </ol>
        }
    }

    /// The trimmed value, or a `<placeholder>` marker when blank — for review
    /// summaries only.
    fn trimmed_or(value: &str, placeholder: &str) -> String {
        let t = value.trim();
        if t.is_empty() {
            format!("<{placeholder}>")
        } else {
            t.to_owned()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_steps_round_trip_by_index() {
        for s in AttestationStep::all() {
            assert_eq!(AttestationStep::from_index(s.index()), s);
        }
        // Only the last step submits.
        assert!(AttestationStep::ScopeReview.is_last());
        assert!(!AttestationStep::Issuer.is_last());
    }

    #[test]
    fn attestation_step_gates_only_its_required_fields() {
        let mut f = AttestationFields::default();
        // Issuer step needs a non-blank issuer; capacity/authority optional.
        assert!(!attestation_step_valid(AttestationStep::Issuer, &f));
        f.issuer = "root".into();
        assert!(attestation_step_valid(AttestationStep::Issuer, &f));

        // Grant step needs subject+action+resource.
        assert!(!attestation_step_valid(AttestationStep::Grant, &f));
        f.subject = "alice".into();
        f.action = "read".into();
        f.resource = "db".into();
        assert!(attestation_step_valid(AttestationStep::Grant, &f));

        // Scope step needs scope; quota optional.
        assert!(!attestation_step_valid(AttestationStep::ScopeReview, &f));
        f.scope = "prod".into();
        assert!(attestation_step_valid(AttestationStep::ScopeReview, &f));
    }

    #[test]
    fn attestation_body_matches_the_dispatcher_field_order_and_defaults_capacity() {
        let f = AttestationFields {
            issuer: " root ".into(),
            capacity: "  ".into(), // blank -> "self"
            authority: "".into(),
            subject: "alice".into(),
            action: "read".into(),
            resource: "db".into(),
            quota: "cpu=1000m".into(),
            scope: "prod".into(),
        };
        let body = compose_attestation_body("tok", &f);
        // token\nissuer\ncapacity\nauthority\nsubject\naction\nresource\nquota\nscope
        assert_eq!(
            body,
            "tok\nroot\nself\n\nalice\nread\ndb\ncpu=1000m\nprod"
        );
        // A supplied capacity is passed through verbatim (trimmed).
        let f2 = AttestationFields {
            capacity: " admin@prod ".into(),
            ..f
        };
        assert!(compose_attestation_body("tok", &f2).contains("\nadmin@prod\n"));
    }

    #[test]
    fn attestation_result_parses_cid_sentence_and_chain() {
        let body = "CID cid-top\nSENTENCE root grants alice read on db\nCHAIN cid-1\nCHAIN cid-2\nnoise\n";
        let r = parse_attestation_result(body);
        assert_eq!(r.cid, "cid-top");
        assert_eq!(r.sentence, "root grants alice read on db");
        assert_eq!(r.chain, vec!["cid-1", "cid-2"]);
    }

    #[test]
    fn custody_op_metadata_maps_to_routes_and_field_needs() {
        assert_eq!(CustodyOp::Rotate.path(), "/portal/custody/rotate");
        assert_eq!(CustodyOp::Migrate.path(), "/portal/custody/migrate");
        assert_eq!(CustodyOp::Seal.path(), "/portal/custody/seal");
        assert_eq!(CustodyOp::Revoke.path(), "/portal/custody/revoke");
        // Only rotate/migrate need a CID; only migrate needs a holder.
        assert!(CustodyOp::Rotate.needs_cid() && !CustodyOp::Rotate.needs_holder());
        assert!(CustodyOp::Migrate.needs_cid() && CustodyOp::Migrate.needs_holder());
        assert!(!CustodyOp::Seal.needs_cid() && !CustodyOp::Seal.needs_holder());
        assert!(!CustodyOp::Revoke.needs_cid() && !CustodyOp::Revoke.needs_holder());
    }

    #[test]
    fn custody_step_gates_the_fields_each_op_consumes() {
        let mut f = CustodyFields::default();
        // Every op needs a handle.
        for op in CustodyOp::all() {
            assert!(!custody_step_valid(op, &f), "{op:?} accepted a blank handle");
        }
        f.handle = "h1".into();
        // Seal/revoke are satisfied by handle alone.
        assert!(custody_step_valid(CustodyOp::Seal, &f));
        assert!(custody_step_valid(CustodyOp::Revoke, &f));
        // Rotate still needs a cid.
        assert!(!custody_step_valid(CustodyOp::Rotate, &f));
        f.cid = "cid-9".into();
        assert!(custody_step_valid(CustodyOp::Rotate, &f));
        // Migrate additionally needs a holder.
        assert!(!custody_step_valid(CustodyOp::Migrate, &f));
        f.holder = "bob".into();
        assert!(custody_step_valid(CustodyOp::Migrate, &f));
    }

    #[test]
    fn custody_body_matches_each_dispatcher_shape() {
        let f = CustodyFields {
            handle: " h1 ".into(),
            cid: " cid-9 ".into(),
            holder: " bob ".into(),
        };
        assert_eq!(compose_custody_body("tok", CustodyOp::Rotate, &f), "tok\nh1\ncid-9");
        assert_eq!(
            compose_custody_body("tok", CustodyOp::Migrate, &f),
            "tok\nh1\nbob\ncid-9"
        );
        assert_eq!(compose_custody_body("tok", CustodyOp::Seal, &f), "tok\nh1");
        assert_eq!(compose_custody_body("tok", CustodyOp::Revoke, &f), "tok\nh1");
    }

    #[test]
    fn custody_steps_round_trip_by_index() {
        for s in CustodyStep::all() {
            assert_eq!(CustodyStep::from_index(s.index()), s);
        }
        assert!(CustodyStep::Review.is_last());
    }
}
