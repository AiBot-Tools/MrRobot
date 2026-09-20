# Survey: agency-os (Directus Community "AgencyOS")

Clone: `refs/agency-os` (read-only). All paths below are relative to that root. Claims are marked CONFIRMED (read in the clone) or INFERRED.

## Identity

* Upstream: `github.com/directus-community/agency-os` (README.md links and "Use This Template" URL). Not a fork; this is the original. CONFIRMED.
* License: MIT, "Copyright (c) 2023 Directus Community" (`LICENSE`). CONFIRMED.
* Commit surveyed: `dd00d38fd01ca97a7cc5bfa4df2043d6cc796b08`, 2025-03-26. CONFIRMED.
* Stack: Nuxt 3.16 + Vue, `@directus/sdk` 19, Nuxt UI 2, Tailwind, Stripe 17 (server) + `@stripe/stripe-js` (client), FormKit-style dynamic form schemas, `v-perfect-signature` for e-signatures (`package.json`). Backend is a Directus 10.13.1 instance (`.directus/docker-compose.yaml`) seeded by `npx directus-template-cli apply` (README.md). 273 files, no tests directory, no agent/LLM code anywhere. CONFIRMED.

## What it is

A web template for running a digital agency: marketing website + CMS page builder, a CRM/sales pipeline, proposals with e-signature acceptance, projects/tasks with client-assignable tasks, invoicing with Stripe checkout, expenses, and a private client portal. The schema lives in Directus (Postgres), the repo holds the Nuxt frontend, typed schema mirror (`types/schema.ts`), a handful of Nitro server routes, and six Directus Flow "run script" operations (`.directus/run-scripts/`). It is not an agent framework and has no orchestration, memory, tools, or sandbox concepts. CONFIRMED.

## Orchestration model

None. The only automation is Directus Flows (server-side event hooks) whose script bodies are checked in: line-item math, invoice totals, domain extraction from an organization website, email-template interpolation, and form-schema validation (`.directus/run-scripts/*.{js,ts}`). The Flow definitions themselves (triggers, wiring) are not in the repo; they live in the Directus template. INFERRED from `.directus/README.md` which says the scripts are "used in the Directus instance > Flows > Operations".

## Agent roster / roles found

None. Roles in this system are Directus users and roles (admin, client portal user). `types/system/user.ts` has a `status: 'active'` literal; portal auth is a cookie session via `modules/directus/runtime/composables/useDirectusAuth.ts`. There are no agent definitions, personas, or delegation. CONFIRMED.

## Memory model

Relational only: Postgres behind Directus. The decision-relevant part is the CRM/billing schema (`types/schema.ts` "OS" block, `types/os/*.ts`). CONFIRMED. Summary of the entity graph:

```
organizations ──< organizations_contacts >── contacts
   │  (stripe_customer_id, payment_terms, ap_contact, brand_color, addresses[])
   │
   ├──< os_deals (owner, deal_stage -> os_deal_stages, deal_value, close_date,
   │              next_contact_date, contacts[] via os_deal_contacts{primary})
   │        ├──< os_activities (activity_type, start/end/due, assigned_to, contacts[])
   │        └──< os_proposals (status, blocks[] page-builder content,
   │                 contacts[], approvals[] -> os_proposal_approvals
   │                 {signature_text|image|type, esignature_agreement, ip_address, metadata})
   │
   ├──< os_projects (owner, start/due, billing, contacts[], tasks[], expenses[], invoices[])
   │        ├──< os_tasks (status, type, assigned_to, responsibility, is_visible_to_client,
   │        │             form -> forms (client-facing intake), files[], embed_url)
   │        └──  os_project_templates (tasks JSON)
   │
   └──< os_invoices (invoice_number, issue/due, subtotal, total_tax, total,
             amount_paid, amount_due, status paid|unpaid|void)
             ├──< os_invoice_items (item -> os_items catalog, quantity, unit_price,
             │       line_amount, tax_rate -> os_tax_rates, tax_amount, billable_expense -> os_expenses)
             └──< os_payments (stripe_payment_id, amount, transaction_fee, receipt_url, metadata)

Lead capture: forms (schema JSON, on_success, redirect_url) -> inbox {data JSON, form}
Analytics: events {key, service, session, user, metadata}, metrics {key, service, value}
Support: conversations/messages (visitor_id, contact_id), help_articles, help_feedback
Numbering: os_settings {next_invoice_number, next_proposal_number}
Email: os_email_templates {name, subject, body}
```

Status vocabularies actually used in code (CONFIRMED via grep): tasks `pending|in_progress|in_review|completed`; projects `active|in_progress|in_review|completed`; invoices `paid|unpaid|void`; deal stages are a lookup table (`os_deal_stages{name,color,sort}`) rather than an enum (`types/os/os-deal.ts`).

## Tool / plugin / MCP model

None. Integrations are hard-wired: Stripe (checkout session, billing portal, webhook) in `layers/portal/server/api/stripe/*.post.ts`; Directus via the SDK. The Nuxt server proxies every client call through `/api/proxy/*` to Directus (`server/api/proxy/[...].ts`). CONFIRMED.

## Sandbox and security posture

* Isolation: none beyond Directus role permissions. Portal reads use the logged-in user's own session token (`layers/portal/server/api/portal/search.get.ts` uses `withToken(access_token, ...)`), so row scoping is delegated to Directus permissions. CONFIRMED.
* Credential handling: a single admin static token `DIRECTUS_SERVER_TOKEN` is read from env into a module-level client (`server/utils/directus-server.ts`) and used by public, unauthenticated Nitro routes: `server/api/feedback.post.ts` (creates or updates any `help_feedback` row by caller-supplied `id`), `layers/portal/server/api/stripe/create-checkout-session.post.ts` (reads any invoice by caller-supplied `invoiceId`, no auth check, returns the Stripe session), `create-portal-link.post.ts` (opens a billing portal for any caller-supplied `customerId`). `.directus/docker-compose.yaml` ships hard-coded `KEY`, `SECRET`, `ADMIN_PASSWORD`. Preview mode accepts a Directus token in the query string (`modules/directus/runtime/plugins/directus.ts`). CONFIRMED.
* Gates / human-in-the-loop: the only "approval" is the client e-signature on a proposal (`os_proposal_approvals`, `layers/proposals/components/blocks/Acceptance.vue`). No approval gate exists for money movement other than Stripe's own checkout. Stripe webhook signature is verified (`webhooks.post.ts`), which is correct, but a verification failure calls `createError` without `throw` and execution continues; there is also no idempotency key, so Stripe retries would insert duplicate `os_payments`. `Acceptance.vue` swallows submit errors in an empty catch. CONFIRMED.
* Template injection: `.directus/run-scripts/interpolate.js` renders email templates with `new Function(...names, \`return \`${str}\`;\`)`, i.e. the template body is executed as JS. CONFIRMED.

## BEST PARTS

1. **Deal pipeline as data, not enum.** `os_deals.deal_stage -> os_deal_stages{name,color,sort}` plus `deal_value`, `close_date`, `next_contact_date`, `owner`, and a primary-contact flag on the join table (`types/os/os-deal.ts`). Sector: growth (sales). Why: stages are operator-editable rows, so a sales agent can only move a deal to a stage that exists; the kernel can gate stage transitions the same way pmmcp validates goal status transitions. `next_contact_date` is the natural cron hook for a follow-up scout.
2. **Activity log tied to deal, organization, and contacts.** `os_activities{deal, organization, activity_type, start_time, end_time, due_date, assigned_to, contacts[]}` (`types/os/os-activity.ts`). Sector: growth. Why: every outbound touch an agent makes (email drafted, call scheduled) becomes an activity row that a human can read and the CEO can plan against; it is the CRM-side mirror of our event log and keeps "what did the agent do to this lead" answerable without reading the chain.
3. **Proposal acceptance as a signed consent record.** `os_proposal_approvals{signature_text|image|type, esignature_agreement, ip_address, email, metadata, contact, proposal}` (`types/os/os-proposal.ts`, `layers/proposals/components/blocks/Acceptance.vue`). Sector: growth, executive. Why: this is the shape of a human-approval artifact that outlives the run: who, what, when, from where, and an explicit agreement checkbox. Our approvals projection (Phase 1) can adopt the same fields for operator decisions on `irreversible` tool calls, so approvals are replayable from the log.
4. **Invoice math lives server-side in event hooks, never in the client.** `.directus/run-scripts/calculate-invoice-items.ts` computes `line_amount` and `tax_amount` on item write; `calculate-invoice.ts` recomputes `subtotal`, `total_tax`, `total` from line items and returns only the changed fields. Sector: growth (billing), executive (budgets). Why: it is the right division of authority for us: agents propose line items, the kernel (not the model) derives totals; matches invariant 3's "the model never makes an access-control decision" extended to "the model never computes money".
5. **Lead capture is schema-driven and lands in a raw inbox.** `forms{schema JSON, on_success, redirect_url}` -> `inbox{data JSON, form}` (`types/content/form.ts`, `types/help/index.ts`, `components/base/UForm.vue`), with a Flow script that validates form field names against the target collection (`.directus/run-scripts/validate-schema.js`). Sector: growth (marketing), ops-security. Why: inbound leads are untrusted input; keeping them as opaque JSON in an `inbox` table before promotion to `contacts`/`os_deals` is exactly the tainted-ingress shape our `comms` agent needs. Promotion from inbox to contact is a `write` on a tainted run, so it requires a human under invariant 3.
6. **Organization as the billing and identity root.** `organizations{stripe_customer_id, payment_terms, ap_contact, addresses[] with is_primary_billing, brand_color, logo}` and `contacts` many-to-many via `organizations_contacts` (`types/os/organization.ts`, `types/os/contact.ts`). Sector: growth. Why: one account root that both sales and billing hang off avoids the duplicate-customer problem; the Stripe customer id being on the organization (not the contact) is the correct join for a publisher/sales agent that must never see card data.
7. **Client-assignable tasks with an attached intake form.** `os_tasks{responsibility, is_visible_to_client, form -> forms, files[], type}` and `os_project_templates{tasks JSON}` (`types/os/os-task.ts`, `types/os/os-project.ts`). Sector: engineering (project delivery), growth. Why: a task can be owned by the counterparty and carry a structured form for what they owe you; maps directly to a CEO-planned pmmcp task whose blocker is "waiting on human input", with the form schema telling the UI what to ask.
8. **Generic `events` / `metrics` tables with `service` and `session` keys.** `types/meta/analytics.ts`. Sector: executive, growth. Why: a minimal product-analytics schema (`key`, `service`, `session`, `user`, `metadata`, numeric `value`) is enough for a marketing agent to report campaign metrics into memory without inventing a schema per campaign.

## BAD PARTS / anti-patterns

1. **Admin static token behind unauthenticated public routes.** `server/utils/directus-server.ts` builds a module-level client with `DIRECTUS_SERVER_TOKEN`; `server/api/feedback.post.ts` lets any caller update any `help_feedback` row by `id`; `layers/portal/server/api/stripe/create-checkout-session.post.ts` reads any invoice by caller-supplied `invoiceId` with no ownership check; `create-portal-link.post.ts` opens a Stripe billing portal for any `customerId`. Why we leave it out: this is the OpenClaw posture (one omnipotent credential reachable from the edge). Our invariant 2 puts credentials only at the kernel/egress edge with per-call policy; a sales agent gets a scoped tool view, never the admin token.
2. **Email templates executed as JavaScript.** `.directus/run-scripts/interpolate.js` uses `new Function` over the template body. Why we leave it out: template content is operator-editable data; running it is code execution from a database row. Our writer/publisher agents must render with a non-evaluating templater and treat template bodies as data.
3. **Secrets and keys committed in the compose file.** `.directus/docker-compose.yaml` hard-codes `KEY`, `SECRET`, `ADMIN_PASSWORD`, DB password, `CORS_ENABLED: true`, empty `IMPORT_IP_DENY_LIST`. Why we leave it out: violates "never write a secret into any file under the repo"; all of ours come from the pmmcp vault via the broker.
4. **Money-path handlers that fail open or duplicate.** `webhooks.post.ts` calls `createError` without `throw` on signature failure and continues; no idempotency on `checkout.session.completed` so Stripe retries create duplicate `os_payments`; `payment_date` has an operator-precedence bug (`created ?? 0 * 1000`); `Acceptance.vue` has an empty catch. Why we leave it out: payment and consent recording must be exactly-once and fail-closed; our event log's hash chain plus an idempotency key per external event id is the replacement.
5. **Token in the query string for preview mode.** `modules/directus/runtime/plugins/directus.ts` reads `?token=` and calls `directus.setToken(token)`. Why we leave it out: directly contradicts invariant 1 (query-string tokens rejected); tokens leak via referer, logs, and history.
6. **Totals stored as strings and recomputed by comparing `toFixed(2)` output.** `.directus/run-scripts/calculate-invoice.ts` compares `invoice.subtotal !== subtotal.toFixed(2)` and writes string values; `parseFloat` on money. Why we leave it out: money should be integer minor units (the repo itself has `dollarsToCents` in `utils/currency.ts` but the Flow ignores it). Our trading and billing sectors need integer-cent or decimal-string arithmetic with a single canonical representation.

## Conflicts with CLAUDE.md invariants

1. Invariant 1 (bearer in header only, query tokens rejected): preview mode accepts `?token=` (`modules/directus/runtime/plugins/directus.ts`). Conflict if copied.
2. Invariant 2 (agents never hold a credential): the pattern of a shared admin token in server routes reachable from the public edge (`server/utils/directus-server.ts` and its callers) is the exact anti-pattern; any sales agent built on this would hold the key.
3. Invariant 3 (policy gate, default deny, irreversible => human): money-moving routes (`create-checkout-session`, `create-portal-link`) have no authorization check and no human gate; proposal acceptance writes directly from the browser.
4. Invariant 5 (every event redacted, hashed, chained; no UPDATE/DELETE): `feedback.post.ts` and the Directus data model are freely mutable by id; there is no append-only audit trail for deals, invoices, or approvals beyond Directus's own revision system (not in repo, INFERRED).
5. "Never write a secret into any file under the repo": `.directus/docker-compose.yaml` does.
6. Invariant 8 spirit (agents cannot execute operator-editable content): `interpolate.js` executes template bodies as code.

## Verdict

Take the schema, not the code: the organization/contact/deal/stage/activity/proposal-approval/invoice/line-item/payment graph, the `inbox`-then-promote lead pattern, and the rule that totals are derived server-side by a hook the model cannot touch, and express them as pmmcp collections or a kernel-owned SQLite projection that the growth sector's `sales`, `marketer`, and `comms` agents can read and, with gates, write. Leave every server route, the shared admin token, query-string tokens, the JS-evaluating templater, the committed secrets, and the fail-open webhook. There is nothing here for orchestration, memory, or sandboxing; its value to the fleet is a proven, minimal CRM-plus-billing data model with named status vocabularies we can gate on.
