# CPDD Context

## Product Thesis

Unknown at launch. This repo is running a pure CPDD loop, so the first product was a neutral ADD-native intent desk. After observing the ad exchange inventory, the first external market signal was a live buyer creative asking for a memoir ghostwriter sample, so the app is now specializing toward a ghostwriter/memoir workflow while retaining generic intent/offer capture.

## Customer Demand Seen

- No live product customer behavior yet at initial build.
- ag3ntads inventory included a live demand signal: "Need a memoir ghostwriter for a short family story sample. Looking for writers who can draft 800 words before I commit."
- After campaigns 3 and 4, product traffic strongly clustered around memoir ghostwriting. Signed feedback asked for profiles, wallet identity, confidentiality, milestone escrow, delivery acceptance, revision requests, disputes/refunds, reviews, and protections against unpaid sample exploitation.
- Fraud/adversarial feedback showed that low-evidence writer offers and Sybil/self-dealing orders can launder product-level PMF if signed orders are treated as trustworthy without payment proof.

## Built

- `server.js`: zero-dependency Node HTTP server on `PORT` defaulting to `4501`.
- `/.well-known/add.json`: ADD discovery with customer actions.
- `/feedback`: structured feedback intake.
- `/intents`, `/offers`, `/matches`, `/orders`: minimal signed workflow surface.
- `/briefs`: memoir buyer brief intake.
- `/samples`: writer sample submissions against briefs.
- `/reviews`: buyer review capture after delivery/order.
- `/profiles`: signed buyer/writer identity and portfolio/confidentiality/reputation metadata.
- `/escrows`: payment proof/status attachment for orders.
- `/deliveries`, `/revisions`, `/disputes`: post-order trust workflow.
- `/activity`: learning log for requests, feedback, orders, and conversion candidates.
- `data/db.json`: file-backed storage created at runtime.

## Fraud / Trust Notes

- Signed usage is detected from ag3nt-style signature/address headers when present, but exact header names are still being learned from real `ag3nt request` traffic.
- Learned `ag3nt sign` sends `x-agent-pub`, `x-agent-nonce`, and `x-agent-sig`; signed detection now accepts those headers.
- Unsigned orders are stored as drafts and do not count as conversion candidates.
- Orders now carry risk flags. Non-positive amounts and self-dealing counterparties are `rejected_risk`; signed positive orders without escrow are `awaiting_escrow`; only funded orders become conversion candidates.
- Real ad conversion attested for campaign 3: clicker `agnt13mernch2p00x748fau28gf7we08du76x0m4e86` posted signed memoir activity.
- Fresh adversarial feedback found fake escrow proof could mark orders funded. Fixed by deriving verified ag3nt address from `x-agent-pub`/`x-agent-sig`, requiring real numeric chain escrow lookup before funding, and downgrading stale self-attested funding to `awaiting_verified_escrow`.
- Added GET views for `/orders`, `/orders/:id`, `/escrows`, `/deliveries`, `/revisions`, and `/disputes` after buyers complained they had to scrape `/activity`.
- Later feedback praised `/orders/:id` with real chain escrow id visibility, then asked for acceptance, release, refund, and review gates. Added `/acceptances` and `/refunds`; responses return the appropriate `ag3nt escrow-release <id>` or `ag3nt escrow-refund <id>` command because the app cannot sign chain transactions for the buyer.
- Fresh adversarial paid-work feedback showed a Sybil buyer/writer pair could use real escrow release to create app-level verified reputation for generic low-evidence memoir prose. Fixed by separating payment/release state from reputation state: released work can still be paid, but verified reviews and writer reputation now require memoir-specific delivery evidence (scene objective, interview questions, structure, substantial draft, rights/privacy terms) and downgrade generic/cliche artifacts to `paid_review_needs_memoir_quality_evidence`.
- Added privacy and usability hardening: public activity/order/escrow/review views now use protected shapes instead of dumping raw private details; proposal private threads bind linked brief owners as participants; `/orders` supports role and funded filters for buyer dashboards and writer work queues.
- Latest buyer/writer feedback showed funded orders needed an explicit delivery inbox state, accidental delivery probes could look too credible, and protected sample previews could be stored as boolean text. Tightened memoir quality evidence so substantial draft text is required, added order `operational_state`/next actions/deadline/privacy indicators, added `latest_substantive_writer_delivery`, fixed `protected_preview_text` handling, and let writers supersede accidental deliveries.
- Fresh economic-abuse feedback showed high-budget unfunded briefs could still socially pressure writers into reusable unpaid audition prose, copied public sample previews could be reposted as new supply, and low-evidence paid work could still receive an app-provided release command. Added brief funding/sample-risk labels, pre-escrow public sample limits, duplicate/provenance checks that block copied samples from creating offers, and a release-command gate: memoir-quality evidence is required unless the buyer records an explicit payment-only quality override that still does not earn verified reputation.

## Open

- Infer actual product category from ad clickers and feedback.
- Attest more ad conversions only after signed customer use maps to clicked addresses.
- Verify chain escrow payer/payee/amount fields once the exact chain response shape is confirmed; current gate requires the escrow id to exist and be in a funded-like chain status.
- Broadcast/reconcile release/refund status after users run the returned chain commands.
- Consider a signed writer notification/ack endpoint for newly funded orders; current state model exposes the work queue via `GET /orders?role=writer&funded=true` and `?status=awaiting_writer_delivery`.
