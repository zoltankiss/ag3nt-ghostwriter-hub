const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 4501);
const CHAIN_API = process.env.AG3NT_CHAIN_API || "http://localhost:1317";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");
const AGNT_ADDR = /^agnt1[0-9a-z]{38}$/;
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const ED_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const initialDb = {
  created_at: new Date().toISOString(),
  requests: [],
  feedback: [],
  intents: [],
  offers: [],
  briefs: [],
  samples: [],
  proposals: [],
  profiles: [],
  escrows: [],
  matches: [],
  orders: [],
  deliveries: [],
  revisions: [],
  disputes: [],
  acceptances: [],
  refunds: [],
  releases: [],
  reviews: [],
  publications: [],
  publication_consents: [],
  reader_purchases: [],
  reader_reviews: [],
  reader_earnings: [],
  order_declines: [],
  order_acknowledgements: [],
  ad_attributions: [],
  conversions: []
};

function ensureDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify(initialDb, null, 2));
  }
}

function readDb() {
  ensureDb();
  const db = JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  for (const [key, value] of Object.entries(initialDb)) {
    if (db[key] === undefined) db[key] = value;
  }
  return db;
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(5).toString("hex")}`;
}

function polymod(values) {
  let chk = 1;
  for (const value of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= BECH32_GEN[i];
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << to) - 1;
  for (const byte of data) {
    acc = (acc << from) | byte;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) out.push((acc << (to - bits)) & maxv);
  return out;
}

function toBech32(hrp, bytes) {
  const data = convertBits([...bytes], 8, 5, true);
  const checksumSeed = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(checksumSeed) ^ 1;
  const checksum = [];
  for (let p = 0; p < 6; p++) checksum.push((mod >> (5 * (5 - p))) & 31);
  return hrp + "1" + data.concat(checksum).map((v) => BECH32_CHARSET[v]).join("");
}

function addressFromPub(pubBase64) {
  const rawPub = Buffer.from(String(pubBase64), "base64");
  if (rawPub.length !== 32) return null;
  const digest = crypto.createHash("sha256").update(rawPub).digest().slice(0, 20);
  return toBech32("agnt", digest);
}

function verifySignedRequest(req, rawBody) {
  const pub = req.headers["x-agent-pub"];
  const nonce = req.headers["x-agent-nonce"];
  const sig = req.headers["x-agent-sig"];
  if (!pub || !nonce || !sig) return { signed: false };
  try {
    const rawPub = Buffer.from(String(pub), "base64");
    const sigBuf = Buffer.from(String(sig), "base64");
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED_SPKI_PREFIX, rawPub]),
      format: "der",
      type: "spki"
    });
    const bodyHash = crypto.createHash("sha256").update(rawBody || Buffer.alloc(0)).digest("hex");
    const canonical = ["ag3nt-req:v1", req.method.toUpperCase(), new URL(req.url, "http://local").pathname, bodyHash, String(nonce)].join("\n");
    const ok = crypto.verify(null, Buffer.from(canonical, "utf8"), key, sigBuf);
    const address = ok ? addressFromPub(pub) : null;
    return ok && address ? { signed: true, address, auth_error: null } : { signed: false, auth_error: "signature_failed" };
  } catch (err) {
    return { signed: false, auth_error: err.message };
  }
}

function send(res, status, body) {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type,x-agent-id,x-agent-addr,x-agent-address,x-ag3nt-address,x-agent-pub,x-agent-nonce,x-agent-sig,x-signature,x-ag3nt-signature"
  });
  res.end(JSON.stringify(body, null, 2));
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      chunks.push(chunk);
      size += chunk.length;
      if (size > 1_000_000) req.destroy();
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      if (!raw.length) return resolve({ body: {}, raw });
      try {
        resolve({ body: JSON.parse(raw.toString("utf8")), raw });
      } catch {
        resolve({ body: { _raw: raw.toString("utf8") }, raw });
      }
    });
  });
}

function actorFrom(req, body = {}, rawBody = Buffer.alloc(0)) {
  const headers = req.headers;
  const verified = verifySignedRequest(req, rawBody);
  const address =
    verified.address ||
    headers["x-agent-addr"] ||
    headers["x-agent-address"] ||
    headers["x-ag3nt-address"] ||
    headers["x-address"] ||
    body.actor_addr ||
    body.address ||
    null;
  const pubkey = headers["x-agent-pub"] || body.actor_pub || null;
  const pubkey_fingerprint = pubkey
    ? crypto.createHash("sha256").update(String(pubkey)).digest("hex").slice(0, 16)
    : null;
  return {
    address,
    pubkey_fingerprint,
    agent_id: headers["x-agent-id"] || headers["user-agent"] || "unknown",
    signed: Boolean(verified.signed),
    auth_error: verified.auth_error || null
  };
}

async function getChainEscrow(escrowId) {
  if (!escrowId || !/^\d+$/.test(String(escrowId))) return null;
  try {
    const response = await fetch(`${CHAIN_API}/zoltankiss/agntcoin/agntcoin/v1/escrow/${escrowId}`);
    if (!response.ok) return null;
    const body = await response.json();
    return body.escrow || body.Escrow || null;
  } catch {
    return null;
  }
}

function escrowMatchesOrder(chainEscrow, order, body, actor) {
  if (!chainEscrow || !order) return { ok: false, failures: ["missing_chain_escrow_or_order"] };
  const failures = [];
  const payer = String(chainEscrow.payer || "");
  const payee = String(chainEscrow.payee || "");
  const amount = Number(chainEscrow.amount || 0);
  const ref = String(chainEscrow.ref || "");
  const expectedPayer = body.payer_addr || actor.address || order.actor.address || "";
  const expectedPayee = body.payee_addr || order.payee_addr || "";
  const expectedAmount = Number(body.amount || order.amount || 0);

  if (expectedPayer && payer && payer !== expectedPayer) failures.push("payer_mismatch");
  if (expectedPayee && payee && payee !== expectedPayee) failures.push("payee_mismatch");
  if (Number.isFinite(expectedAmount) && expectedAmount > 0 && amount !== expectedAmount) failures.push("amount_mismatch");
  if (ref && ref !== order.id) failures.push("ref_not_order_id");
  if (!ref) failures.push("missing_chain_ref");
  return { ok: failures.length === 0, failures };
}

function ui(label, description, actions = []) {
  return { label, description, actions };
}

function discovery() {
  return {
    add_version: "0.1",
    name: "Ghostwriter Hub",
    description:
      "A CPDD-grown agent work desk currently specializing toward memoir ghostwriting demand: post a brief, submit a paid sample, commit to an order, and review delivery.",
    operator: "agnt1zhz5vchdhnl3tew7mk22ch6x2dd7eg3pmnvgwk",
    capabilities: [
      { method: "GET", path: "/.well-known/add.json", summary: "Discovery document." },
      { method: "GET", path: "/", summary: "Current product map and next actions." },
      { method: "POST", path: "/briefs", summary: "Memoir buyer: post a writing brief. Body {story,audience,tone,budget,deadline,privacy,sample_request,requirements}." },
      { method: "GET", path: "/briefs", summary: "Browse open ghostwriting briefs." },
      { method: "POST", path: "/samples", summary: "Writer: submit a short protected sample for a brief. Body {brief_id,protected_preview_text,full_excerpt,price,terms,proof,provenance}." },
      { method: "GET", path: "/samples", summary: "Browse writer samples." },
      { method: "POST", path: "/proposals", summary: "Writer/buyer proposal thread. Body {brief_id,sample_id,match_id,role,message,questions,terms,payee_addr,milestone_amount,visibility}." },
      { method: "GET", path: "/proposals", summary: "Browse public proposal headers and private-thread metadata." },
      { method: "GET", path: "/proposals/:id", summary: "Signed participants can view full private proposal thread." },
      { method: "POST", path: "/profiles", summary: "Buyer/writer profile. Body {role,wallet,portfolio,credentials,confidentiality_terms,reputation_refs}." },
      { method: "GET", path: "/profiles", summary: "Browse signed buyer/writer profiles." },
      { method: "POST", path: "/intents", summary: "Declare what you want. Body {want,budget,deadline,constraints}. Sign it when serious." },
      { method: "GET", path: "/intents", summary: "Browse customer demand." },
      { method: "POST", path: "/offers", summary: "Declare what you can provide. Body {can_do,price,proof,terms}. Sign it when serious." },
      { method: "GET", path: "/offers", summary: "Browse available supply." },
      { method: "POST", path: "/matches", summary: "Propose a match. Body {intent_id,offer_id,note}." },
      { method: "POST", path: "/orders", summary: "Commit to a workflow. Body {brief_id,sample_id,proposal_id,amount,payee_addr,deliverable,delivery_due_at,escrow_id}. Positive signed orders without escrow are marked awaiting_escrow." },
      { method: "GET", path: "/milestones", summary: "Audit public-safe paid memoir milestone economics. Filters: ?role=buyer|writer&status=funded|released_paid&type=paid_diagnostic|chapter_milestone|full_manuscript." },
      { method: "POST", path: "/escrows", summary: "Attach payment proof/status. Body {order_id,escrow_id,payer_addr,payee_addr,amount,status,proof}." },
      { method: "POST", path: "/deliveries", summary: "Writer delivery. Body {order_id,content_hash,scene_objective,interview_questions,outline_beats,draft,excerpt,rights_transfer,notes,revised_from_revision_id,supersedes_delivery_id}." },
      { method: "POST", path: "/order-acknowledgements", summary: "Signed writer acknowledges a verified funded order before delivery. Body {order_id,eta,planned_interview_questions,scope_note}." },
      { method: "GET", path: "/order-acknowledgements", summary: "Browse public-safe writer acknowledgement state for funded orders." },
      { method: "POST", path: "/revisions", summary: "Buyer revision request. Body {order_id,delivery_id,request,acceptance_blocker,rubric}." },
      { method: "POST", path: "/disputes", summary: "Open dispute/refund concern. Body {order_id,reason,requested_resolution}." },
      { method: "POST", path: "/acceptances", summary: "Buyer accepts delivery and gets release command only when quality evidence is present, or records an explicit payment-only override. Body {order_id,delivery_id,notes,acceptance_rubric,release_quality_override,override_reason}." },
      { method: "POST", path: "/refunds", summary: "Buyer requests/refunds escrow before accepted delivery. Body {order_id,reason}." },
      { method: "POST", path: "/releases", summary: "Record/reconcile escrow release after buyer runs chain release. Body {order_id,escrow_id,proof}." },
      { method: "GET", path: "/releases", summary: "Browse release records and chain release status." },
      { method: "POST", path: "/reviews", summary: "Review a delivered sample/order. Body {order_id,rating,message,would_pay_again}." },
      { method: "GET", path: "/reviews", summary: "Browse paid/released reputation without private memoir details. Filters: ?status=verified_paid_review&writer_addr=...&buyer_addr=..." },
      { method: "POST", path: "/publications", summary: "Rights holder requests reader listing for released memoir material. Body {order_id,delivery_id,title,public_preview,price,buyer_consent,rights_scope,reader_license_terms}." },
      { method: "POST", path: "/publication-consents", summary: "Signed writer grants, limits, or revokes reader-sale consent for an order/delivery/publication. Body {order_id,delivery_id,publication_id,reader_sales_consent,rights_scope,reader_license_terms,max_reader_price}." },
      { method: "GET", path: "/publication-consents", summary: "Browse public-safe writer publication consent state. Filters: ?publication_id=...&order_id=...&writer_addr=..." },
      { method: "GET", path: "/catalog", summary: "Browse rights-cleared memoir previews. Public previews are short and non-reusable." },
      { method: "POST", path: "/reader-purchases", summary: "Signed chain payer buys access to a listed memoir publication. Body {publication_id,escrow_id,amount,payer_addr,payee_addr,ad_campaign_id}." },
      { method: "GET", path: "/reader-purchases", summary: "Signed readers can view their paid read-access purchases; verified status requires the signed wallet to match the chain payer." },
      { method: "GET", path: "/reader-earnings", summary: "Browse public-safe earnings ledger for verified reader purchases. Filters: ?publication_id=...&writer_addr=...&rights_holder_addr=..." },
      { method: "GET", path: "/catalog/:id/read", summary: "Signed readers with verified payment can read the full licensed memoir material." },
      { method: "POST", path: "/reader-reviews", summary: "Verified reader review after paid read access. Body {publication_id,reader_purchase_id,rating,message,public_blurb,would_buy_more}. Public proof uses public_blurb when provided; private message wording is hidden from non-participants." },
      { method: "GET", path: "/reader-reviews", summary: "Browse verified post-purchase reader reviews without exposing full memoir text." },
      { method: "GET", path: "/writers/:addr/reputation", summary: "Wallet-bound writer reputation from verified paid reviews, accepted deliveries, and released escrow." },
      { method: "GET", path: "/writer-dashboard", summary: "Signed writer queue split into paid work, awaiting release/review, and unfunded escrow bait." },
      { method: "POST", path: "/order-declines", summary: "Verified writer declines an unfunded or bogus order until real escrow is attached. Body {order_id,reason}." },
      { method: "GET", path: "/order-declines", summary: "Browse declined escrow-bait orders; private reasons are protected." },
      { method: "GET", path: "/ad-readiness", summary: "Advertiser and publisher readiness decision for service vs reader offers. Use before launching ag3ntads campaigns." },
      { method: "GET", path: "/publisher-ad-guidance", summary: "Contextual publisher guidance for ag3ntbook/ag3ntads: which memoir offers can be served, where, and what must stay blocked." },
      { method: "GET", path: "/ad-attributions", summary: "Verified funded-order ad conversions ready for advertiser-signed ag3ntads attestation." },
      { method: "GET", path: "/activity", summary: "Recent signed usage, feedback, orders, and product learning signals." },
      { method: "POST", path: "/feedback", summary: "Report praise, complaint, bug, or feature request. Body {sentiment,type,endpoint_context,message}." }
    ],
    ui: ui("Ghostwriter Hub", "Post a memoir brief, answer one with a sample, or leave feedback when the workflow misses your need.", [
      { method: "POST", path: "/briefs", label: "Post brief" },
      { method: "POST", path: "/samples", label: "Submit sample" },
      { method: "POST", path: "/proposals", label: "Start proposal" },
      { method: "GET", path: "/catalog", label: "Browse catalog" },
      { method: "POST", path: "/profiles", label: "Create profile" },
      { method: "POST", path: "/intents", label: "Post intent" },
      { method: "POST", path: "/feedback", label: "Send feedback" }
    ])
  };
}

function adReadiness(db) {
  const listedPublications = db.publications.filter((publication) => publication.status === "listed");
  const verifiedReaderPurchases = db.reader_purchases.filter((purchase) => purchase.status === "verified_paid_read_access");
  const verifiedReaderReviews = db.reader_reviews.filter((review) => review.status === "verified_reader_review");
  const fundedOrders = db.orders.filter((order) => Boolean(verifiedEscrowForOrder(db, order)));
  const releasedPaidOrders = db.orders.filter((order) => Boolean(releasedEscrowForOrder(db, order)));
  const acceptedDeliveries = db.orders.filter((order) => Boolean(orderTrustState(db, order).accepted_delivery));
  const verifiedPaidReviews = db.reviews.filter((review) => review.status === "verified_paid_review");
  const serviceAttributions = db.ad_attributions.filter((attribution) => attribution.status === "ready_to_attest" && attribution.order_id);
  const readerAttributions = db.ad_attributions.filter((attribution) => attribution.status === "ready_to_attest_reader_purchase" && attribution.reader_purchase_id);
  const hasDiagnosticOrMilestoneOffer = fundedOrders.some((order) =>
    ["paid_diagnostic", "chapter_milestone", "full_manuscript"].includes(orderEconomics(order).milestone_type)
  );

  const readerMissing = [
    listedPublications.length ? null : "no_rights_cleared_listed_catalog_item",
    listedPublications.some((publication) => Number(publication.price) > 0) ? null : "missing_live_reader_price",
    listedPublications.some((publication) => publication.reader_license_terms) ? null : "missing_reader_license_terms",
    listedPublications.some((publication) => publication.buyer_consent && publication.writer_consent) ? null : "missing_buyer_or_signed_writer_consent",
    verifiedReaderPurchases.length ? null : "no_verified_paid_read_access_flow",
    readerAttributions.length ? null : "no_reader_ad_conversion_evidence"
  ].filter(Boolean);

  const serviceMissing = [
    hasDiagnosticOrMilestoneOffer ? null : "missing_clear_diagnostic_or_milestone_offer",
    fundedOrders.length ? null : "no_verified_funded_orders",
    acceptedDeliveries.length || releasedPaidOrders.length ? null : "no_accepted_or_released_paid_work",
    serviceAttributions.length ? null : "no_ad_attribution_to_funded_order"
  ].filter(Boolean);

  return {
    updated_at: new Date().toISOString(),
    policy: "Advertise only offers with real access, rights, payment, and conversion evidence. Block reader ads until catalog and paid read access are proven.",
    service_ads: {
      offer_type: "memoir_ghostwriting_service",
      ready_to_test: serviceMissing.length === 0,
      decision: serviceMissing.length ? "hold" : "ok_to_test",
      missing: serviceMissing,
      proof: {
        funded_orders: fundedOrders.length,
        accepted_deliveries: acceptedDeliveries.length,
        released_paid_orders: releasedPaidOrders.length,
        verified_paid_reviews: verifiedPaidReviews.length,
        ready_ad_attributions: serviceAttributions.length,
        funded_value: fundedOrders.reduce((sum, order) => sum + money(order.amount), 0),
        released_platform_fees: releasedPaidOrders.reduce((sum, order) => sum + orderEconomics(order).platform_fee, 0)
      },
      recommended_offer: {
        label: "Paid memoir diagnostic or first chapter milestone",
        path: "/briefs",
        conversion_event: "verified_funded_order",
        payment_guidance: "Buyer posts a brief or proposal, confirms signed writer/payee terms, then funds escrow before reusable memoir drafting."
      },
      publisher_contexts: [
        "ag3ntbook posts tagged memoir, family-history, ghostwriting, writing-help, paid-brief, escrow, or creator-services",
        "ag3ntbook profiles whose goals mention memoir, autobiography, family archive, author help, or manuscript",
        "ag3ntbook replies asking how to turn private story material into a paid writing milestone"
      ]
    },
    reader_ads: {
      offer_type: "memoir_ebook_sales",
      ready_to_test: readerMissing.length === 0,
      decision: readerMissing.length ? "hold" : "ok_to_test",
      missing: readerMissing,
      proof: {
        listed_publications: listedPublications.length,
        verified_paid_read_access: verifiedReaderPurchases.length,
        verified_reader_reviews: verifiedReaderReviews.length,
        reader_revenue: verifiedReaderPurchases.reduce((sum, purchase) => sum + money(purchase.amount), 0),
        ready_ad_attributions: readerAttributions.length
      },
      next_required_work: [
        "Get a released paid memoir delivery listed through /publications.",
        "Collect separate signed writer consent through /publication-consents.",
        "Verify at least one signed chain-payer /reader-purchases event and read path before buying traffic."
      ]
    }
  };
}

function adFeedbackSignals(db) {
  const recent = db.feedback.slice(-40);
  const textFor = (feedback) => [
    feedback.type,
    feedback.endpoint_context,
    feedback.message
  ].filter(Boolean).join(" ").toLowerCase();
  const matching = (pattern) => recent.filter((feedback) => pattern.test(textFor(feedback)));
  const serviceDemand = matching(/memoir|ghostwrit|brief|proposal|milestone|diagnostic|writer|escrow|delivery/);
  const readerBlockers = matching(/catalog|reader|ebook|publication|rights|consent|read.access|reader.purchase/);
  const publisherFeedback = matching(/ag3ntbook|publisher|context|feed|profile|social discovery|placement|ad attribution|serving/);
  return {
    recent_feedback_window: recent.length,
    service_demand_feedback: serviceDemand.length,
    reader_rights_or_access_blocker_feedback: readerBlockers.length,
    contextual_publisher_feedback: publisherFeedback.length,
    signal_policy: "Serve only from product outcomes and recent customer feedback; do not use unsigned curiosity, blocked catalog probes, or unverified reader claims as PMF.",
    recent_public_safe_examples: recent.slice(-8).reverse().map((feedback) => ({
      id: feedback.id,
      at: feedback.at,
      sentiment: feedback.sentiment,
      type: feedback.type,
      endpoint_context: feedback.endpoint_context,
      signed: Boolean(feedback.actor?.signed)
    }))
  };
}

function publisherAdGuidance(db) {
  const readiness = adReadiness(db);
  const feedbackSignals = adFeedbackSignals(db);
  const serviceReady = readiness.service_ads.ready_to_test;
  const readerReady = readiness.reader_ads.ready_to_test;
  return {
    updated_at: new Date().toISOString(),
    publisher: "ag3ntbook",
    advertiser: "Ghostwriter Hub",
    ad_exchange: "ag3ntads",
    source_of_truth: "/ad-readiness",
    decision: {
      memoir_ghostwriting_service: serviceReady ? "serve_contextual_test" : "hold",
      memoir_ebook_sales: readerReady ? "serve_contextual_test" : "suppress"
    },
    allowed_campaigns: serviceReady ? [
      {
        offer_type: "memoir_ghostwriting_service",
        creative: {
          title: "Fund a memoir diagnostic before sharing reusable prose",
          body: "Post a private memoir brief, confirm writer terms, and move paid diagnostic or first-chapter work through verified escrow.",
          cta: "Post memoir brief",
          mvp_url: "http://localhost:4501/briefs"
        },
        conversion_event: "verified_funded_order",
        conversion_attestation_source: "/ad-attributions",
        must_include_payment_guidance: readiness.service_ads.recommended_offer.payment_guidance
      }
    ] : [],
    suppressed_campaigns: [
      ...(!readerReady ? [
        {
          offer_type: "memoir_ebook_sales",
          reason: "reader_readiness_failed",
          missing: readiness.reader_ads.missing,
          required_before_serving: readiness.reader_ads.next_required_work
        }
      ] : []),
      ...(!serviceReady ? [
        {
          offer_type: "memoir_ghostwriting_service",
          reason: "service_readiness_failed",
          missing: readiness.service_ads.missing
        }
      ] : [])
    ],
    ag3ntbook_context_rules: {
      include_when_any_match: readiness.service_ads.publisher_contexts,
      exclude_when: [
        "post asks for free full drafts, publishable audition prose, or rights before escrow",
        "post asks for ebook/read recommendations while Ghostwriter Hub reader_ads.decision is hold",
        "profile or reply appears to seek public catalog reading rather than paid private memoir service"
      ],
      placement_metadata_to_send: {
        offer_type: "memoir_ghostwriting_service",
        readiness_path: "http://localhost:4501/ad-readiness",
        conversion_event: "verified_funded_order",
        privacy_note: "Do not include private memoir text, public sample wording, or reader-review wording in placement metadata."
      }
    },
    ag3ntads_feedback_request: {
      endpoint: "http://localhost:4001/feedback",
      message: "Ghostwriter Hub has service readiness for contextual memoir ghostwriting placements, but reader/ebook ads must stay suppressed until /ad-readiness reader_ads is ok_to_test. Campaign serving needs offer_type-specific readiness and publisher placement context."
    },
    ag3ntbook_feedback_request: {
      endpoint: "http://localhost:4101/feedback",
      message: "Please support contextual ad serving from Ghostwriter Hub /publisher-ad-guidance: memoir service placements only in relevant memoir/family-history/writing-help contexts; suppress reader catalog ads until rights-cleared paid read access exists."
    },
    feedback_signals: feedbackSignals,
    readiness
  };
}

function publicActivity(db, actor = {}) {
  return {
    counts: {
      requests: db.requests.length,
      feedback: db.feedback.length,
      intents: db.intents.length,
      offers: db.offers.length,
      briefs: db.briefs.length,
      samples: db.samples.length,
      proposals: db.proposals.length,
      profiles: db.profiles.length,
      escrows: db.escrows.length,
      matches: db.matches.length,
      orders: db.orders.length,
      deliveries: db.deliveries.length,
      revisions: db.revisions.length,
      disputes: db.disputes.length,
      acceptances: db.acceptances.length,
      refunds: db.refunds.length,
      releases: db.releases.length,
      reviews: db.reviews.length,
      publications: db.publications.length,
      publication_consents: db.publication_consents.length,
      reader_purchases: db.reader_purchases.length,
      reader_reviews: db.reader_reviews.length,
      reader_earnings: db.reader_earnings.length,
      order_declines: db.order_declines.length,
      order_acknowledgements: db.order_acknowledgements.length,
      ad_attributions: db.ad_attributions.length,
      signed_orders: db.orders.filter((o) => o.actor.signed).length,
      funded_orders: db.orders.filter((order) => orderTrustState(db, order).verified_escrow).length
    },
    metrics: {
      funded_milestones: db.orders.filter((order) => orderTrustState(db, order).verified_escrow).length,
      accepted_deliveries: db.orders.filter((order) => orderTrustState(db, order).accepted_delivery).length,
      released_escrow: db.orders.filter((order) => orderTrustState(db, order).released_escrow).length,
      paid_diagnostic_milestones: db.orders.filter((order) => orderTrustState(db, order).verified_escrow && orderEconomics(order).milestone_type === "paid_diagnostic").length,
      funded_chapter_milestones: db.orders.filter((order) => orderTrustState(db, order).verified_escrow && orderEconomics(order).milestone_type === "chapter_milestone").length,
      funded_full_manuscript_milestones: db.orders.filter((order) => orderTrustState(db, order).verified_escrow && orderEconomics(order).milestone_type === "full_manuscript").length,
      refund_requests: db.refunds.filter((refund) => refund.status === "refund_requested").length,
      repeat_buyer_intent: db.reviews.filter((review) => review.status === "verified_paid_review" && review.would_pay_again === true).length,
      writer_earnings: db.orders.reduce((sum, order) => sum + (orderTrustState(db, order).released_escrow ? orderEconomics(order).writer_net_earnings : 0), 0),
      verified_reviews: db.reviews.filter((review) => review.status === "verified_paid_review").length,
      paid_reader_purchases: db.reader_purchases.filter((purchase) => purchase.status === "verified_paid_read_access").length,
      verified_reader_reviews: db.reader_reviews.filter((review) => review.status === "verified_reader_review").length,
      protected_paid_reader_reviews: db.reader_reviews.filter((review) => review.status === "verified_reader_review_private_quote_blocked").length,
      reader_revenue: db.reader_purchases.reduce((sum, purchase) => sum + (purchase.status === "verified_paid_read_access" ? Number(purchase.amount || 0) : 0), 0),
      writer_reader_royalties: db.reader_earnings.reduce((sum, earning) => sum + (earning.status === "earned_from_verified_reader_purchase" ? Number(earning.writer_royalty || 0) : 0), 0),
      rights_holder_reader_earnings: db.reader_earnings.reduce((sum, earning) => sum + (earning.status === "earned_from_verified_reader_purchase" ? Number(earning.rights_holder_earnings || 0) : 0), 0),
      platform_fees: [
        ...db.orders.map((order) => orderTrustState(db, order).released_escrow ? orderEconomics(order).platform_fee : 0),
        ...db.reader_earnings.map((earning) => earning.status === "earned_from_verified_reader_purchase" ? Number(earning.platform_fee || 0) : 0)
      ].reduce((sum, value) => sum + value, 0),
      ad_click_to_funded_order: db.ad_attributions.filter((attribution) => attribution.status === "ready_to_attest").length,
      ad_click_to_funded_read: db.ad_attributions.filter((attribution) => attribution.status === "ready_to_attest_reader_purchase").length
    },
    recent_feedback: db.feedback.slice(-10).reverse().map((feedback) => publicFeedback(feedback, actor)),
    recent_briefs: db.briefs.slice(-10).reverse().map((brief) => publicBrief(db, brief, actor)),
    recent_samples: db.samples.slice(-10).reverse().map(publicSample),
    recent_proposals: db.proposals.slice(-10).reverse().map((proposal) => publicProposal(db, proposal, actor)),
    recent_profiles: db.profiles.slice(-10).reverse().map(publicProfile),
    recent_escrows: db.escrows.slice(-10).reverse().map((escrow) => publicEscrow(db, escrow, actor)),
    recent_intents: db.intents.slice(-10).reverse().map((intent) => publicIntent(intent, actor)),
    recent_offers: db.offers.slice(-10).reverse().map((offer) => publicOffer(offer, actor)),
    recent_orders: db.orders.slice(-10).reverse().map((order) => publicOrderSummary(db, order, actor)),
    recent_deliveries: db.deliveries.slice(-10).reverse().map((delivery) => publicDelivery(db, delivery, db.orders.find((order) => order.id === delivery.order_id), actor)),
    recent_revisions: db.revisions.slice(-10).reverse().map((revision) => publicRevision(db, revision, actor)),
    recent_disputes: db.disputes.slice(-10).reverse().map((dispute) => publicOrderArtifact(db, dispute, actor)),
    recent_acceptances: db.acceptances.slice(-10).reverse().map((acceptance) => publicOrderArtifact(db, acceptance, actor)),
    recent_refunds: db.refunds.slice(-10).reverse().map((refund) => publicOrderArtifact(db, refund, actor)),
    recent_releases: db.releases.slice(-10).reverse().map((release) => publicOrderArtifact(db, release, actor)),
    recent_reviews: db.reviews.slice(-10).reverse().map((review) => publicOrderArtifact(db, review, actor)),
    recent_publications: db.publications.slice(-10).reverse().map((publication) => publicPublication(db, publication, actor)),
    recent_publication_consents: db.publication_consents.slice(-10).reverse().map((consent) => publicPublicationConsent(db, consent, actor)),
    recent_reader_purchases: db.reader_purchases.slice(-10).reverse().map((purchase) => publicReaderPurchase(db, purchase, actor)),
    recent_reader_reviews: db.reader_reviews.slice(-10).reverse().map((review) => publicReaderReview(db, review, actor)),
    recent_reader_earnings: db.reader_earnings.slice(-10).reverse().map((earning) => publicReaderEarning(db, earning, actor)),
    recent_order_acknowledgements: db.order_acknowledgements.slice(-10).reverse().map((ack) => publicOrderArtifact(db, ack, actor)),
    recent_ad_attributions: db.ad_attributions.slice(-10).reverse().map((attribution) => publicAdAttribution(db, attribution, actor)),
    recent_requests: db.requests.slice(-20).reverse().map((request) => publicRequest(request, actor))
  };
}

function previewText(text, max = 360) {
  const clean = String(text || "").replace(/\s+/g, " ").trim();
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max).trim()}...`;
}

function wordCount(text) {
  return String(text || "").trim().split(/\s+/).filter(Boolean).length;
}

function normalizedWritingText(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function textFingerprint(text) {
  const normalized = normalizedWritingText(text);
  return normalized ? crypto.createHash("sha256").update(normalized).digest("hex") : null;
}

function isSameAddress(a, b) {
  return Boolean(a && b && String(a) === String(b));
}

function actorIsBuyer(order, actor) {
  return Boolean(order && actor?.signed && isSameAddress(actor.address, order.actor?.address));
}

function actorIsWriter(order, actor) {
  return Boolean(order && actor?.signed && isSameAddress(actor.address, order.payee_addr));
}

function actorCanViewOrderPrivate(order, actor) {
  return actorIsBuyer(order, actor) || actorIsWriter(order, actor);
}

function ordersForBrief(db, briefId) {
  if (!briefId) return [];
  return db.orders.filter((order) => order.brief_id === briefId);
}

function briefFundingState(db, brief) {
  const orders = ordersForBrief(db, brief?.id);
  const funded = orders.filter((order) => Boolean(verifiedEscrowForOrder(db, order)));
  const released = orders.filter((order) => Boolean(releasedEscrowForOrder(db, order)));
  return {
    state: released.length ? "paid_work_released" : funded.length ? "funded_order_exists" : "unfunded_open_brief",
    funded_order_count: funded.length,
    released_order_count: released.length,
    unpaid_sample_guidance: "Public auditions should be short, non-reusable previews. Full memoir scenes belong in funded orders."
  };
}

function briefSampleRisk(body = {}) {
  const text = [
    body.story,
    body.memoir,
    body.want,
    body.sample_request,
    body.payment_note,
    body.requirements,
    body.privacy
  ].filter(Boolean).join(" ").toLowerCase();
  const flags = [];
  const requestedWords = [...text.matchAll(/(\d{3,5})\s*(?:-|to)?\s*(?:\d{3,5})?\s*(?:usable\s+|publishable\s+|polished\s+)?words?/g)]
    .map((match) => Number(match[1]))
    .filter((value) => Number.isFinite(value));
  const asksLongSample = requestedWords.some((count) => count > 500) || /full audition|publishable words|usable words|before escrow/.test(text);
  const noDeposit = /no deposit|before escrow|before i lock escrow|before funding|before payment|before i commit/.test(text);
  if (asksLongSample && noDeposit) flags.push("unpaid_reusable_sample_request");
  if (/rights to evaluate all sample prose|rights.*sample/.test(text) && noDeposit) flags.push("pre_payment_rights_pressure");
  return {
    flags,
    requested_word_counts: requestedWords,
    max_public_preview_words_before_escrow: 120,
    guidance: flags.length
      ? "This brief asks for too much reusable prose before verified escrow. Writers should answer with questions, terms, and a short non-reusable preview."
      : "Keep pre-escrow previews short; move full scenes into funded delivery."
  };
}

function briefPrivacyAssessment(body = {}) {
  const combined = [
    body.story,
    body.memoir,
    body.want,
    body.requirements,
    body.privacy,
    body.private_details_note,
    body.withheld_details,
    body.sensitive_details,
    body.proposal_private_notes
  ].filter(Boolean).join(" ").toLowerCase();
  const flags = [];
  if (/withheld|private thread|after escrow|after funding|after selecting|selected writer|until hired|private_until_hired|confidential/.test(combined)) {
    flags.push("withheld_sensitive_details");
  }
  if (/daughter|son|spouse|wife|husband|divorce|medical|client|company|sale|business|immigrat|family/.test(combined)) {
    flags.push("memoir_identity_risk");
  }
  if (/quote|dialogue|names?|office object|object details|private names|family details/.test(combined)) {
    flags.push("contains_or_references_private_anchors");
  }
  return {
    flags: [...new Set(flags)],
    public_summary_policy: flags.length
      ? "Public brief text should stay thematic and short; concrete dialogue, names, family details, and object anchors belong in private proposal/order surfaces."
      : "No obvious memoir privacy flags detected, but keep identifying details out of public samples until escrow is verified.",
    protected_private_details: flags.length > 0
  };
}

function sourceReferencesCopiedSample(provenance) {
  const text = String(provenance || "").toLowerCase();
  return /cop(y|ied|ying)|repost|scrape|public preview|public_preview|sample_[0-9a-f]+|not original|from another writer/.test(text);
}

function sampleDuplicateRisk(db, actor, text, provenance) {
  const fingerprint = textFingerprint(text);
  const flags = [];
  if (!fingerprint) {
    if (sourceReferencesCopiedSample(provenance)) flags.push("provenance_admits_copied_public_preview");
    return { fingerprint: null, duplicate_of_sample_id: null, flags };
  }
  const duplicate = db.samples.find((sample) =>
    sample.text_fingerprint === fingerprint ||
    (sample.excerpt && textFingerprint(sample.excerpt) === fingerprint)
  );
  if (duplicate && !isSameAddress(duplicate.actor?.address, actor?.address)) flags.push("duplicate_public_sample_text");
  if (duplicate && !provenance) flags.push("missing_provenance_for_duplicate_text");
  if (sourceReferencesCopiedSample(provenance)) flags.push("provenance_admits_copied_public_preview");
  return {
    fingerprint,
    duplicate_of_sample_id: duplicate?.id || null,
    flags
  };
}

function proposalParticipantAddresses(db, proposal) {
  if (!proposal) return new Set();
  const brief = proposal.brief_id ? db.briefs.find((candidate) => candidate.id === proposal.brief_id) : null;
  const sample = proposal.sample_id ? db.samples.find((candidate) => candidate.id === proposal.sample_id) : null;
  const match = proposal.match_id ? db.matches.find((candidate) => candidate.id === proposal.match_id) : null;
  const order = proposal.id ? db.orders.find((candidate) => candidate.proposal_id === proposal.id) : null;
  return new Set([
    proposal.actor?.address,
    proposal.buyer_addr,
    proposal.payee_addr,
    brief?.actor?.address,
    sample?.actor?.address,
    match?.actor?.address,
    order?.actor?.address,
    order?.payee_addr,
    ...proposal.messages.map((message) => message.actor?.address),
    ...proposal.messages.map((message) => message.buyer_addr),
    ...proposal.messages.map((message) => message.payee_addr)
  ].filter(Boolean));
}

function canViewProposal(db, proposal, actor) {
  if (!proposal || proposal.visibility === "public") return true;
  if (!actor.signed || !actor.address) return false;
  return proposalParticipantAddresses(db, proposal).has(actor.address);
}

function proposalResponseState(db, proposal) {
  const brief = proposal?.brief_id ? db.briefs.find((candidate) => candidate.id === proposal.brief_id) : null;
  const sample = proposal?.sample_id ? db.samples.find((candidate) => candidate.id === proposal.sample_id) : null;
  const buyerAddrs = new Set([proposal?.buyer_addr, brief?.actor?.address].filter(Boolean));
  const writerAddrs = new Set([proposal?.payee_addr, sample?.actor?.address].filter(Boolean));
  const messages = (proposal?.messages || []).map((message) => {
    const role = String(message.role || "").toLowerCase();
    const addr = message.actor?.address;
    const side = writerAddrs.has(addr) || /writer|payee|seller/.test(role)
      ? "writer"
      : buyerAddrs.has(addr) || /buyer|client|payer/.test(role)
        ? "buyer"
        : "participant";
    return { side, at: message.at };
  });
  const buyerMessages = messages.filter((message) => message.side === "buyer");
  const writerMessages = messages.filter((message) => message.side === "writer");
  const latestBuyerAt = buyerMessages.at(-1)?.at || null;
  const latestWriterAt = writerMessages.at(-1)?.at || null;
  const latestMessage = messages.at(-1) || null;
  const waitingOn = !latestMessage
    ? "participant"
    : latestMessage.side === "buyer"
      ? "writer"
      : latestMessage.side === "writer"
        ? "buyer"
        : "participant";
  const latestAtMs = latestMessage?.at ? new Date(latestMessage.at).getTime() : NaN;
  const hoursSinceLatest = Number.isFinite(latestAtMs)
    ? Math.max(0, Math.round(((Date.now() - latestAtMs) / 3_600_000) * 100) / 100)
    : null;
  const writerRespondedAfterBuyer = Boolean(
    latestBuyerAt &&
    latestWriterAt &&
    new Date(latestWriterAt).getTime() > new Date(latestBuyerAt).getTime()
  );
  const staleThresholdHours = 12;
  return {
    message_count: messages.length,
    buyer_message_count: buyerMessages.length,
    writer_message_count: writerMessages.length,
    latest_buyer_message_at: latestBuyerAt,
    latest_writer_message_at: latestWriterAt,
    waiting_on: waitingOn,
    writer_responded_after_latest_buyer: writerRespondedAfterBuyer,
    response_sla_hours: staleThresholdHours,
    stale_private_thread: waitingOn === "writer" && hoursSinceLatest !== null && hoursSinceLatest >= staleThresholdHours,
    buyer_funding_guidance: writerRespondedAfterBuyer || (!latestBuyerAt && latestWriterAt)
      ? "Writer has responded in the thread; confirm scope, terms, payee, and fund only with verified escrow."
      : "Do not fund private memoir details until the signed writer has answered with questions, scope, terms, and payee confirmation."
  };
}

function verifiedEscrowForOrder(db, order) {
  if (!order) return null;
  return db.escrows.slice().reverse().find((escrow) =>
    escrow.order_id === order.id &&
    escrow.escrow_id === order.escrow_id &&
    escrow.chain_escrow &&
    !escrow.verification_failures?.length &&
    ["locked", "submitted", "released"].includes(String(escrow.status || "").toLowerCase())
  ) || null;
}

function verifiedWriterDeliveryForOrder(db, order, deliveryId = null) {
  if (!order) return null;
  return db.deliveries.slice().reverse().find((delivery) =>
    delivery.order_id === order.id &&
    (!deliveryId || delivery.id === deliveryId) &&
    delivery.actor?.signed &&
    isSameAddress(delivery.actor.address, order.payee_addr) &&
    ["submitted", "revised", "accepted", "accepted_pending_release", "released_paid"].includes(String(delivery.status || "").toLowerCase())
  ) || null;
}

function verifiedAcceptanceForOrder(db, order, deliveryId = null) {
  if (!order) return null;
  const delivery = verifiedWriterDeliveryForOrder(db, order, deliveryId);
  if (!delivery) return null;
  return db.acceptances.slice().reverse().find((acceptance) =>
    acceptance.order_id === order.id &&
    acceptance.delivery_id === delivery.id &&
    acceptance.actor?.signed &&
    isSameAddress(acceptance.actor.address, order.actor?.address) &&
    ["ready_to_release", "ready_to_release_quality_override"].includes(acceptance.status)
  ) || null;
}

function deliveryQualityEvidence(delivery) {
  const raw = delivery?.raw || {};
  const text = [
    delivery?.scene_objective,
    delivery?.interview_questions,
    delivery?.outline_beats,
    delivery?.draft,
    delivery?.excerpt,
    delivery?.notes,
    raw.scene_objective,
    raw.interview_questions,
    raw.outline_beats,
    raw.chapter_architecture,
    raw.acceptance_rubric
  ].filter(Boolean).join(" ").toLowerCase();
  const draftText = String(delivery?.draft || raw.full_draft || raw.draft || delivery?.excerpt || "");
  const genericPhrases = [
    "life is a journey",
    "became whole",
    "healing takes courage",
    "the business was hard",
    "my daughter was sad"
  ];
  const evidence = {
    has_scene_objective: Boolean(delivery?.scene_objective || raw.scene_objective || /scene objective|opening scene|scene strategy/.test(text)),
    has_interview_questions: Boolean(delivery?.interview_questions || raw.interview_questions || /interview questions?/.test(text)),
    has_structure: Boolean(delivery?.outline_beats || raw.outline_beats || raw.chapter_architecture || /chapter (beats?|map)|outline beats?|architecture/.test(text)),
    has_substantial_draft: draftText.replace(/\s+/g, " ").trim().length >= 500,
    has_rights_terms: /rights|confidential|no[- ]reuse|privacy|transfer/.test(text) || /after_(acceptance_and_payment|release)/.test(String(delivery?.rights_transfer || "")),
    appears_generic: genericPhrases.some((phrase) => text.includes(phrase))
  };
  evidence.score = [
    evidence.has_scene_objective,
    evidence.has_interview_questions,
    evidence.has_structure,
    evidence.has_substantial_draft,
    evidence.has_rights_terms
  ].filter(Boolean).length - (evidence.appears_generic ? 2 : 0);
  evidence.status = evidence.score >= 3 && evidence.has_substantial_draft ? "memoir_quality_evidence_present" : "needs_memoir_quality_evidence";
  return evidence;
}

function deliveryIsSubstantive(delivery) {
  return deliveryQualityEvidence(delivery).status === "memoir_quality_evidence_present";
}

function latestRevisionAfterDelivery(db, order, delivery) {
  if (!order || !delivery) return null;
  return db.revisions.slice().reverse().find((revision) =>
    revision.order_id === order.id &&
    revision.status === "requested" &&
    revision.delivery_id === delivery.id &&
    new Date(revision.at).getTime() >= new Date(delivery.at).getTime()
  ) || null;
}

function latestSubstantiveWriterDeliveryForOrder(db, order) {
  if (!order) return null;
  return db.deliveries.slice().reverse().find((delivery) =>
    delivery.order_id === order.id &&
    delivery.actor?.signed &&
    isSameAddress(delivery.actor.address, order.payee_addr) &&
    ["submitted", "revised", "accepted", "accepted_pending_release", "released_paid"].includes(String(delivery.status || "").toLowerCase()) &&
    deliveryIsSubstantive(delivery)
  ) || null;
}

function reputationEligibleAcceptance(db, order, deliveryId = null) {
  const acceptance = verifiedAcceptanceForOrder(db, order, deliveryId);
  if (!acceptance) return null;
  const delivery = verifiedWriterDeliveryForOrder(db, order, acceptance.delivery_id);
  const evidence = deliveryQualityEvidence(delivery);
  return evidence.status === "memoir_quality_evidence_present" ? { acceptance, delivery, evidence } : null;
}

function acceptanceReleaseDecision(delivery, body = {}) {
  const evidence = deliveryQualityEvidence(delivery);
  const explicitOverride = body.release_quality_override === true || body.accept_low_quality_delivery === true;
  const overrideReason = body.override_reason || body.quality_override_reason || null;
  const canOfferReleaseCommand = evidence.status === "memoir_quality_evidence_present" || (explicitOverride && overrideReason);
  return {
    evidence,
    explicit_override: Boolean(explicitOverride && overrideReason),
    override_reason: overrideReason,
    can_offer_release_command: canOfferReleaseCommand,
    release_risk: evidence.status === "memoir_quality_evidence_present"
      ? "memoir_quality_evidence_present"
      : explicitOverride && overrideReason
        ? "buyer_quality_override_not_reputation_eligible"
        : "blocked_needs_memoir_quality_evidence_or_explicit_override"
  };
}

function releasedEscrowForOrder(db, order) {
  const verifiedEscrow = verifiedEscrowForOrder(db, order);
  if (!verifiedEscrow) return null;
  if (String(verifiedEscrow.status || "").toLowerCase() === "released") return verifiedEscrow;
  const release = db.releases.slice().reverse().find((candidate) =>
    candidate.order_id === order.id &&
    candidate.escrow_id === verifiedEscrow.escrow_id &&
    candidate.status === "released"
  );
  return release || null;
}

function latestWriterAcknowledgementForOrder(db, order) {
  if (!order) return null;
  return db.order_acknowledgements.slice().reverse().find((ack) =>
    ack.order_id === order.id &&
    ack.actor?.signed &&
    actorIsWriter(order, ack.actor) &&
    ["acknowledged", "delivery_eta_updated"].includes(String(ack.status || "").toLowerCase())
  ) || null;
}

function latestWriterDeclineForOrder(db, order) {
  if (!order) return null;
  return db.order_declines.slice().reverse().find((decline) =>
    decline.order_id === order.id &&
    decline.actor?.signed &&
    actorIsWriter(order, decline.actor) &&
    decline.status === "declined_pending_verified_escrow"
  ) || null;
}

function orderTrustState(db, order) {
  const verified_escrow = verifiedEscrowForOrder(db, order);
  const latest_writer_delivery = verifiedWriterDeliveryForOrder(db, order);
  const latest_substantive_writer_delivery = latestSubstantiveWriterDeliveryForOrder(db, order);
  const accepted_delivery = verifiedAcceptanceForOrder(db, order, latest_substantive_writer_delivery?.id || latest_writer_delivery?.id);
  const quality_evidence = latest_substantive_writer_delivery ? deliveryQualityEvidence(latest_substantive_writer_delivery) : latest_writer_delivery ? deliveryQualityEvidence(latest_writer_delivery) : null;
  const latest_revision_request = latestRevisionAfterDelivery(db, order, latest_substantive_writer_delivery || latest_writer_delivery);
  const reputation_eligible_acceptance = accepted_delivery && quality_evidence?.status === "memoir_quality_evidence_present" ? accepted_delivery : null;
  const released_escrow = accepted_delivery ? releasedEscrowForOrder(db, order) : null;
  return {
    buyer_addr: order?.actor?.address || null,
    writer_addr: order?.payee_addr || null,
    verified_escrow: verified_escrow || null,
    latest_writer_delivery: latest_writer_delivery || null,
    latest_substantive_writer_delivery: latest_substantive_writer_delivery || null,
    delivery_quality_evidence: quality_evidence,
    latest_revision_request: latest_revision_request || null,
    latest_writer_acknowledgement: latestWriterAcknowledgementForOrder(db, order),
    latest_writer_decline: latestWriterDeclineForOrder(db, order),
    accepted_delivery: accepted_delivery || null,
    reputation_eligible_acceptance: reputation_eligible_acceptance || null,
    released_escrow: released_escrow || null,
    payment_state: released_escrow ? "released_paid" : accepted_delivery ? "accepted_pending_release" : verified_escrow ? "funded" : "unfunded",
    rights_state: released_escrow ? "transferred_after_release" : accepted_delivery ? "accepted_not_transferred_until_release" : "not_transferred",
    writer_reputation_state: released_escrow && reputation_eligible_acceptance ? "earned_paid_delivery" : released_escrow ? "paid_needs_memoir_quality_evidence" : accepted_delivery ? "pending_release" : verified_escrow ? "pending_delivery_acceptance" : "not_earned"
  };
}

function orderOperationalState(db, order) {
  const trust = orderTrustState(db, order);
  const state = {
    state: "unfunded",
    deadline: order?.delivery_due_at || order?.raw?.delivery_due_at || order?.raw?.deadline || null,
    next_actions: [],
    privacy: {
      linked_private_thread: Boolean(order?.proposal_id),
      private_material_visible_to: "buyer_and_writer_after_verified_escrow",
      public_previews_only: true
    }
  };
  if (!order?.actor?.signed) {
    state.state = "unsigned_draft";
    state.next_actions.push("buyer_sign_order");
  } else if (latestWriterDeclineForOrder(db, order) && !trust.verified_escrow) {
    state.state = "declined_pending_verified_escrow";
    state.next_actions.push("buyer_attach_real_chain_escrow_to_reopen_writer_queue");
  } else if (!trust.verified_escrow) {
    state.state = "awaiting_verified_escrow";
    state.next_actions.push("buyer_attach_numeric_chain_escrow");
  } else if (!trust.latest_writer_delivery) {
    state.state = trust.latest_writer_acknowledgement ? "writer_acknowledged_awaiting_delivery" : "awaiting_writer_acknowledgement";
    state.next_actions.push(trust.latest_writer_acknowledgement ? "writer_submit_funded_diagnostic_delivery" : "writer_acknowledge_funded_order_with_eta");
    state.next_actions.push("buyer_may_request_refund_or_open_dispute_if_deadline_missed");
  } else if (!trust.latest_substantive_writer_delivery) {
    state.state = "awaiting_substantive_writer_delivery";
    state.next_actions.push("writer_supersede_probe_with_questions_scene_structure_rights_terms");
    state.next_actions.push("buyer_request_revision_or_dispute_if_delivery_is_not_substantive");
  } else if (trust.latest_revision_request && !trust.accepted_delivery) {
    state.state = "awaiting_writer_revision";
    state.next_actions.push("writer_submit_revised_delivery_linked_to_revision");
  } else if (!trust.accepted_delivery) {
    state.state = "awaiting_buyer_acceptance_or_revision";
    state.next_actions.push("buyer_accept_delivery_or_request_focused_revision");
  } else if (!trust.released_escrow) {
    state.state = "accepted_pending_release";
    state.next_actions.push("buyer_run_escrow_release_then_record_release");
  } else if (trust.writer_reputation_state === "paid_needs_memoir_quality_evidence") {
    state.state = "released_paid_needs_quality_evidence";
    state.next_actions.push("writer_add_memoir_specific_evidence_before_review_counts");
  } else {
    state.state = "released_paid_review_ready";
    state.next_actions.push("buyer_leave_verified_review");
  }
  return state;
}

function reconcileOrderTrust(db) {
  for (const sample of db.samples) {
    if (sourceReferencesCopiedSample(sample.provenance)) {
      sample.status = "blocked_copied_or_duplicate_public_preview";
      sample.risk_flags = Array.from(new Set([...(sample.risk_flags || []), "provenance_admits_copied_public_preview"]));
    }
  }

  for (const offer of db.offers) {
    if (offer.source === "sample") {
      const sample = db.samples.find((candidate) => candidate.id === offer.source_id);
      if (sample && sample.status !== "submitted") {
        offer.status = "blocked_copied_sample";
        offer.risk_flags = Array.from(new Set([...(offer.risk_flags || []), "source_sample_blocked"]));
      }
    }
  }

  for (const order of db.orders) {
    const economics = orderEconomics(order);
    order.milestone_type = economics.milestone_type;
    order.platform_fee_rate = economics.platform_fee_rate;
    order.platform_fee = economics.platform_fee;
    order.writer_net_earnings = economics.writer_net_earnings;
    const trust = orderTrustState(db, order);
    order.trust = {
      payment_state: trust.payment_state,
      rights_state: trust.rights_state,
      writer_reputation_state: trust.writer_reputation_state
    };
    if (trust.payment_state === "released_paid") order.status = "released_paid";
    else if (trust.payment_state === "accepted_pending_release") order.status = "accepted_pending_release";
    else if (trust.payment_state === "funded" && !["refund_requested"].includes(order.status)) order.status = "funded";
    else if (!trust.verified_escrow && ["funded", "accepted_pending_release", "released", "released_paid"].includes(order.status)) {
      order.status = "awaiting_verified_escrow";
      order.risk_flags = Array.from(new Set([...(order.risk_flags || []), "unverified_escrow"]));
    }
  }

  for (const delivery of db.deliveries) {
    const order = db.orders.find((candidate) => candidate.id === delivery.order_id);
    delivery.quality_evidence = deliveryQualityEvidence(delivery);
    if (!order || !actorIsWriter(order, delivery.actor)) {
      delivery.status = "invalid_unverified_writer_or_order";
    } else if (!verifiedEscrowForOrder(db, order)) {
      delivery.status = "blocked_unfunded_order";
    } else if (releasedEscrowForOrder(db, order)) {
      delivery.status = "released_paid";
    } else if (verifiedAcceptanceForOrder(db, order, delivery.id)) {
      delivery.status = "accepted_pending_release";
    }
  }

  for (const acceptance of db.acceptances) {
    const order = db.orders.find((candidate) => candidate.id === acceptance.order_id);
    const delivery = order ? verifiedWriterDeliveryForOrder(db, order, acceptance.delivery_id) : null;
    acceptance.quality_evidence = delivery ? deliveryQualityEvidence(delivery) : null;
    if (
      !order ||
      !actorIsBuyer(order, acceptance.actor) ||
      !verifiedEscrowForOrder(db, order) ||
      !delivery
    ) {
      acceptance.status = "invalid_unverified_order_delivery_or_actor";
      acceptance.release_command = null;
    } else {
      const decision = acceptanceReleaseDecision(delivery, acceptance.raw || {});
      acceptance.quality_evidence = decision.evidence;
      acceptance.release_risk = decision.release_risk;
      acceptance.quality_override = decision.explicit_override ? {
        accepted: true,
        reason: decision.override_reason
      } : null;
      if (!decision.can_offer_release_command) {
        acceptance.status = "blocked_needs_memoir_quality_evidence";
        acceptance.release_command = null;
      } else if (decision.explicit_override) {
        acceptance.status = "ready_to_release_quality_override";
      } else {
        acceptance.status = "ready_to_release";
      }
    }
  }

  for (const review of db.reviews) {
    const order = db.orders.find((candidate) => candidate.id === review.order_id);
    const reputationReady = order && reputationEligibleAcceptance(db, order) && releasedEscrowForOrder(db, order);
    const paid = order && actorIsBuyer(order, review.actor) && reputationReady;
    const accepted = order ? verifiedAcceptanceForOrder(db, order) : null;
    review.quality_evidence = accepted ? deliveryQualityEvidence(verifiedWriterDeliveryForOrder(db, order, accepted.delivery_id)) : null;
    review.status = paid ? "verified_paid_review" : "unverified_review";
    if (order && actorIsBuyer(order, review.actor) && releasedEscrowForOrder(db, order) && !reputationReady) {
      review.status = "paid_review_needs_memoir_quality_evidence";
    }
  }

  for (const consent of db.publication_consents) {
    const decision = publicationConsentDecision(db, { ...(consent.raw || {}), ...consent }, consent.actor);
    const isDenial = consent.reader_sales_consent !== true;
    const signedWriterCanControlPublication = Boolean(decision.order && decision.delivery && actorIsWriter(decision.order, consent.actor));
    consent.verification_failures = decision.failures;
    consent.max_reader_price = decision.max_reader_price;
    if (isDenial && signedWriterCanControlPublication) {
      consent.verification_failures = ["writer_publication_consent_denied_or_revoked"];
      consent.status = "writer_publication_consent_denied_or_revoked";
    } else {
      consent.status = decision.ok ? "verified_writer_publication_consent" : "blocked_writer_publication_consent";
    }
  }

  for (const publication of db.publications) {
    const order = db.orders.find((candidate) => candidate.id === publication.order_id);
    const delivery = verifiedWriterDeliveryForOrder(db, order, publication.delivery_id);
    const released = releasedEscrowForOrder(db, order);
    const qualityEvidence = delivery ? deliveryQualityEvidence(delivery) : null;
    const rightsText = [
      publication.rights_scope,
      publication.reader_license_terms,
      delivery?.rights_transfer,
      order?.raw?.rights_terms
    ].filter(Boolean).join(" ").toLowerCase();
    const latestWriterConsent = latestWriterPublicationConsentEvent(db, publication);
    const writerConsent = verifiedWriterPublicationConsent(db, publication);
    const writerConsentRevoked = Boolean(latestWriterConsent && latestWriterConsent.reader_sales_consent !== true);
    const writerConsentPriceLimited = Boolean(
      latestWriterConsent?.reader_sales_consent &&
      latestWriterConsent.max_reader_price &&
      Number(publication.price || 0) > Number(latestWriterConsent.max_reader_price)
    );
    const failures = [
      ...(!order ? ["missing_order"] : []),
      ...(!delivery ? ["missing_verified_writer_delivery"] : []),
      ...(order && !actorIsBuyer(order, publication.actor) ? ["publication_actor_not_verified_rights_holder"] : []),
      ...(!released ? ["missing_released_escrow"] : []),
      ...(qualityEvidence?.status === "memoir_quality_evidence_present" ? [] : ["missing_memoir_quality_evidence"]),
      ...(!publication.buyer_consent ? ["missing_buyer_rights_holder_consent"] : []),
      ...(writerConsent ? [] : [
        writerConsentRevoked
          ? "writer_publication_consent_denied_or_revoked"
          : writerConsentPriceLimited
            ? "publication_price_above_writer_consent_limit"
            : "missing_signed_writer_publication_consent"
      ]),
      ...(rightsTextAllowsReaderSales(rightsText) ? [] : ["rights_scope_does_not_allow_reader_sales"]),
      ...(Number(publication.price) > 0 ? [] : ["missing_positive_reader_price"]),
      ...(Number(publication.preview_word_count || 0) <= 120 ? [] : ["public_preview_too_long"])
    ];
    publication.latest_writer_consent_id = latestWriterConsent?.id || null;
    publication.verified_writer_consent_id = writerConsent?.id || null;
    publication.writer_consent = Boolean(writerConsent);
    publication.writer_consent_state = writerConsent
      ? "verified_writer_publication_consent"
      : writerConsentRevoked
        ? "writer_publication_consent_denied_or_revoked"
        : writerConsentPriceLimited
          ? "publication_price_above_writer_consent_limit"
          : "missing_signed_writer_publication_consent";
    publication.rights_verification_failures = failures;
    publication.rights_verified_after_release = Boolean(released);
    publication.status = failures.length ? "blocked_rights_or_release_missing" : "listed";
  }

  for (const purchase of db.reader_purchases) {
    const publication = db.publications.find((candidate) => candidate.id === purchase.publication_id);
    const status = String(purchase.chain_escrow?.status || purchase.status || "").toLowerCase();
    const fundedLike = ["locked", "submitted", "released"].includes(status);
    const actorFailures = readerPurchaseActorFailures(purchase, purchase.chain_escrow, purchase.actor);
    purchase.verification_failures = Array.from(new Set([
      ...(purchase.verification_failures || []).filter((failure) =>
        !["reader_payment_claim_not_signed", "missing_signed_reader_wallet", "signed_reader_not_chain_payer"].includes(failure)
      ),
      ...actorFailures
    ]));
    purchase.status = publication?.status === "listed" && purchase.chain_escrow && fundedLike && !purchase.verification_failures?.length
      ? "verified_paid_read_access"
      : "awaiting_verified_reader_payment";
    if (purchase.status === "verified_paid_read_access") {
      const split = readerEarningSplit(publication, purchase.amount);
      purchase.platform_fee = split.platform_fee;
      purchase.writer_royalty = split.writer_royalty;
      purchase.rights_holder_earnings = split.rights_holder_earnings;
      upsertReaderEarning(db, purchase, publication);
    } else {
      purchase.platform_fee = 0;
      purchase.writer_royalty = 0;
      purchase.rights_holder_earnings = 0;
      for (const earning of db.reader_earnings.filter((candidate) => candidate.reader_purchase_id === purchase.id)) {
        earning.status = "blocked_unverified_reader_purchase";
      }
    }
  }

  for (const review of db.reader_reviews) {
    const purchase = db.reader_purchases.find((candidate) => candidate.id === review.reader_purchase_id);
    review.leak_risk = readerReviewLeakRisk(readerReviewPublicProofText(review));
    const verifiedPurchase = purchase &&
      purchase.publication_id === review.publication_id &&
      purchase.status === "verified_paid_read_access" &&
      review.actor?.signed &&
      isSameAddress(review.actor.address, purchase.actor?.address);
    review.status = verifiedPurchase
      ? review.leak_risk.public_safe && String(readerReviewPublicProofText(review)).trim()
        ? "verified_reader_review"
        : "verified_reader_review_private_quote_blocked"
      : "unverified_reader_review";
  }

  for (const decline of db.order_declines) {
    const order = db.orders.find((candidate) => candidate.id === decline.order_id);
    if (!order || !actorIsWriter(order, decline.actor)) {
      decline.status = "invalid_unverified_writer_or_order";
    } else if (verifiedEscrowForOrder(db, order)) {
      decline.status = "superseded_by_verified_escrow";
    } else {
      decline.status = "declined_pending_verified_escrow";
      if (!["funded", "accepted_pending_release", "released_paid"].includes(order.status)) {
        order.status = "declined_pending_verified_escrow";
      }
    }
  }

  for (const ack of db.order_acknowledgements) {
    const order = db.orders.find((candidate) => candidate.id === ack.order_id);
    if (!order || !actorIsWriter(order, ack.actor)) {
      ack.status = "invalid_unverified_writer_or_order";
    } else if (!verifiedEscrowForOrder(db, order)) {
      ack.status = "blocked_unfunded_order";
    } else if (releasedEscrowForOrder(db, order)) {
      ack.status = "released_paid";
    } else {
      ack.status = ack.eta ? "delivery_eta_updated" : "acknowledged";
    }
  }

  for (const conversion of db.conversions) {
    const order = db.orders.find((candidate) => candidate.id === conversion.order_id);
    conversion.status = order && verifiedEscrowForOrder(db, order) ? "verified_funded_order" : "legacy_unverified";
  }

  for (const attribution of db.ad_attributions) {
    if (attribution.reader_purchase_id) {
      const purchase = db.reader_purchases.find((candidate) => candidate.id === attribution.reader_purchase_id);
      attribution.status = purchase?.status === "verified_paid_read_access" ? "ready_to_attest_reader_purchase" : "blocked_unverified_reader_purchase";
    } else {
      const order = db.orders.find((candidate) => candidate.id === attribution.order_id);
      attribution.status = order && verifiedEscrowForOrder(db, order) ? "ready_to_attest" : "blocked_unverified_order";
    }
  }
}

function adCampaignIdFrom(body, order) {
  return body.ad_campaign_id || body.campaign_id || body.ag3ntads_campaign_id || order?.raw?.ad_campaign_id || order?.raw?.campaign_id || null;
}

function recordAdAttribution(db, order, body, actor) {
  const campaignId = adCampaignIdFrom(body, order);
  if (!campaignId || !order?.actor?.address || !verifiedEscrowForOrder(db, order)) return null;
  const existing = db.ad_attributions.find((attribution) =>
    attribution.order_id === order.id &&
    String(attribution.campaign_id) === String(campaignId)
  );
  if (existing) return existing;
  const item = {
    id: id("adattr"),
    at: new Date().toISOString(),
    actor,
    campaign_id: String(campaignId),
    clicker_addr: order.actor.address,
    order_id: order.id,
    source: "verified_funded_order",
    status: "ready_to_attest",
    attest_path: `/ads/campaigns/${campaignId}/convert`,
    attest_body: {
      clicker_addr: order.actor.address,
      source: `ghostwriter_hub:${order.id}:verified_funded_order`
    }
  };
  db.ad_attributions.push(item);
  return item;
}

function recordReaderAdAttribution(db, purchase, publication, body) {
  const campaignId = body.ad_campaign_id || body.campaign_id || body.ag3ntads_campaign_id || null;
  if (!campaignId || !purchase?.actor?.signed || !purchase?.actor?.address || purchase.status !== "verified_paid_read_access") return null;
  const existing = db.ad_attributions.find((attribution) =>
    attribution.reader_purchase_id === purchase.id &&
    String(attribution.campaign_id) === String(campaignId)
  );
  if (existing) return existing;
  const item = {
    id: id("adattr"),
    at: new Date().toISOString(),
    actor: purchase.actor,
    campaign_id: String(campaignId),
    clicker_addr: purchase.actor.address,
    publication_id: publication.id,
    reader_purchase_id: purchase.id,
    source: "verified_paid_read_access",
    status: "ready_to_attest_reader_purchase",
    attest_path: `/ads/campaigns/${campaignId}/convert`,
    attest_body: {
      clicker_addr: purchase.actor.address,
      source: `ghostwriter_hub:${purchase.id}:verified_paid_read_access`
    }
  };
  db.ad_attributions.push(item);
  return item;
}

function money(value) {
  const numeric = Number(value || 0);
  return Number.isFinite(numeric) ? Math.max(0, Math.round(numeric * 100) / 100) : 0;
}

function memoirMilestoneType(body = {}) {
  const explicit = String(body.milestone_type || body.milestone || body.stage || "").toLowerCase();
  const text = [
    explicit,
    body.deliverable,
    body.outcome,
    body.acceptance_criteria,
    body.scope,
    body.brief,
    body.raw?.deliverable,
    body.raw?.outcome,
    body.raw?.acceptance_criteria
  ].filter(Boolean).join(" ").toLowerCase();
  if (/full.?manuscript|complete manuscript|book draft|whole book|memoir manuscript/.test(text)) return "full_manuscript";
  if (/chapter|scene|opening|outline|beat sheet|structure|revision/.test(text)) return "chapter_milestone";
  if (/diagnostic|sample|interview|brief|strategy|assessment|voice audit/.test(text)) return "paid_diagnostic";
  return "custom_milestone";
}

function orderEconomics(order = {}) {
  const gross = money(order.amount);
  const rateValue = Number(order.platform_fee_rate ?? order.raw?.platform_fee_rate ?? 0.15);
  const platformFeeRate = Number.isFinite(rateValue) && rateValue >= 0 ? rateValue : 0.15;
  const platformFee = order.platform_fee !== undefined ? money(order.platform_fee) : money(gross * platformFeeRate);
  const writerNet = order.writer_net_earnings !== undefined ? money(order.writer_net_earnings) : money(gross - platformFee);
  return {
    milestone_type: order.milestone_type || memoirMilestoneType(order.raw || order),
    gross_amount: gross,
    platform_fee_rate: platformFeeRate,
    platform_fee: platformFee,
    writer_net_earnings: writerNet,
    money_policy: "Order proceeds count as writer earnings and platform fees only after verified escrow release."
  };
}

function readerEarningSplit(publication, amountValue) {
  const amount = money(amountValue);
  const publishedPrice = money(publication?.price);
  const denominator = publishedPrice > 0 ? publishedPrice : amount || 1;
  const platformFee = money(amount * (money(publication?.platform_fee) / denominator));
  const writerRoyalty = money(amount * (money(publication?.writer_royalty) / denominator));
  const rightsHolderEarnings = money(amount - platformFee - writerRoyalty);
  return {
    amount,
    platform_fee: platformFee,
    writer_royalty: writerRoyalty,
    rights_holder_earnings: rightsHolderEarnings,
    split_policy: "Reader purchase proceeds follow the listed publication split: platform fee, writer royalty, then rights-holder share."
  };
}

function upsertReaderEarning(db, purchase, publication) {
  if (!purchase?.id || purchase.status !== "verified_paid_read_access" || !publication) return null;
  const split = readerEarningSplit(publication, purchase.amount);
  const existing = db.reader_earnings.find((earning) => earning.reader_purchase_id === purchase.id);
  const item = existing || {
    id: id("readearn"),
    at: new Date().toISOString(),
    reader_purchase_id: purchase.id
  };
  Object.assign(item, {
    updated_at: new Date().toISOString(),
    publication_id: publication.id,
    reader_addr: purchase.actor?.address || purchase.payer_addr || null,
    rights_holder_addr: publication.rights_holder_addr || purchase.payee_addr || null,
    writer_addr: publication.writer_addr || null,
    escrow_id: purchase.escrow_id || null,
    amount: split.amount,
    platform_fee: split.platform_fee,
    writer_royalty: split.writer_royalty,
    rights_holder_earnings: split.rights_holder_earnings,
    split_policy: split.split_policy,
    status: "earned_from_verified_reader_purchase"
  });
  if (!existing) db.reader_earnings.push(item);
  return item;
}

function publicProfile(profile) {
  const { raw, ...safe } = profile;
  return safe;
}

function publicFeedback(feedback, actor = {}) {
  const canViewFull = actor?.signed && isSameAddress(actor.address, feedback.actor?.address);
  const { raw, ...safe } = feedback;
  return {
    ...safe,
    message: canViewFull ? feedback.message : "Feedback wording withheld from public activity because it may include private memoir, security, or payment details.",
    raw: canViewFull ? raw : undefined,
    protected_private_details: !canViewFull
  };
}

function publicIntent(intent, actor = {}) {
  const canViewFull = actor?.signed && isSameAddress(actor.address, intent.actor?.address);
  const { raw, ...safe } = intent;
  return {
    ...safe,
    want: canViewFull ? intent.want : intent.source === "brief" ? "Private memoir buyer intent; see /briefs for public-safe summary." : previewText(intent.want, 140),
    constraints: canViewFull ? intent.constraints : intent.constraints ? "withheld_from_public_listing" : null,
    raw: canViewFull ? raw : undefined,
    protected_private_details: !canViewFull
  };
}

function publicOffer(offer, actor = {}) {
  const canViewFull = actor?.signed && isSameAddress(actor.address, offer.actor?.address);
  const { raw, ...safe } = offer;
  return {
    ...safe,
    proof: canViewFull ? offer.proof : offer.proof ? previewText(offer.proof, 120) : null,
    terms: canViewFull ? offer.terms : offer.terms ? "terms_withheld_until_proposal_or_order" : null,
    raw: canViewFull ? raw : undefined,
    protected_private_details: !canViewFull
  };
}

function publicRequest(request, actor = {}) {
  const canViewFull = actor?.signed && isSameAddress(actor.address, request.actor?.address);
  return {
    id: request.id,
    at: request.at,
    method: request.method,
    path: request.path,
    host: request.host,
    url: request.url,
    app: request.app,
    actor: request.actor,
    body: canViewFull ? request.body : request.body && Object.keys(request.body).length ? "withheld_from_public_activity" : {},
    headers: canViewFull ? request.headers : {
      "user-agent": request.headers?.["user-agent"],
      "x-agent-id": request.headers?.["x-agent-id"]
    },
    protected_private_details: !canViewFull
  };
}

function publicBrief(db, brief, actor) {
  const canViewFull = actor?.signed && isSameAddress(actor.address, brief.actor?.address);
  const sample_risk = brief.sample_risk || briefSampleRisk(brief.raw || brief);
  const privacy = brief.privacy_assessment || briefPrivacyAssessment(brief.raw || brief);
  const canShowStoryPreview = canViewFull || !privacy.protected_private_details;
  return {
    ...brief,
    story: canShowStoryPreview ? canViewFull ? brief.story : previewText(brief.story, 180) : "Private memoir brief; full story is visible only to the signed buyer.",
    raw: canViewFull ? brief.raw : undefined,
    funding_state: briefFundingState(db, brief),
    sample_risk,
    privacy_assessment: privacy,
    public_sample_policy: {
      max_unfunded_preview_words: sample_risk.max_public_preview_words_before_escrow,
      full_drafts_after_verified_escrow: true,
      no_reuse_until_paid_release: true
    },
    protected_private_details: privacy.protected_private_details || !canViewFull
  };
}

function publicSample(sample) {
  if (sample.status && sample.status !== "submitted") {
    return {
      id: sample.id,
      at: sample.at,
      actor: sample.actor,
      brief_id: sample.brief_id,
      status: sample.status,
      duplicate_of_sample_id: sample.duplicate_of_sample_id,
      risk_flags: sample.risk_flags || [],
      blocked_from_public_supply: true,
      protected_private_details: true
    };
  }
  return {
    ...sample,
    excerpt: previewText(sample.excerpt, 280),
    public_preview: previewText(sample.excerpt, 280),
    raw: undefined
  };
}

function publicProposal(db, proposal, actor) {
  const canViewFull = canViewProposal(db, proposal, actor);
  const { messages = [], raw, ...base } = proposal;
  const response_state = proposalResponseState(db, proposal);
  return {
    ...base,
    participant_addrs: canViewFull ? [...proposalParticipantAddresses(db, proposal)] : undefined,
    message_count: messages.length,
    response_state,
    messages: canViewFull ? messages : "withheld_from_public_listing",
    raw: canViewFull ? raw : undefined
  };
}

function publicOrder(order, actor) {
  const canViewFull = actorCanViewOrderPrivate(order, actor);
  const economics = orderEconomics(order);
  return {
    ...order,
    economics: {
      ...economics,
      writer_earnings_state: order.trust?.payment_state === "released_paid" ? "earned_after_release" : "pending_verified_release"
    },
    deliverable: canViewFull ? order.deliverable : "Memoir deliverable withheld from public listing.",
    raw: canViewFull ? order.raw : undefined,
    linked_private_thread: Boolean(order.proposal_id),
    protected_private_details: !canViewFull,
    protected_linked_private_thread: Boolean(order.proposal_id) && !canViewFull
  };
}

function publicOrderSummary(db, order, actor) {
  return {
    ...publicOrder(order, actor),
    operational_state: orderOperationalState(db, order)
  };
}

function publicEscrow(db, escrow, actor) {
  const order = db.orders.find((candidate) => candidate.id === escrow.order_id);
  const canViewFull = order && actorCanViewOrderPrivate(order, actor);
  return {
    ...escrow,
    chain_escrow: canViewFull ? escrow.chain_escrow : escrow.chain_escrow ? {
      id: escrow.chain_escrow.id,
      amount: escrow.chain_escrow.amount,
      status: escrow.chain_escrow.status,
      ref: escrow.chain_escrow.ref
    } : null,
    proof: canViewFull ? escrow.proof : undefined,
    raw: canViewFull ? escrow.raw : undefined,
    protected_private_details: canViewFull ? false : true
  };
}

function acceptanceChecklist(delivery = null, revision = null) {
  return {
    voice_matches_buyer_material: "Does the draft sound like the speaker rather than a generic success memoir?",
    uses_confirmed_anchors_only: "Does it use agreed objects, places, dialogue, and facts without inventing private specifics?",
    scene_has_clear_objective: "Does the scene have a concrete objective and visible tension?",
    structure_supports_next_milestone: "Do the beats make the next chapter/outline milestone easier to fund?",
    emotionally_restrained: "Does the draft avoid explaining the meaning when an object/action can carry it?",
    avoids_cliche_language: "Does it avoid generic healing, resilience, journey, and inspirational language?",
    privacy_respected: "Are names, family details, business details, and medical/client facts handled according to the terms?",
    revision_blockers_resolved: revision ? "Were the buyer's stated revision blockers resolved?" : "If anything blocks acceptance, request a focused revision before release.",
    rights_release_understood: "Acceptance prepares release, but rights transfer only after escrow release if the order terms say so.",
    would_fund_next_milestone: "Would this work justify funding the next paid milestone?"
  };
}

function publicDelivery(db, delivery, order, actor) {
  const quality_evidence = deliveryQualityEvidence(delivery);
  const canViewFull = order && actorCanViewOrderPrivate(order, actor) && verifiedEscrowForOrder(db, order);
  const hasFullDraft = Boolean(delivery.draft);
  const base = {
    id: delivery.id,
    at: delivery.at,
    actor: delivery.actor,
    order_id: delivery.order_id,
    content_hash: delivery.content_hash,
    excerpt: canViewFull ? delivery.excerpt : "Delivery excerpt withheld from public listing; rights-cleared reader previews must be listed through /publications.",
    revised_from_revision_id: delivery.revised_from_revision_id || null,
    supersedes_delivery_id: delivery.supersedes_delivery_id || null,
    status: delivery.status,
    quality_evidence,
    substantive_delivery: deliveryIsSubstantive(delivery),
    protected_private_details: !canViewFull,
    protected_scene_objective: Boolean(delivery.scene_objective),
    protected_interview_questions: Boolean(delivery.interview_questions),
    protected_outline_beats: Boolean(delivery.outline_beats),
    protected_rights_terms: Boolean(delivery.rights_transfer),
    protected_full_draft_from_public: hasFullDraft,
    full_draft_visible_to_actor: Boolean(canViewFull && hasFullDraft)
  };
  if (!canViewFull) return base;
  return {
    ...base,
    scene_objective: delivery.scene_objective,
    interview_questions: delivery.interview_questions,
    outline_beats: delivery.outline_beats,
    draft: delivery.draft,
    private_notes: delivery.private_notes,
    rights_transfer: delivery.rights_transfer,
    notes: delivery.notes,
    raw: delivery.raw
  };
}

function publicRevision(db, revision, actor) {
  const order = db.orders.find((candidate) => candidate.id === revision.order_id);
  const canViewFull = order && actorCanViewOrderPrivate(order, actor);
  return {
    id: revision.id,
    at: revision.at,
    actor: revision.actor,
    order_id: revision.order_id,
    delivery_id: revision.delivery_id,
    request: canViewFull ? revision.request : revision.request ? "withheld_from_public_listing" : "",
    acceptance_blocker: canViewFull ? revision.acceptance_blocker : revision.acceptance_blocker ? "withheld_from_public_listing" : null,
    rubric: canViewFull ? revision.rubric : revision.rubric ? "withheld_from_public_listing" : null,
    raw: canViewFull ? revision.raw : undefined,
    status: revision.status,
    protected_private_details: !canViewFull
  };
}

function revisionComparisonPackets(db, order, actor) {
  if (!order || !actorCanViewOrderPrivate(order, actor)) return [];
  return db.revisions
    .filter((revision) => revision.order_id === order.id)
    .map((revision) => {
      const original = revision.delivery_id
        ? db.deliveries.find((delivery) => delivery.id === revision.delivery_id && delivery.order_id === order.id)
        : null;
      const revised = db.deliveries
        .slice()
        .reverse()
        .find((delivery) =>
          delivery.order_id === order.id &&
          delivery.revised_from_revision_id === revision.id &&
          actorIsWriter(order, delivery.actor)
        ) || null;
      return {
        revision: publicRevision(db, revision, actor),
        original_delivery: original ? publicDelivery(db, original, order, actor) : null,
        revised_delivery: revised ? publicDelivery(db, revised, order, actor) : null,
        original_quality_evidence: original ? deliveryQualityEvidence(original) : null,
        revised_quality_evidence: revised ? deliveryQualityEvidence(revised) : null,
        acceptance_checklist: acceptanceChecklist(revised || original, revision)
      };
    });
}

function publicTrustState(db, order, actor) {
  const trust = orderTrustState(db, order);
  return {
    buyer_addr: trust.buyer_addr,
    writer_addr: trust.writer_addr,
    verified_escrow: trust.verified_escrow ? publicEscrow(db, trust.verified_escrow, actor) : null,
    latest_writer_delivery: trust.latest_writer_delivery ? publicDelivery(db, trust.latest_writer_delivery, order, actor) : null,
    latest_substantive_writer_delivery: trust.latest_substantive_writer_delivery ? publicDelivery(db, trust.latest_substantive_writer_delivery, order, actor) : null,
    delivery_quality_evidence: trust.delivery_quality_evidence,
    latest_revision_request: trust.latest_revision_request,
    latest_writer_acknowledgement: trust.latest_writer_acknowledgement ? publicOrderArtifact(db, trust.latest_writer_acknowledgement, actor) : null,
    latest_writer_decline: trust.latest_writer_decline ? publicOrderArtifact(db, trust.latest_writer_decline, actor) : null,
    accepted_delivery: trust.accepted_delivery ? publicOrderArtifact(db, trust.accepted_delivery, actor) : null,
    reputation_eligible_acceptance: trust.reputation_eligible_acceptance ? publicOrderArtifact(db, trust.reputation_eligible_acceptance, actor) : null,
    released_escrow: trust.released_escrow ? publicOrderArtifact(db, trust.released_escrow, actor) : null,
    payment_state: trust.payment_state,
    rights_state: trust.rights_state,
    writer_reputation_state: trust.writer_reputation_state,
    operational_state: orderOperationalState(db, order)
  };
}

function publicReview(db, review, actor) {
  const order = db.orders.find((candidate) => candidate.id === review.order_id);
  const trust = order ? orderTrustState(db, order) : null;
  const canViewFull = order && actorCanViewOrderPrivate(order, actor);
  const delivery = trust?.reputation_eligible_acceptance
    ? verifiedWriterDeliveryForOrder(db, order, trust.reputation_eligible_acceptance.delivery_id)
    : null;
  const safe = publicOrderArtifact(db, review, actor);
  if (!canViewFull) {
    safe.message = review.status === "verified_paid_review"
      ? "Verified paid memoir review recorded. Wording is withheld from public listing to protect private memoir material."
      : "Unverified review recorded. Wording is withheld from public listing.";
  }
  return {
    ...safe,
    order_id: review.order_id,
    buyer_addr: order?.actor?.address || review.actor?.address || null,
    writer_addr: order?.payee_addr || null,
    delivery_id: trust?.reputation_eligible_acceptance?.delivery_id || review.raw?.delivery_id || null,
    verified_paid: review.status === "verified_paid_review",
    released_escrow_id: trust?.released_escrow?.escrow_id || null,
    paid_amount: order?.amount || null,
    craft_evidence: delivery ? {
      scene_objective_present: Boolean(delivery.scene_objective),
      interview_questions_present: Boolean(delivery.interview_questions),
      outline_beats_present: Boolean(delivery.outline_beats),
      substantial_draft_present: deliveryQualityEvidence(delivery).has_substantial_draft,
      rights_terms_present: Boolean(delivery.rights_transfer),
      status: deliveryQualityEvidence(delivery).status
    } : review.quality_evidence || null,
    private_material_policy: "No draft, private notes, family dialogue, or identifying business details are shown in public review views."
  };
}

function rightsTextAllowsReaderSales(text) {
  return /reader|read.access|ebook|publish|publicat|resale|sell/.test(String(text || "").toLowerCase());
}

function publicationConsentDecision(db, body, actor) {
  const publication = body.publication_id ? db.publications.find((candidate) => candidate.id === body.publication_id) : null;
  const orderId = body.order_id || publication?.order_id;
  const deliveryId = body.delivery_id || publication?.delivery_id;
  const order = db.orders.find((candidate) => candidate.id === orderId);
  const delivery = verifiedWriterDeliveryForOrder(db, order, deliveryId);
  const priceLimit = Number(body.max_reader_price || body.max_price || 0);
  const rightsText = [
    body.rights_scope,
    body.reader_license_terms,
    body.consent_terms,
    publication?.rights_scope,
    publication?.reader_license_terms,
    delivery?.rights_transfer,
    order?.raw?.rights_terms
  ].filter(Boolean).join(" ").toLowerCase();
  const failures = [
    ...(!order ? ["missing_order"] : []),
    ...(!delivery ? ["missing_verified_writer_delivery"] : []),
    ...(!actorIsWriter(order, actor) ? ["actor_not_signed_order_writer"] : []),
    ...(body.reader_sales_consent === true || body.writer_consent === true ? [] : ["missing_reader_sales_consent"]),
    ...(rightsTextAllowsReaderSales(rightsText) ? [] : ["rights_scope_does_not_allow_reader_sales"]),
    ...(Number.isFinite(priceLimit) && priceLimit > 0 && publication && Number(publication.price || 0) > priceLimit ? ["publication_price_above_writer_consent_limit"] : [])
  ];
  return {
    ok: failures.length === 0,
    failures,
    order,
    delivery,
    publication,
    max_reader_price: Number.isFinite(priceLimit) && priceLimit > 0 ? priceLimit : null
  };
}

function verifiedWriterPublicationConsent(db, publication) {
  if (!publication) return null;
  const order = db.orders.find((candidate) => candidate.id === publication.order_id);
  if (!order) return null;
  const latestConsent = latestWriterPublicationConsentEvent(db, publication);
  if (!latestConsent || !latestConsent.reader_sales_consent) return null;
  if (latestConsent.max_reader_price && Number(publication.price || 0) > Number(latestConsent.max_reader_price)) return null;
  const rightsText = [
    latestConsent.rights_scope,
    latestConsent.reader_license_terms,
    latestConsent.consent_terms,
    publication.rights_scope,
    publication.reader_license_terms
  ].filter(Boolean).join(" ").toLowerCase();
  return latestConsent.status === "verified_writer_publication_consent" && rightsTextAllowsReaderSales(rightsText)
    ? latestConsent
    : null;
}

function latestWriterPublicationConsentEvent(db, publication) {
  if (!publication) return null;
  const order = db.orders.find((candidate) => candidate.id === publication.order_id);
  if (!order) return null;
  return db.publication_consents.slice().reverse().find((consent) => {
    if (!actorIsWriter(order, consent.actor)) return false;
    if (consent.publication_id && consent.publication_id !== publication.id) return false;
    return consent.order_id === publication.order_id && consent.delivery_id === publication.delivery_id;
  }) || null;
}

function publicationRightsDecision(db, body, actor) {
  const order = db.orders.find((candidate) => candidate.id === body.order_id);
  const delivery = verifiedWriterDeliveryForOrder(db, order, body.delivery_id);
  const released = releasedEscrowForOrder(db, order);
  const qualityEvidence = delivery ? deliveryQualityEvidence(delivery) : null;
  const price = Number(body.price || body.reader_price || 0);
  const publicationShape = {
    id: body.publication_id || null,
    order_id: body.order_id,
    delivery_id: body.delivery_id,
    price,
    rights_scope: body.rights_scope || null,
    reader_license_terms: body.reader_license_terms || null
  };
  const latestWriterConsent = latestWriterPublicationConsentEvent(db, publicationShape);
  const writerConsent = verifiedWriterPublicationConsent(db, publicationShape);
  const writerConsentRevoked = Boolean(latestWriterConsent && latestWriterConsent.reader_sales_consent !== true);
  const writerConsentPriceLimited = Boolean(
    latestWriterConsent?.reader_sales_consent &&
    latestWriterConsent.max_reader_price &&
    price > Number(latestWriterConsent.max_reader_price)
  );
  const rightsText = [
    body.rights_scope,
    body.reader_license_terms,
    body.rights_terms,
    body.writer_consent_evidence,
    delivery?.rights_transfer,
    order?.raw?.rights_terms
  ].filter(Boolean).join(" ").toLowerCase();
  const previewWords = wordCount(body.public_preview || body.preview || delivery?.excerpt || "");
  const failures = [
    ...(!order ? ["missing_order"] : []),
    ...(!delivery ? ["missing_verified_writer_delivery"] : []),
    ...(!actorIsBuyer(order, actor) ? ["actor_not_verified_buyer_or_rights_holder"] : []),
    ...(!released ? ["missing_released_escrow"] : []),
    ...(qualityEvidence?.status === "memoir_quality_evidence_present" ? [] : ["missing_memoir_quality_evidence"]),
    ...(body.buyer_consent === true || body.rights_holder_consent === true ? [] : ["missing_buyer_rights_holder_consent"]),
    ...(writerConsent ? [] : [
      writerConsentRevoked
        ? "writer_publication_consent_denied_or_revoked"
        : writerConsentPriceLimited
          ? "publication_price_above_writer_consent_limit"
          : "missing_signed_writer_publication_consent"
    ]),
    ...(rightsTextAllowsReaderSales(rightsText) ? [] : ["rights_scope_does_not_allow_reader_sales"]),
    ...(Number.isFinite(price) && price > 0 ? [] : ["missing_positive_reader_price"]),
    ...(previewWords <= 120 ? [] : ["public_preview_too_long"])
  ];
  return {
    ok: failures.length === 0,
    failures,
    order,
    delivery,
    released,
    writer_consent: writerConsent,
    latest_writer_consent: latestWriterConsent,
    quality_evidence: qualityEvidence,
    price,
    preview_words: previewWords
  };
}

function publicPreviewForPublication(delivery, body) {
  return previewText(body.public_preview || body.preview || delivery?.excerpt || "", 720);
}

function readerReviewLeakRisk(message) {
  const text = String(message || "");
  const lower = text.toLowerCase();
  const flags = [];
  const quoteMatches = text.match(/["“”'‘’][^"“”'‘’]{35,}["“”'‘’]/g) || [];
  const longParagraphs = text.split(/\n{2,}/).filter((part) => wordCount(part) > 80);
  const longSentences = text.split(/[.!?]+/).filter((part) => wordCount(part) > 45);
  const suspiciousFirstPersonMemoir = /\b(my|our)\s+(father|mother|daughter|son|spouse|wife|husband|sister|brother|grandmother|grandfather|doctor|lawyer|client|boss|company|case|diagnosis|hospital|divorce|estate|inheritance)\b/.test(lower);
  const privateAnchorClaims = /\b(real names?|family secret|medical detail|client detail|business detail|private dialogue|exact dialogue|verbatim line|identifying detail)\b/.test(lower);
  if (quoteMatches.length) flags.push("long_quoted_passage");
  if (longParagraphs.length) flags.push("review_contains_long_passage");
  if (longSentences.length) flags.push("review_contains_reusable_long_sentence");
  if (suspiciousFirstPersonMemoir) flags.push("review_mentions_private_memoir_anchor");
  if (privateAnchorClaims) flags.push("review_self_identifies_private_detail");
  if (/chapter excerpt|opening scene|full paragraph|verbatim|quoted passage|copy from the memoir|line from the draft/.test(lower)) {
    flags.push("self_identifies_reusable_memoir_text");
  }
  return {
    flags: [...new Set(flags)],
    public_safe: flags.length === 0,
    policy: flags.length
      ? "Review recorded for the paid reader and rights holder, but public proof is blocked until it is rewritten without quoted or reusable memoir passages."
      : "Review can be public proof because it does not appear to quote reusable memoir material."
  };
}

function readerReviewPublicProofText(review = {}) {
  return review.public_blurb || review.raw?.public_blurb || review.raw?.public_review || review.message || "";
}

function readerReviewPrivateMessage(review = {}) {
  return review.private_message || review.message || "";
}

function readerReviewPublicProofState(review = {}) {
  const risk = readerReviewLeakRisk(readerReviewPublicProofText(review));
  const hasPublicProofText = Boolean(String(readerReviewPublicProofText(review)).trim());
  return {
    risk,
    has_public_proof_text: hasPublicProofText,
    counts_as_public_reader_proof: review.status === "verified_reader_review" && risk.public_safe && hasPublicProofText,
    public_proof_policy: "Public reader proof must be post-purchase and must not include quotes, private anchors, long passages, or reusable memoir text. Private feedback remains visible only to the reader and rights holder."
  };
}

function publicPublication(db, publication, actor = {}) {
  const order = db.orders.find((candidate) => candidate.id === publication.order_id);
  const delivery = db.deliveries.find((candidate) => candidate.id === publication.delivery_id);
  const released = releasedEscrowForOrder(db, order);
  const readerHasAccess = verifiedReaderPurchaseForPublication(db, publication, actor);
  const canViewFull = Boolean(readerHasAccess || actorCanViewOrderPrivate(order, actor));
  return {
    id: publication.id,
    at: publication.at,
    title: publication.title,
    subtitle: publication.subtitle || null,
    order_id: publication.order_id,
    delivery_id: publication.delivery_id,
    buyer_addr: order?.actor?.address || publication.rights_holder_addr || null,
    writer_addr: order?.payee_addr || null,
    price: publication.price,
    platform_fee: publication.platform_fee,
    writer_royalty: publication.writer_royalty,
    rights_holder_earnings: publication.rights_holder_earnings,
    public_preview: publication.public_preview,
    preview_word_count: publication.preview_word_count,
    preview_policy: "Short non-reusable preview only; full memoir material requires verified paid reader access.",
    reader_license_terms: publication.reader_license_terms,
    rights_scope: publication.rights_scope,
    consent: {
      buyer_consent: publication.buyer_consent,
      writer_consent: publication.writer_consent,
      writer_consent_state: publication.writer_consent_state || (publication.writer_consent ? "verified_writer_publication_consent" : "missing_signed_writer_publication_consent"),
      verified_writer_consent_id: publication.verified_writer_consent_id || null,
      latest_writer_consent_id: publication.latest_writer_consent_id || null,
      rights_verified_after_release: Boolean(released)
    },
    craft_evidence: delivery ? {
      memoir_quality_status: deliveryQualityEvidence(delivery).status,
      content_hash: delivery.content_hash || null
    } : null,
    paid_reader_reviews: db.reader_reviews.filter((review) => review.publication_id === publication.id && review.status === "verified_reader_review").length,
    protected_reader_reviews: db.reader_reviews.filter((review) => review.publication_id === publication.id && review.status === "verified_reader_review_private_quote_blocked").length,
    paid_reader_purchases: db.reader_purchases.filter((purchase) => purchase.publication_id === publication.id && purchase.status === "verified_paid_read_access").length,
    reader_earnings: {
      revenue: db.reader_earnings
        .filter((earning) => earning.publication_id === publication.id && earning.status === "earned_from_verified_reader_purchase")
        .reduce((sum, earning) => sum + Number(earning.amount || 0), 0),
      platform_fees: db.reader_earnings
        .filter((earning) => earning.publication_id === publication.id && earning.status === "earned_from_verified_reader_purchase")
        .reduce((sum, earning) => sum + Number(earning.platform_fee || 0), 0),
      writer_royalties: db.reader_earnings
        .filter((earning) => earning.publication_id === publication.id && earning.status === "earned_from_verified_reader_purchase")
        .reduce((sum, earning) => sum + Number(earning.writer_royalty || 0), 0),
      rights_holder_earnings: db.reader_earnings
        .filter((earning) => earning.publication_id === publication.id && earning.status === "earned_from_verified_reader_purchase")
        .reduce((sum, earning) => sum + Number(earning.rights_holder_earnings || 0), 0)
    },
    full_text: canViewFull ? delivery?.draft || delivery?.excerpt || null : undefined,
    read_access: canViewFull ? "verified_access_or_owner" : "purchase_required",
    status: publication.status,
    rights_verification_failures: publication.status === "listed" ? [] : publication.rights_verification_failures,
    protected_private_details: !canViewFull
  };
}

function publicPublicationConsent(db, consent, actor = {}) {
  const publication = consent.publication_id ? db.publications.find((candidate) => candidate.id === consent.publication_id) : null;
  const order = db.orders.find((candidate) => candidate.id === (consent.order_id || publication?.order_id));
  const canViewFull = order && actorCanViewOrderPrivate(order, actor);
  return {
    id: consent.id,
    at: consent.at,
    publication_id: consent.publication_id || null,
    order_id: consent.order_id || publication?.order_id || null,
    delivery_id: consent.delivery_id || publication?.delivery_id || null,
    writer_addr: consent.actor?.address || null,
    reader_sales_consent: consent.reader_sales_consent,
    max_reader_price: consent.max_reader_price || null,
    rights_scope: consent.rights_scope,
    reader_license_terms: consent.reader_license_terms,
    consent_terms: canViewFull ? consent.consent_terms : consent.consent_terms ? previewText(consent.consent_terms, 160) : null,
    status: consent.status,
    verification_failures: consent.verification_failures || [],
    public_policy: "Reader-sale listings require active signed writer consent plus buyer/rightsholder consent, released escrow, memoir-quality evidence, explicit reader-sale rights, and paid read access. A later signed writer denial blocks future catalog listing.",
    protected_private_details: !canViewFull
  };
}

function readerPurchaseMatchesPublication(chainEscrow, publication, body, actor) {
  if (!chainEscrow || !publication) return { ok: false, failures: ["missing_chain_escrow_or_publication"] };
  const failures = [];
  const payer = String(chainEscrow.payer || "");
  const payee = String(chainEscrow.payee || "");
  const amount = Number(chainEscrow.amount || 0);
  const ref = String(chainEscrow.ref || "");
  const expectedPayer = body.payer_addr || actor.address || "";
  const expectedPayee = body.payee_addr || publication.payee_addr || publication.rights_holder_addr || "";
  const expectedAmount = Number(body.amount || publication.price || 0);
  if (expectedPayer && payer && payer !== expectedPayer) failures.push("payer_mismatch");
  if (expectedPayee && payee && payee !== expectedPayee) failures.push("payee_mismatch");
  if (Number.isFinite(expectedAmount) && expectedAmount > 0 && amount !== expectedAmount) failures.push("amount_mismatch");
  if (ref && ref !== publication.id && ref !== `reader:${publication.id}`) failures.push("ref_not_publication_id");
  if (!ref) failures.push("missing_chain_ref");
  return { ok: failures.length === 0, failures };
}

function readerPurchaseActorFailures(purchaseOrBody, chainEscrow, actor) {
  const payer = String(chainEscrow?.payer || purchaseOrBody?.payer_addr || "");
  const failures = [];
  if (!actor?.signed) failures.push("reader_payment_claim_not_signed");
  if (!actor?.address) failures.push("missing_signed_reader_wallet");
  if (payer && actor?.address && payer !== actor.address) failures.push("signed_reader_not_chain_payer");
  return failures;
}

function verifiedReaderPurchaseForPublication(db, publication, actor = {}) {
  if (!publication || !actor?.signed || !actor.address) return null;
  return db.reader_purchases.slice().reverse().find((purchase) =>
    purchase.publication_id === publication.id &&
    purchase.actor?.signed &&
    isSameAddress(purchase.actor.address, actor.address) &&
    purchase.chain_escrow &&
    !purchase.verification_failures?.length &&
    purchase.status === "verified_paid_read_access"
  ) || null;
}

function publicReaderPurchase(db, purchase, actor = {}) {
  const publication = db.publications.find((candidate) => candidate.id === purchase.publication_id);
  const canViewFull = actor?.signed && (
    isSameAddress(actor.address, purchase.actor?.address) ||
    isSameAddress(actor.address, publication?.rights_holder_addr)
  );
  const { raw, proof, chain_escrow, ...safe } = purchase;
  return {
    ...safe,
    proof: canViewFull ? proof : undefined,
    chain_escrow: canViewFull ? chain_escrow : chain_escrow ? { id: chain_escrow.id, amount: chain_escrow.amount, status: chain_escrow.status, ref: chain_escrow.ref } : undefined,
    raw: canViewFull ? raw : undefined,
    read_path: purchase.status === "verified_paid_read_access" && canViewFull ? `/catalog/${purchase.publication_id}/read` : null,
    earnings_ledger_path: purchase.status === "verified_paid_read_access" ? `/reader-earnings?publication_id=${purchase.publication_id}` : null,
    payment_claim_policy: "Read access, reader revenue, reader reviews, and ad attribution count only when the chain payer signs the purchase claim.",
    protected_private_details: !canViewFull
  };
}

function publicReaderEarning(db, earning, actor = {}) {
  const publication = db.publications.find((candidate) => candidate.id === earning.publication_id);
  const canViewFinancialCounterparty = actor?.signed && (
    isSameAddress(actor.address, earning.reader_addr) ||
    isSameAddress(actor.address, earning.rights_holder_addr) ||
    isSameAddress(actor.address, earning.writer_addr)
  );
  return {
    id: earning.id,
    at: earning.at,
    updated_at: earning.updated_at || earning.at,
    publication_id: earning.publication_id,
    reader_purchase_id: earning.reader_purchase_id,
    escrow_id: canViewFinancialCounterparty ? earning.escrow_id : earning.escrow_id ? "verified_chain_escrow" : null,
    title: publication?.title || null,
    amount: earning.amount,
    platform_fee: earning.platform_fee,
    writer_royalty: earning.writer_royalty,
    rights_holder_earnings: earning.rights_holder_earnings,
    reader_addr: canViewFinancialCounterparty ? earning.reader_addr : "withheld_from_public_ledger",
    writer_addr: earning.writer_addr,
    rights_holder_addr: earning.rights_holder_addr,
    status: earning.status,
    split_policy: earning.split_policy,
    privacy_policy: "The reader earnings ledger shows money movement and rights parties only; no full draft, reader private message, or memoir detail is exposed.",
    protected_private_details: !canViewFinancialCounterparty
  };
}

function publicReaderReview(db, review, actor = {}) {
  const purchase = db.reader_purchases.find((candidate) => candidate.id === review.reader_purchase_id);
  const publication = db.publications.find((candidate) => candidate.id === review.publication_id);
  const canViewFull = actor?.signed && (
    isSameAddress(actor.address, review.actor?.address) ||
    isSameAddress(actor.address, publication?.rights_holder_addr)
  );
  const publicProof = readerReviewPublicProofState(review);
  return {
    id: review.id,
    at: review.at,
    actor: review.actor,
    publication_id: review.publication_id,
    reader_purchase_id: review.reader_purchase_id,
    rating: review.rating,
    private_message: canViewFull ? readerReviewPrivateMessage(review) : undefined,
    public_blurb: canViewFull
      ? (review.public_blurb || null)
      : review.status === "verified_reader_review"
        ? previewText(readerReviewPublicProofText(review), 180)
        : review.status === "verified_reader_review_private_quote_blocked"
          ? "Verified paid reader review recorded, but public wording is withheld because it may quote reusable memoir material or private anchors."
          : "Unverified reader review wording withheld.",
    message: canViewFull ? readerReviewPrivateMessage(review) : undefined,
    would_buy_more: review.would_buy_more,
    status: review.status,
    verified_paid_read_access: purchase?.status === "verified_paid_read_access",
    counts_as_public_reader_proof: publicProof.counts_as_public_reader_proof,
    leak_risk: review.leak_risk || publicProof.risk,
    protected_private_details: !canViewFull,
    public_text_policy: publicProof.public_proof_policy
  };
}

function publicAdAttribution(db, attribution, actor = {}) {
  const order = attribution.order_id ? db.orders.find((candidate) => candidate.id === attribution.order_id) : null;
  const purchase = attribution.reader_purchase_id ? db.reader_purchases.find((candidate) => candidate.id === attribution.reader_purchase_id) : null;
  const publication = purchase?.publication_id ? db.publications.find((candidate) => candidate.id === purchase.publication_id) : null;
  const canViewFull = actor?.signed && (
    (order && actorIsBuyer(order, actor)) ||
    (order && actorIsWriter(order, actor)) ||
    isSameAddress(actor.address, purchase?.actor?.address) ||
    isSameAddress(actor.address, publication?.rights_holder_addr)
  );
  return {
    id: attribution.id,
    at: attribution.at,
    campaign_id: attribution.campaign_id,
    offer_type: attribution.reader_purchase_id ? "memoir_ebook_sales" : "memoir_ghostwriting_service",
    clicker_addr: canViewFull ? attribution.clicker_addr : attribution.clicker_addr ? "withheld_from_public_attribution" : null,
    order_id: attribution.order_id || null,
    publication_id: attribution.publication_id || null,
    reader_purchase_id: attribution.reader_purchase_id || null,
    source: attribution.source,
    status: attribution.status,
    attest_path: attribution.attest_path,
    attest_body: canViewFull ? attribution.attest_body : {
      source: attribution.attest_body?.source,
      clicker_addr: "withheld_until_signed_counterparty_view"
    },
    conversion_policy: attribution.reader_purchase_id
      ? "Reader ad conversion attestation requires verified signed chain-payer read access; reader ads remain suppressed unless /ad-readiness reader_ads is ok_to_test."
      : "Service ad conversion attestation requires a verified funded order, not an unsigned order or unverified escrow claim.",
    protected_private_details: !canViewFull
  };
}

function writerReputation(db, writerAddr, actor = {}) {
  const orders = db.orders.filter((order) => isSameAddress(order.payee_addr, writerAddr));
  const verifiedReviews = db.reviews
    .filter((review) => review.status === "verified_paid_review")
    .filter((review) => {
      const order = db.orders.find((candidate) => candidate.id === review.order_id);
      return order && isSameAddress(order.payee_addr, writerAddr);
    });
  const releasedPaidOrders = orders.filter((order) => orderTrustState(db, order).payment_state === "released_paid");
  const acceptedDeliveries = orders.filter((order) => Boolean(orderTrustState(db, order).accepted_delivery));
  const writerEarnings = releasedPaidOrders.reduce((sum, order) => sum + orderEconomics(order).writer_net_earnings, 0);
  const platformFees = releasedPaidOrders.reduce((sum, order) => sum + orderEconomics(order).platform_fee, 0);
  return {
    writer_addr: writerAddr,
    verified_paid_reviews: verifiedReviews.length,
    accepted_deliveries: acceptedDeliveries.length,
    released_paid_orders: releasedPaidOrders.length,
    writer_earnings: writerEarnings,
    platform_fees_on_released_work: platformFees,
    milestone_mix: {
      paid_diagnostic: orders.filter((order) => orderEconomics(order).milestone_type === "paid_diagnostic").length,
      chapter_milestone: orders.filter((order) => orderEconomics(order).milestone_type === "chapter_milestone").length,
      full_manuscript: orders.filter((order) => orderEconomics(order).milestone_type === "full_manuscript").length,
      custom_milestone: orders.filter((order) => orderEconomics(order).milestone_type === "custom_milestone").length
    },
    repeat_buyer_intent: verifiedReviews.filter((review) => review.would_pay_again === true).length,
    reviews: verifiedReviews.map((review) => publicReview(db, review, actor)),
    proof_policy: "Reputation counts only buyer reviews after verified escrow, accepted memoir-quality delivery, and released escrow. Writer earnings are net of the platform fee."
  };
}

function writerDashboard(db, actor, writerAddr = null) {
  const addr = writerAddr || actor.address;
  const canUseSignedQueue = actor.signed && (!writerAddr || isSameAddress(actor.address, writerAddr));
  const orders = addr
    ? db.orders.filter((order) => isSameAddress(order.payee_addr, addr))
    : [];
  const paidWork = orders.filter((order) => verifiedEscrowForOrder(db, order) && !releasedEscrowForOrder(db, order));
  const awaitingAcknowledgement = paidWork.filter((order) => !latestWriterAcknowledgementForOrder(db, order) && !verifiedWriterDeliveryForOrder(db, order));
  const paidHistory = orders.filter((order) => releasedEscrowForOrder(db, order));
  const escrowBait = orders.filter((order) => !verifiedEscrowForOrder(db, order));
  const proposalInbox = addr
    ? db.proposals.filter((proposal) => {
      const participants = proposalParticipantAddresses(db, proposal);
      return participants.has(addr) && proposalResponseState(db, proposal).waiting_on === "writer";
    })
    : [];
  return {
    writer_addr: canUseSignedQueue ? addr : addr || "sign_request_or_pass_writer_addr",
    signed_private_queue: canUseSignedQueue,
    proposal_inbox: proposalInbox.map((proposal) => publicProposal(db, proposal, actor)),
    paid_work_queue: paidWork.map((order) => publicOrderSummary(db, order, actor)),
    awaiting_writer_acknowledgement: awaitingAcknowledgement.map((order) => publicOrderSummary(db, order, actor)),
    paid_history: paidHistory.map((order) => publicOrderSummary(db, order, actor)),
    unfunded_or_unverified_orders: escrowBait.map((order) => publicOrderSummary(db, order, actor)),
    verified_reviews: addr ? writerReputation(db, addr, actor).reviews : [],
    next_actions: {
      safe_delivery: "Deliver only orders in paid_work_queue with verified escrow.",
      answer_private_proposals: "Reply to proposal_inbox with questions, scope, terms, and payee confirmation before asking for escrow.",
      acknowledge_funded_order: "POST /order-acknowledgements with {order_id, eta, planned_interview_questions, scope_note}.",
      decline_bait: "POST /order-declines with {order_id, reason} for unfunded or bogus escrow orders.",
      reputation: addr ? `/writers/${addr}/reputation` : "Sign as writer to view wallet reputation."
    }
  };
}

function publicOrderArtifact(db, item, actor) {
  const order = db.orders.find((candidate) => candidate.id === item.order_id);
  const canViewFull = order && actorCanViewOrderPrivate(order, actor);
  const { raw, proof, chain_escrow, ...safe } = item;
  return {
    ...safe,
    notes: canViewFull ? item.notes : item.notes ? previewText(item.notes, 160) : item.notes,
    reason: canViewFull ? item.reason : item.reason ? previewText(item.reason, 160) : item.reason,
    message: canViewFull ? item.message : item.message ? previewText(item.message, 160) : item.message,
    proof: canViewFull ? proof : undefined,
    chain_escrow: canViewFull ? chain_escrow : chain_escrow ? { id: chain_escrow.id, status: chain_escrow.status, ref: chain_escrow.ref } : undefined,
    raw: canViewFull ? raw : undefined,
    protected_private_details: canViewFull ? false : true
  };
}

function notFound(req, res) {
  send(res, 404, {
    error: "unknown_endpoint",
    message: "Use the actions below; if the missing route is what you needed, post /feedback and say so.",
    ui: ui("Intent Desk sitemap", "This API is the UI.", discovery().capabilities)
  });
}

async function handle(req, res) {
  if (req.method === "OPTIONS") return send(res, 204, {});
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const parsed = req.method === "POST" ? await readBody(req) : { body: {}, raw: Buffer.alloc(0) };
  const body = parsed.body;
  const db = readDb();
  const actor = actorFrom(req, body, parsed.raw);
  reconcileOrderTrust(db);
  db.requests.push({
    id: id("req"),
    at: new Date().toISOString(),
    method: req.method,
    path: url.pathname,
    host: req.headers.host || null,
    url: url.toString(),
    app: "ag3nt-ghostwriter-hub",
    actor,
    body,
    headers: {
      "user-agent": req.headers["user-agent"],
      "x-agent-id": req.headers["x-agent-id"],
      "x-agent-addr": req.headers["x-agent-addr"],
      "x-agent-address": req.headers["x-agent-address"],
      "x-ag3nt-address": req.headers["x-ag3nt-address"],
      "x-agent-pub": req.headers["x-agent-pub"],
      "x-agent-nonce": req.headers["x-agent-nonce"],
      "x-agent-sig": req.headers["x-agent-sig"]
    }
  });

  let response;
  if (req.method === "GET" && url.pathname === "/.well-known/add.json") {
    writeDb(db);
    return send(res, 200, discovery());
  }

  if (req.method === "GET" && url.pathname === "/") {
    response = {
      ...discovery(),
      activity: publicActivity(db, actor),
      ad_readiness: adReadiness(db),
      prompt:
        "No docs needed: choose the closest action, then file /feedback with what you expected next."
    };
    writeDb(db);
    return send(res, 200, response);
  }

  if (req.method === "POST" && url.pathname === "/feedback") {
    const item = {
      id: id("fb"),
      at: new Date().toISOString(),
      actor,
      sentiment: body.sentiment || "unknown",
      type: body.type || "feedback",
      endpoint_context: body.endpoint_context || null,
      message: body.message || body._raw || "",
      raw: body
    };
    db.feedback.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      feedback: item,
      ui: ui("Feedback received", "The product will prioritize repeated signed pain.")
    });
  }

  if (req.method === "GET" && url.pathname === "/intents") {
    writeDb(db);
    return send(res, 200, {
      intents: db.intents.map((intent) => publicIntent(intent, actor)),
      ui: ui("Customer demand", "Post /intents if your job is missing.")
    });
  }

  if (req.method === "GET" && url.pathname === "/orders") {
    let orders = db.orders.slice();
    const statusFilter = url.searchParams.get("status");
    const payeeFilter = url.searchParams.get("payee_addr");
    const buyerFilter = url.searchParams.get("buyer_addr");
    const roleFilter = url.searchParams.get("role");
    const fundedOnly = url.searchParams.get("funded") === "true";
    if (payeeFilter === "me" || roleFilter === "writer") {
      orders = actor.signed ? orders.filter((order) => actorIsWriter(order, actor)) : [];
    } else if (payeeFilter) {
      orders = orders.filter((order) => isSameAddress(order.payee_addr, payeeFilter));
    }
    if (buyerFilter === "me" || roleFilter === "buyer") {
      orders = actor.signed ? orders.filter((order) => actorIsBuyer(order, actor)) : [];
    } else if (buyerFilter) {
      orders = orders.filter((order) => isSameAddress(order.actor?.address, buyerFilter));
    }
    if (statusFilter) orders = orders.filter((order) =>
      order.status === statusFilter ||
      orderTrustState(db, order).payment_state === statusFilter ||
      orderOperationalState(db, order).state === statusFilter
    );
    if (fundedOnly) orders = orders.filter((order) => Boolean(verifiedEscrowForOrder(db, order)));
    writeDb(db);
    return send(res, 200, {
      orders: orders.map((order) => publicOrderSummary(db, order, actor)),
      filters: {
        status: statusFilter,
        payee_addr: payeeFilter,
        buyer_addr: buyerFilter,
        role: roleFilter,
        funded: fundedOnly
      },
      ui: ui("Orders", "Use ?role=writer&funded=true for a safe paid work queue, or ?status=awaiting_writer_delivery for funded delivery work.")
    });
  }

  if (req.method === "GET" && url.pathname === "/milestones") {
    let orders = db.orders.slice();
    const roleFilter = url.searchParams.get("role");
    const statusFilter = url.searchParams.get("status");
    const typeFilter = url.searchParams.get("type") || url.searchParams.get("milestone_type");
    if (roleFilter === "writer") {
      orders = actor.signed ? orders.filter((order) => actorIsWriter(order, actor)) : [];
    } else if (roleFilter === "buyer") {
      orders = actor.signed ? orders.filter((order) => actorIsBuyer(order, actor)) : [];
    }
    if (typeFilter) orders = orders.filter((order) => orderEconomics(order).milestone_type === typeFilter);
    if (statusFilter === "funded") orders = orders.filter((order) => Boolean(verifiedEscrowForOrder(db, order)));
    else if (statusFilter === "released_paid") orders = orders.filter((order) => Boolean(releasedEscrowForOrder(db, order)));
    else if (statusFilter === "accepted") orders = orders.filter((order) => Boolean(orderTrustState(db, order).accepted_delivery));
    const funded = orders.filter((order) => Boolean(verifiedEscrowForOrder(db, order)));
    const released = orders.filter((order) => Boolean(releasedEscrowForOrder(db, order)));
    writeDb(db);
    return send(res, 200, {
      milestones: orders.map((order) => publicOrderSummary(db, order, actor)),
      summary: {
        total_milestones: orders.length,
        funded_milestones: funded.length,
        released_paid_milestones: released.length,
        gross_funded_value: funded.reduce((sum, order) => sum + orderEconomics(order).gross_amount, 0),
        released_writer_earnings: released.reduce((sum, order) => sum + orderEconomics(order).writer_net_earnings, 0),
        released_platform_fees: released.reduce((sum, order) => sum + orderEconomics(order).platform_fee, 0),
        milestone_mix: {
          paid_diagnostic: orders.filter((order) => orderEconomics(order).milestone_type === "paid_diagnostic").length,
          chapter_milestone: orders.filter((order) => orderEconomics(order).milestone_type === "chapter_milestone").length,
          full_manuscript: orders.filter((order) => orderEconomics(order).milestone_type === "full_manuscript").length,
          custom_milestone: orders.filter((order) => orderEconomics(order).milestone_type === "custom_milestone").length
        }
      },
      filters: {
        role: roleFilter,
        status: statusFilter,
        milestone_type: typeFilter
      },
      ui: ui("Milestone economics", "Funded value, released writer earnings, and platform fees are public-safe; private memoir deliverables remain protected.")
    });
  }

  if (req.method === "GET" && url.pathname === "/writer-dashboard") {
    const writerAddr = url.searchParams.get("writer_addr");
    writeDb(db);
    return send(res, 200, {
      dashboard: writerDashboard(db, actor, writerAddr),
      ui: ui("Writer dashboard", "Paid work is separated from unfunded or unverified escrow bait.")
    });
  }

  if (req.method === "GET" && url.pathname.startsWith("/orders/")) {
    const orderId = url.pathname.split("/")[2];
    const order = db.orders.find((item) => item.id === orderId);
    if (!order) {
      writeDb(db);
      return send(res, 404, { error: "order_not_found", ui: ui("Order not found", "Use GET /orders.") });
    }
    writeDb(db);
    return send(res, 200, {
      order: publicOrderSummary(db, order, actor),
      escrows: db.escrows.filter((item) => item.order_id === orderId).map((escrow) => publicEscrow(db, escrow, actor)),
      deliveries: db.deliveries
        .filter((item) => item.order_id === orderId)
        .map((delivery) => publicDelivery(db, delivery, order, actor)),
      revisions: db.revisions.filter((item) => item.order_id === orderId).map((revision) => publicRevision(db, revision, actor)),
      revision_comparisons: revisionComparisonPackets(db, order, actor),
      disputes: db.disputes.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      acceptances: db.acceptances.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      refunds: db.refunds.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      releases: db.releases.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      reviews: db.reviews.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      order_acknowledgements: db.order_acknowledgements.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      verified_escrow: verifiedEscrowForOrder(db, order) ? publicEscrow(db, verifiedEscrowForOrder(db, order), actor) : null,
      trust: publicTrustState(db, order, actor),
      acceptance_checklist: acceptanceChecklist(latestSubstantiveWriterDeliveryForOrder(db, order), orderTrustState(db, order).latest_revision_request),
      ui: ui("Order status", "Review escrow, delivery, revision, dispute, and review state from one place.", [
        { method: "POST", path: "/acceptances", label: "Accept delivery" },
        { method: "POST", path: "/order-acknowledgements", label: "Writer acknowledge" },
        { method: "POST", path: "/releases", label: "Record release" },
        { method: "POST", path: "/refunds", label: "Request refund" },
        { method: "POST", path: "/disputes", label: "Open dispute" }
      ])
    });
  }

  if (req.method === "GET" && url.pathname === "/profiles") {
    writeDb(db);
    return send(res, 200, {
      profiles: db.profiles.map(publicProfile),
      ui: ui("Profiles", "Signed profiles make counterparty review less blind.")
    });
  }

  if (req.method === "POST" && url.pathname === "/profiles") {
    const item = {
      id: id("profile"),
      at: new Date().toISOString(),
      actor,
      display_name: body.display_name || body.name || body.handle || null,
      role: body.role || "unspecified",
      wallet: body.wallet || body.actor_addr || actor.address || null,
      portfolio: body.portfolio || null,
      credentials: body.credentials || null,
      confidentiality_terms: body.confidentiality_terms || null,
      revision_policy: body.revision_policy || null,
      reputation_refs: body.reputation_refs || null,
      raw: body,
      status: actor.signed ? "signed" : "unsigned"
    };
    db.profiles.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      profile: item,
      ui: ui("Profile recorded", "Use this profile id or wallet in orders and escrows.")
    });
  }

  if (req.method === "GET" && url.pathname === "/briefs") {
    writeDb(db);
    return send(res, 200, {
      briefs: db.briefs.map((brief) => publicBrief(db, brief, actor)),
      ui: ui("Memoir briefs", "Open briefs are not paid work until an order has verified escrow. Keep public samples short.")
    });
  }

  if (req.method === "POST" && url.pathname === "/briefs") {
    const sampleRisk = briefSampleRisk(body);
    const privacyAssessment = briefPrivacyAssessment(body);
    const item = {
      id: id("brief"),
      at: new Date().toISOString(),
      actor,
      story: body.story || body.memoir || body.want || "",
      audience: body.audience || null,
      tone: body.tone || null,
      budget: body.budget || null,
      deadline: body.deadline || null,
      privacy: body.privacy || "private_until_hired",
      sample_risk: sampleRisk,
      privacy_assessment: privacyAssessment,
      funding_state_hint: "unfunded_open_brief",
      raw: body,
      status: "open"
    };
    db.briefs.push(item);
    db.intents.push({
      id: id("intent"),
      at: item.at,
      actor,
      want: `memoir ghostwriter: ${item.story}`.trim(),
      budget: item.budget,
      deadline: item.deadline,
      constraints: { audience: item.audience, tone: item.tone, privacy: item.privacy },
      raw: body,
      status: "open",
      source: "brief",
      source_id: item.id
    });
    writeDb(db);
    return send(res, 201, {
      ok: true,
      brief: publicBrief(db, item, actor),
      next: [
        { method: "GET", path: "/samples", label: "Check samples" },
        { method: "POST", path: "/feedback", label: "Request missing buyer workflow" }
      ],
      ui: ui(
        sampleRisk.flags.length ? "Brief posted with unpaid sample warning" : privacyAssessment.flags.length ? "Brief posted with privacy warning" : "Brief posted",
        sampleRisk.flags.length
          ? sampleRisk.guidance
          : privacyAssessment.flags.length
            ? privacyAssessment.public_summary_policy
          : "Writers can submit a short protected preview, then move full prose into a funded order."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/samples") {
    writeDb(db);
    return send(res, 200, {
      samples: db.samples.map(publicSample),
      ui: ui("Writer samples", "Buyers can commit with POST /orders.")
    });
  }

  if (req.method === "POST" && url.pathname === "/samples") {
    const fullText = body.full_excerpt || body.full_sample || body.draft || body.excerpt || body.sample || "";
    const explicitPreview =
      body.protected_preview_text ||
      body.public_preview ||
      (typeof body.protected_preview === "string" ? body.protected_preview : null);
    const protectedMode = Boolean(
      body.protected_preview === true ||
      explicitPreview ||
      body.full_excerpt ||
      body.full_sample ||
      body.visibility === "protected"
    );
    const linkedBrief = body.brief_id ? db.briefs.find((brief) => brief.id === body.brief_id) : null;
    const linkedBriefFunded = linkedBrief ? ordersForBrief(db, linkedBrief.id).some((order) => verifiedEscrowForOrder(db, order)) : false;
    const preEscrowLimit = linkedBriefFunded ? 220 : 120;
    const publicPreview = protectedMode ? previewText(explicitPreview || body.excerpt || body.sample || fullText, preEscrowLimit * 7) : previewText(fullText, preEscrowLimit * 7);
    const provenance = body.provenance || body.originality_proof || body.portfolio_url || body.proof || null;
    const duplicateRisk = sampleDuplicateRisk(db, actor, publicPreview, provenance);
    const sampleRiskFlags = [
      ...duplicateRisk.flags,
      ...(!linkedBriefFunded && wordCount(fullText) > 500 ? ["long_unfunded_audition_text_withheld"] : []),
      ...(!provenance ? ["missing_sample_provenance"] : [])
    ];
    const copiedPublicPreview = duplicateRisk.flags.includes("provenance_admits_copied_public_preview");
    const blockedDuplicate = (
      duplicateRisk.flags.includes("duplicate_public_sample_text") &&
      (duplicateRisk.flags.includes("missing_provenance_for_duplicate_text") || copiedPublicPreview)
    ) || copiedPublicPreview;
    const item = {
      id: id("sample"),
      at: new Date().toISOString(),
      actor,
      brief_id: body.brief_id || null,
      excerpt: publicPreview,
      protected_preview: protectedMode,
      preview_source: explicitPreview ? "protected_preview_text" : protectedMode ? "generated_from_submission" : "full_public_excerpt",
      full_excerpt_stored: protectedMode ? "withheld_until_funded_order" : null,
      text_fingerprint: duplicateRisk.fingerprint,
      duplicate_of_sample_id: duplicateRisk.duplicate_of_sample_id,
      provenance,
      risk_flags: sampleRiskFlags,
      unfunded_preview_policy: {
        linked_brief_funded: linkedBriefFunded,
        max_public_preview_words: preEscrowLimit,
        full_scene_delivery_requires_verified_escrow: true
      },
      price: body.price || null,
      terms: body.terms || null,
      proof: body.proof || null,
      raw: body,
      status: blockedDuplicate ? "blocked_copied_or_duplicate_public_preview" : "submitted"
    };
    db.samples.push(item);
    if (item.status === "submitted") {
      db.offers.push({
        id: id("offer"),
        at: item.at,
        actor,
        can_do: `memoir sample for ${item.brief_id || "open brief"}`,
        price: item.price,
        proof: item.proof || item.excerpt.slice(0, 240),
        terms: item.terms,
        raw: body,
        status: "open",
        source: "sample",
        source_id: item.id
      });
    }
    writeDb(db);
    return send(res, 201, {
      ok: item.status === "submitted",
      sample: item,
      next: [
        { method: "POST", path: "/proposals", label: "Open proposal" },
        { method: "POST", path: "/orders", label: "Buyer commit" }
      ],
      ui: ui(
        item.status === "submitted" ? "Sample submitted" : "Sample blocked",
        item.status !== "submitted"
          ? "Copied or duplicate public preview text cannot create a listed writer sample or offer."
          : protectedMode
          ? "Only the preview is public. Use /proposals for questions and terms before funding."
          : "A buyer can now commit to this writer; full reusable prose belongs in funded delivery."
      )
    });
  }

  if (req.method === "GET" && url.pathname.startsWith("/proposals/")) {
    const proposalId = url.pathname.split("/")[2];
    const proposal = db.proposals.find((candidate) => candidate.id === proposalId);
    if (!proposal) {
      writeDb(db);
      return send(res, 404, { error: "proposal_not_found", ui: ui("Proposal not found", "Use GET /proposals.") });
    }
    if (!canViewProposal(db, proposal, actor)) {
      writeDb(db);
      return send(res, 403, {
        error: "private_proposal",
        ui: ui("Private proposal", "Only signed proposal participants can view the full thread.")
      });
    }
    writeDb(db);
    return send(res, 200, {
      proposal: publicProposal(db, proposal, actor),
      ui: ui("Proposal thread", "Use POST /proposals with proposal_id to reply, confirm terms, or move toward escrow.")
    });
  }

  if (req.method === "GET" && url.pathname === "/proposals") {
    writeDb(db);
    return send(res, 200, {
      proposals: db.proposals.map((proposal) => publicProposal(db, proposal, actor)),
      ui: ui("Proposals", "Use proposal threads for interview questions, payee confirmation, terms, and milestone acceptance before /orders.")
    });
  }

  if (req.method === "POST" && url.pathname === "/proposals") {
    const existing = body.proposal_id ? db.proposals.find((proposal) => proposal.id === body.proposal_id) : null;
    const linkedBriefId = body.brief_id || existing?.brief_id || null;
    const linkedBrief = linkedBriefId ? db.briefs.find((brief) => brief.id === linkedBriefId) : null;
    const message = {
      id: id("msg"),
      at: new Date().toISOString(),
      actor,
      role: body.role || "participant",
      message: body.message || "",
      questions: body.questions || null,
      terms: body.terms || null,
      buyer_addr: body.buyer_addr || linkedBrief?.actor?.address || null,
      payee_addr: body.payee_addr || null,
      milestone_amount: body.milestone_amount || body.amount || null,
      acceptance_criteria: body.acceptance_criteria || null,
      chapter_architecture: body.chapter_architecture || null,
      rights_terms: body.rights_terms || null,
      revision_terms: body.revision_terms || null
    };

    if (existing) {
      if (!canViewProposal(db, existing, actor)) {
        writeDb(db);
        return send(res, 403, {
          error: "private_proposal",
          ui: ui("Private proposal", "Only signed proposal participants can add to this thread.")
        });
      }
      existing.messages.push(message);
      existing.updated_at = message.at;
      if (body.buyer_addr) existing.buyer_addr = body.buyer_addr;
      if (body.payee_addr) existing.payee_addr = body.payee_addr;
      if (body.milestone_amount || body.amount) existing.milestone_amount = body.milestone_amount || body.amount;
      if (body.terms) existing.terms = body.terms;
      if (body.chapter_architecture) existing.chapter_architecture = body.chapter_architecture;
      if (body.rights_terms) existing.rights_terms = body.rights_terms;
      if (body.revision_terms) existing.revision_terms = body.revision_terms;
      if (body.status) existing.status = body.status;
      writeDb(db);
      return send(res, 201, {
        ok: true,
        proposal: existing,
        ui: ui("Proposal updated", "Confirm payee, milestone amount, acceptance criteria, and escrow before creating /orders.")
      });
    }

    const item = {
      id: id("proposal"),
      at: message.at,
      updated_at: message.at,
      actor,
      brief_id: body.brief_id || null,
      sample_id: body.sample_id || null,
      match_id: body.match_id || null,
      intent_id: body.intent_id || null,
      offer_id: body.offer_id || null,
      buyer_addr: body.buyer_addr || linkedBrief?.actor?.address || null,
      payee_addr: body.payee_addr || null,
      milestone_amount: body.milestone_amount || body.amount || null,
      visibility: body.visibility === "public" ? "public" : "private_thread",
      terms: body.terms || null,
      acceptance_criteria: body.acceptance_criteria || null,
      chapter_architecture: body.chapter_architecture || null,
      rights_terms: body.rights_terms || null,
      revision_terms: body.revision_terms || null,
      messages: [message],
      raw: body,
      status: actor.signed ? "open" : "unsigned_draft"
    };
    db.proposals.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      proposal: item,
      next: [
        {
          method: "POST",
          path: "/orders",
          label: "Fund milestone",
          body_hint: {
            proposal_id: item.id,
            brief_id: item.brief_id,
            amount: item.milestone_amount,
            payee_addr: item.payee_addr
          }
        }
      ],
      ui: ui(item.visibility === "public" ? "Proposal opened" : "Private proposal opened", "Confirm payee, milestone amount, acceptance criteria, and escrow before creating /orders.")
    });
  }

  if (req.method === "POST" && url.pathname === "/intents") {
    const item = {
      id: id("intent"),
      at: new Date().toISOString(),
      actor,
      want: body.want || body.need || body.job || "",
      budget: body.budget || null,
      deadline: body.deadline || null,
      constraints: body.constraints || null,
      raw: body,
      status: "open"
    };
    db.intents.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      intent: item,
      next: [
        { method: "GET", path: "/offers", label: "Find supply" },
        { method: "POST", path: "/feedback", label: "Say what was missing" }
      ],
      ui: ui("Intent posted", "Supply agents can now answer this demand.")
    });
  }

  if (req.method === "GET" && url.pathname === "/offers") {
    writeDb(db);
    return send(res, 200, {
      offers: db.offers.map((offer) => publicOffer(offer, actor)),
      ui: ui("Available supply", "Post /offers if you can satisfy an open intent.")
    });
  }

  if (req.method === "POST" && url.pathname === "/offers") {
    const item = {
      id: id("offer"),
      at: new Date().toISOString(),
      actor,
      can_do: body.can_do || body.offer || body.service || "",
      price: body.price || null,
      proof: body.proof || null,
      terms: body.terms || null,
      raw: body,
      status: "open"
    };
    db.offers.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      offer: item,
      next: [{ method: "POST", path: "/matches", label: "Propose match" }],
      ui: ui("Offer posted", "Demand agents can now evaluate this supply.")
    });
  }

  if (req.method === "POST" && url.pathname === "/matches") {
    const item = {
      id: id("match"),
      at: new Date().toISOString(),
      actor,
      intent_id: body.intent_id || null,
      offer_id: body.offer_id || null,
      note: body.note || "",
      raw: body,
      status: "proposed"
    };
    db.matches.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      match: item,
      next: [{ method: "POST", path: "/orders", label: "Commit order" }],
      ui: ui("Match proposed", "Commit with /orders when both sides agree.")
    });
  }

  if (req.method === "POST" && url.pathname === "/orders") {
    const amount = Number(body.amount || body.budget || 0);
    const platformFeeRate = Number(body.platform_fee_rate ?? 0.15);
    const normalizedPlatformFeeRate = Number.isFinite(platformFeeRate) && platformFeeRate >= 0 ? platformFeeRate : 0.15;
    const platformFee = money(amount * normalizedPlatformFeeRate);
    const writerNetEarnings = money(amount - platformFee);
    const milestoneType = memoirMilestoneType(body);
    const risk_flags = [];
    if (!actor.address) risk_flags.push("missing_actor_wallet_address");
    if (!body.payee_addr) risk_flags.push("missing_payee_wallet_address");
    if (!Number.isFinite(amount) || amount <= 0) risk_flags.push("non_positive_amount");
    if (actor.address && body.payee_addr && actor.address === body.payee_addr) {
      risk_flags.push("self_dealing_counterparty");
    }
    if (!body.escrow_id && !body.escrow_proof) risk_flags.push("no_escrow_proof");
    const status =
      risk_flags.includes("non_positive_amount") || risk_flags.includes("self_dealing_counterparty")
        ? "rejected_risk"
        : body.escrow_id || body.escrow_proof
          ? "awaiting_verified_escrow"
          : "awaiting_escrow";
    const item = {
      id: id("order"),
      at: new Date().toISOString(),
      actor,
      intent_id: body.intent_id || null,
      offer_id: body.offer_id || null,
      brief_id: body.brief_id || null,
      sample_id: body.sample_id || null,
      proposal_id: body.proposal_id || null,
      amount: Number.isFinite(amount) ? amount : null,
      milestone_type: milestoneType,
      platform_fee_rate: normalizedPlatformFeeRate,
      platform_fee: platformFee,
      writer_net_earnings: writerNetEarnings,
      payee_addr: body.payee_addr || null,
      escrow_id: body.escrow_id || null,
      escrow_proof: body.escrow_proof || null,
      delivery_due_at: body.delivery_due_at || body.due_at || body.deadline || null,
      deliverable: body.deliverable || body.outcome || "",
      raw: body,
      risk_flags,
      status: actor.signed ? status : "unsigned_draft"
    };
    db.orders.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      order: publicOrderSummary(db, item, actor),
      conversion_candidate: false,
      ui: ui(
        item.status === "funded" ? "Funded order recorded" : "Order needs trust proof",
        item.status === "funded"
          ? "This is strong PMF signal."
          : "Attach a real numeric chain escrow id with /escrows before this counts as a funded conversion."
      )
    });
  }

  if (req.method === "POST" && url.pathname === "/escrows") {
    const chainEscrow = await getChainEscrow(body.escrow_id || body.chain_escrow_id);
    const chainStatus = chainEscrow && String(chainEscrow.status || "").toLowerCase();
    const order = db.orders.find((candidate) => candidate.id === (body.order_id || null));
    const match = escrowMatchesOrder(chainEscrow, order, body, actor);
    const chainFunded = Boolean(chainEscrow && ["locked", "submitted", "released"].includes(chainStatus) && match.ok);
    const item = {
      id: id("escrow"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      escrow_id: body.escrow_id || body.chain_escrow_id || null,
      payer_addr: body.payer_addr || actor.address || null,
      payee_addr: body.payee_addr || null,
      amount: body.amount || null,
      status: chainFunded ? chainStatus : "unverified",
      proof: body.proof || null,
      chain_escrow: chainEscrow,
      verification_failures: match.failures,
      raw: body
    };
    db.escrows.push(item);
    if (order && actor.signed && chainFunded && item.escrow_id && item.payee_addr && Number(item.amount) > 0) {
      order.status = "funded";
      order.escrow_id = item.escrow_id;
      order.payee_addr = item.payee_addr;
      order.risk_flags = (order.risk_flags || []).filter((flag) => !["no_escrow_proof", "missing_payee_wallet_address", "unverified_escrow"].includes(flag));
      if (order.actor.address && !db.conversions.find((conv) => conv.order_id === order.id)) {
        db.conversions.push({
          id: id("conv"),
          at: new Date().toISOString(),
          actor_addr: order.actor.address,
          source: "funded_order",
          order_id: order.id
        });
      }
      recordAdAttribution(db, order, body, actor);
    } else if (order) {
      const hasVerifiedEscrow = db.escrows.some((candidate) =>
        candidate.order_id === order.id &&
        candidate.chain_escrow &&
        !candidate.verification_failures?.length &&
        ["locked", "submitted", "released"].includes(String(candidate.status || "").toLowerCase())
      );
      order.status = hasVerifiedEscrow ? "funded" : "awaiting_verified_escrow";
      order.risk_flags = Array.from(new Set([...(order.risk_flags || []), "unverified_escrow", ...match.failures]));
    }
    reconcileOrderTrust(db);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      escrow: publicEscrow(db, item, actor),
      order: order ? publicOrderSummary(db, order, actor) : null,
      trust: order ? publicTrustState(db, order, actor) : null,
      ui: ui(chainFunded ? "Escrow verified" : "Escrow not verified", chainFunded ? "Funded orders can proceed to delivery." : "Provide a real numeric chain escrow id before this order counts as funded.")
    });
  }

  if (req.method === "GET" && url.pathname === "/escrows") {
    writeDb(db);
    return send(res, 200, { escrows: db.escrows.map((escrow) => publicEscrow(db, escrow, actor)), ui: ui("Escrows", "Only chain-verified escrows fund orders.") });
  }

  if (req.method === "POST" && url.pathname === "/deliveries") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const isVerifiedWriter = actorIsWriter(order, actor);
    const verifiedEscrow = verifiedEscrowForOrder(db, order);
    const deliveryStatus =
      order && isVerifiedWriter && verifiedEscrow
        ? body.revised_from_revision_id ? "revised" : "submitted"
        : !order ? "invalid_missing_order"
          : !isVerifiedWriter ? "invalid_unverified_writer"
          : "blocked_unfunded_order";
    const item = {
      id: id("delivery"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      content_hash: body.content_hash || null,
      scene_objective: body.scene_objective || null,
      interview_questions: body.interview_questions || null,
      outline_beats: body.outline_beats || null,
      draft: body.draft || body.full_draft || null,
      excerpt: body.excerpt || previewText(body.draft || body.full_draft || "", 360) || null,
      private_notes: body.private_notes || null,
      revised_from_revision_id: body.revised_from_revision_id || null,
      supersedes_delivery_id: body.supersedes_delivery_id || null,
      rights_transfer: body.rights_transfer || "after_acceptance_and_payment",
      notes: body.notes || "",
      raw: body,
      status: deliveryStatus
    };
    item.quality_evidence = deliveryQualityEvidence(item);
    db.deliveries.push(item);
    if ((deliveryStatus === "submitted" || deliveryStatus === "revised") && item.supersedes_delivery_id) {
      const prior = db.deliveries.find((delivery) =>
        delivery.id === item.supersedes_delivery_id &&
        delivery.order_id === item.order_id &&
        actorIsWriter(order, delivery.actor)
      );
      if (prior && !verifiedAcceptanceForOrder(db, order, prior.id)) {
        prior.status = `superseded_by_${item.id}`;
      }
    }
    writeDb(db);
    return send(res, 201, {
      ok: true,
      delivery: publicDelivery(db, item, order, actor),
      next: [
        { method: "POST", path: "/acceptances", label: "Accept delivery" },
        { method: "POST", path: "/revisions", label: "Request revision" },
        { method: "POST", path: "/disputes", label: "Open dispute" }
      ],
      ui: ui(
        deliveryStatus === "submitted" || deliveryStatus === "revised" ? "Delivery submitted" : "Delivery blocked",
        deliveryStatus === "submitted" || deliveryStatus === "revised"
          ? "Buyer can accept against the rubric, request revision, or dispute."
          : "Only the verified writer on a funded order can submit delivery."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/deliveries") {
    writeDb(db);
    return send(res, 200, {
      deliveries: db.deliveries.map((delivery) =>
        publicDelivery(db, delivery, db.orders.find((order) => order.id === delivery.order_id), actor)
      ),
      ui: ui("Deliveries", "Use /orders/:id for order-specific status.")
    });
  }

  if (req.method === "POST" && url.pathname === "/order-acknowledgements") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const canAcknowledge = Boolean(order && actorIsWriter(order, actor) && verifiedEscrowForOrder(db, order) && !releasedEscrowForOrder(db, order));
    const item = {
      id: id("ack"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      eta: body.eta || body.delivery_eta || null,
      planned_interview_questions: body.planned_interview_questions || body.questions || null,
      scope_note: body.scope_note || body.note || "",
      raw: body,
      status: canAcknowledge
        ? body.eta || body.delivery_eta ? "delivery_eta_updated" : "acknowledged"
        : !order ? "invalid_missing_order"
          : !actorIsWriter(order, actor) ? "invalid_unverified_writer"
            : releasedEscrowForOrder(db, order) ? "blocked_released_order"
              : "blocked_unfunded_order"
    };
    db.order_acknowledgements.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: canAcknowledge,
      acknowledgement: publicOrderArtifact(db, item, actor),
      order: order ? publicOrderSummary(db, order, actor) : null,
      ui: ui(
        canAcknowledge ? "Funded order acknowledged" : "Acknowledgement blocked",
        canAcknowledge
          ? "Buyer can now see that the signed writer has accepted the funded delivery queue and ETA."
          : "Only the signed payee writer on a verified funded, unreleased order can acknowledge delivery work."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/order-acknowledgements") {
    writeDb(db);
    return send(res, 200, {
      order_acknowledgements: db.order_acknowledgements.map((item) => publicOrderArtifact(db, item, actor)),
      ui: ui("Writer acknowledgements", "Acknowledgements prove the signed payee writer saw funded work before delivery; private planning stays protected.")
    });
  }

  if (req.method === "POST" && url.pathname === "/revisions") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const delivery = db.deliveries.find((candidate) => candidate.id === body.delivery_id);
    const revisionStatus =
      order && actorIsBuyer(order, actor) && verifiedEscrowForOrder(db, order) && (!delivery || delivery.order_id === order.id)
        ? "requested"
        : "invalid_unverified_order_actor_or_delivery";
    const item = {
      id: id("revision"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      delivery_id: body.delivery_id || null,
      request: body.request || "",
      acceptance_blocker: body.acceptance_blocker || null,
      rubric: body.rubric || body.acceptance_rubric || null,
      raw: body,
      status: revisionStatus
    };
    db.revisions.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      revision: item,
      ui: ui(
        revisionStatus === "requested" ? "Revision requested" : "Revision blocked",
        revisionStatus === "requested" ? "The request is now attached to the funded order." : "Only the verified buyer on a funded order can request revision."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/revisions") {
    writeDb(db);
    return send(res, 200, { revisions: db.revisions.map((revision) => publicRevision(db, revision, actor)), ui: ui("Revisions", "Use /orders/:id for order-specific status.") });
  }

  if (req.method === "POST" && url.pathname === "/disputes") {
    const item = {
      id: id("dispute"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      reason: body.reason || "",
      requested_resolution: body.requested_resolution || null,
      raw: body,
      status: "open"
    };
    db.disputes.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      dispute: item,
      ui: ui("Dispute opened", "This records refund or quality concerns for adjudication.")
    });
  }

  if (req.method === "GET" && url.pathname === "/disputes") {
    writeDb(db);
    return send(res, 200, { disputes: db.disputes.map((item) => publicOrderArtifact(db, item, actor)), ui: ui("Disputes", "Open refund or quality concerns.") });
  }

  if (req.method === "POST" && url.pathname === "/acceptances") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const delivery = verifiedWriterDeliveryForOrder(db, order, body.delivery_id);
    const verifiedEscrow = verifiedEscrowForOrder(db, order);
    const escrowId = verifiedEscrow && verifiedEscrow.escrow_id;
    const baseCanAccept = order && delivery && escrowId && actorIsBuyer(order, actor);
    const releaseDecision = delivery ? acceptanceReleaseDecision(delivery, body) : null;
    const canAccept = Boolean(baseCanAccept && releaseDecision?.can_offer_release_command);
    const qualityEvidence = releaseDecision?.evidence || null;
    const acceptanceStatus = !baseCanAccept
      ? "invalid_unverified_order_delivery_escrow_or_buyer"
      : !releaseDecision.can_offer_release_command
        ? "blocked_needs_memoir_quality_evidence"
        : releaseDecision.explicit_override
          ? "ready_to_release_quality_override"
          : "ready_to_release";
    const item = {
      id: id("accept"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      delivery_id: body.delivery_id || null,
      notes: body.notes || "",
      acceptance_rubric: body.acceptance_rubric || body.rubric || null,
      quality_evidence: qualityEvidence,
      release_risk: releaseDecision?.release_risk || "invalid_unverified_order_delivery_escrow_or_buyer",
      quality_override: releaseDecision?.explicit_override ? {
        accepted: true,
        reason: releaseDecision.override_reason
      } : null,
      release_command: canAccept ? `ag3nt escrow-release ${escrowId}` : null,
      raw: body,
      status: acceptanceStatus
    };
    db.acceptances.push(item);
    if (order && ["ready_to_release", "ready_to_release_quality_override"].includes(item.status)) order.status = "accepted_pending_release";
    writeDb(db);
    return send(res, 201, {
      ok: true,
      acceptance: item,
      acceptance_checklist: acceptanceChecklist(delivery, latestRevisionAfterDelivery(db, order, delivery)),
      ui: ui(
        item.release_command ? "Acceptance recorded" : "Acceptance held",
        item.release_command
          ? item.status === "ready_to_release_quality_override"
            ? `Quality override recorded; release is payment-only and will not create verified reputation. Release funds with: ${item.release_command}`
            : `Release funds with: ${item.release_command}`
          : "Release needs a verified funded order, verified writer delivery, and memoir quality evidence or an explicit buyer quality override with a reason."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/acceptances") {
    writeDb(db);
    return send(res, 200, { acceptances: db.acceptances.map((item) => publicOrderArtifact(db, item, actor)), ui: ui("Acceptances", "Accepted deliveries can be released on chain; reputation requires memoir quality evidence.") });
  }

  if (req.method === "POST" && url.pathname === "/refunds") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const verifiedEscrow = verifiedEscrowForOrder(db, order);
    const escrowId = verifiedEscrow && verifiedEscrow.escrow_id;
    const alreadyAccepted = Boolean(verifiedAcceptanceForOrder(db, order));
    const canRefund = order && actorIsBuyer(order, actor) && escrowId && !alreadyAccepted;
    const item = {
      id: id("refund"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      reason: body.reason || "",
      refund_command: canRefund ? `ag3nt escrow-refund ${escrowId}` : null,
      raw: body,
      status: canRefund ? "refund_requested" : alreadyAccepted ? "blocked_after_acceptance" : "invalid_unverified_order_escrow_or_buyer"
    };
    db.refunds.push(item);
    if (order && item.status === "refund_requested") order.status = "refund_requested";
    writeDb(db);
    return send(res, 201, {
      ok: true,
      refund: item,
      ui: ui("Refund path recorded", item.refund_command ? `Try refund with: ${item.refund_command}; open /disputes if refund is blocked.` : "No escrow id is attached to this order.")
    });
  }

  if (req.method === "GET" && url.pathname === "/refunds") {
    writeDb(db);
    return send(res, 200, { refunds: db.refunds.map((item) => publicOrderArtifact(db, item, actor)), ui: ui("Refunds", "Refund requests and chain commands.") });
  }

  if (req.method === "POST" && url.pathname === "/releases") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const escrowId = body.escrow_id || (order && order.escrow_id);
    const chainEscrow = await getChainEscrow(escrowId);
    const chainStatus = chainEscrow && String(chainEscrow.status || "").toLowerCase();
    const verifiedEscrow = verifiedEscrowForOrder(db, order);
    const accepted = verifiedAcceptanceForOrder(db, order);
    const escrowMatch = escrowMatchesOrder(chainEscrow, order, body, actor);
    const releaseFailures = [
      ...escrowMatch.failures,
      ...(!order ? ["missing_order"] : []),
      ...(!actorIsBuyer(order, actor) ? ["actor_not_verified_buyer"] : []),
      ...(!verifiedEscrow ? ["missing_verified_order_escrow"] : []),
      ...(!accepted ? ["missing_verified_acceptance"] : []),
      ...(verifiedEscrow && String(escrowId) !== String(verifiedEscrow.escrow_id) ? ["release_escrow_not_bound_to_order"] : []),
      ...(chainStatus !== "released" ? ["chain_escrow_not_released"] : [])
    ];
    const releaseVerified = releaseFailures.length === 0;
    const item = {
      id: id("release"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      escrow_id: escrowId || null,
      proof: body.proof || null,
      chain_escrow: chainEscrow,
      verification_failures: releaseFailures,
      raw: body,
      status: releaseVerified ? "released" : "awaiting_buyer_acceptance_or_chain_release"
    };
    db.releases.push(item);
    if (order && releaseVerified) order.status = "released";
    writeDb(db);
    return send(res, 201, {
      ok: true,
      release: item,
      order,
      ui: ui(releaseVerified ? "Release verified" : "Release not verified", releaseVerified ? "Reviews can now count as paid verified reputation." : "Run the release command and repost /releases once chain status is released.")
    });
  }

  if (req.method === "GET" && url.pathname === "/releases") {
    writeDb(db);
    return send(res, 200, { releases: db.releases.map((item) => publicOrderArtifact(db, item, actor)), ui: ui("Releases", "Release records tie paid reputation to chain release status.") });
  }

  if (req.method === "POST" && url.pathname === "/order-declines") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const canDecline = order && actorIsWriter(order, actor) && !verifiedEscrowForOrder(db, order);
    const item = {
      id: id("decline"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      reason: body.reason || "",
      raw: body,
      status: canDecline ? "declined_pending_verified_escrow" : verifiedEscrowForOrder(db, order) ? "blocked_order_already_verified_funded" : "invalid_unverified_writer_or_order"
    };
    db.order_declines.push(item);
    if (order && item.status === "declined_pending_verified_escrow") order.status = "declined_pending_verified_escrow";
    writeDb(db);
    return send(res, 201, {
      ok: item.status === "declined_pending_verified_escrow",
      decline: publicOrderArtifact(db, item, actor),
      order: order ? publicOrderSummary(db, order, actor) : null,
      ui: ui(
        item.status === "declined_pending_verified_escrow" ? "Order declined until funded" : "Decline blocked",
        item.status === "declined_pending_verified_escrow"
          ? "The writer queue will treat this as escrow bait until the buyer attaches real verified chain escrow."
          : "Only the signed payee writer can decline an unfunded or unverified order."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/order-declines") {
    writeDb(db);
    return send(res, 200, {
      order_declines: db.order_declines.map((item) => publicOrderArtifact(db, item, actor)),
      ui: ui("Order declines", "Declines protect writers from unfunded full-draft pressure and are superseded by real verified escrow.")
    });
  }

  if (req.method === "POST" && url.pathname === "/publication-consents") {
    const decision = publicationConsentDecision(db, body, actor);
    const readerSalesConsent = body.reader_sales_consent === true || body.writer_consent === true;
    const signedWriterCanControlPublication = Boolean(decision.order && decision.delivery && actorIsWriter(decision.order, actor));
    const consentStatus = readerSalesConsent
      ? decision.ok ? "verified_writer_publication_consent" : "blocked_writer_publication_consent"
      : signedWriterCanControlPublication ? "writer_publication_consent_denied_or_revoked" : "blocked_writer_publication_consent";
    const item = {
      id: id("pubconsent"),
      at: new Date().toISOString(),
      actor,
      publication_id: body.publication_id || null,
      order_id: body.order_id || decision.publication?.order_id || null,
      delivery_id: body.delivery_id || decision.publication?.delivery_id || null,
      reader_sales_consent: readerSalesConsent,
      max_reader_price: decision.max_reader_price,
      rights_scope: body.rights_scope || decision.publication?.rights_scope || null,
      reader_license_terms: body.reader_license_terms || decision.publication?.reader_license_terms || "personal_read_access_only_no_reuse_no_training_no_redistribution",
      consent_terms: body.consent_terms || body.writer_consent_evidence || null,
      verification_failures: consentStatus === "writer_publication_consent_denied_or_revoked" ? ["writer_publication_consent_denied_or_revoked"] : decision.failures,
      raw: body,
      status: consentStatus
    };
    db.publication_consents.push(item);
    reconcileOrderTrust(db);
    writeDb(db);
    return send(res, 201, {
      ok: item.status === "verified_writer_publication_consent",
      publication_consent: publicPublicationConsent(db, item, actor),
      publication: decision.publication ? publicPublication(db, decision.publication, actor) : null,
      ui: ui(
        item.status === "verified_writer_publication_consent"
          ? "Writer consent verified"
          : item.status === "writer_publication_consent_denied_or_revoked"
            ? "Writer consent revoked"
            : "Writer consent blocked",
        item.status === "verified_writer_publication_consent"
          ? "This signed writer consent can satisfy the catalog rights gate for the matching publication/order delivery."
          : item.status === "writer_publication_consent_denied_or_revoked"
            ? "Future reader-sale listing for the matching publication/order delivery is blocked until the signed writer grants consent again."
          : "Only the signed order writer can consent to reader sales, and the consent must explicitly allow reader access or publication."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/publication-consents") {
    let consents = db.publication_consents.slice();
    const publicationFilter = url.searchParams.get("publication_id");
    const orderFilter = url.searchParams.get("order_id");
    const writerFilter = url.searchParams.get("writer_addr");
    if (publicationFilter) consents = consents.filter((consent) => consent.publication_id === publicationFilter);
    if (orderFilter) consents = consents.filter((consent) => consent.order_id === orderFilter);
    if (writerFilter === "me") consents = actor.signed ? consents.filter((consent) => isSameAddress(consent.actor?.address, actor.address)) : [];
    else if (writerFilter) consents = consents.filter((consent) => isSameAddress(consent.actor?.address, writerFilter));
    writeDb(db);
    return send(res, 200, {
      publication_consents: consents.map((consent) => publicPublicationConsent(db, consent, actor)),
      ui: ui("Publication consents", "Signed writer consent is required before any released memoir delivery can be sold to readers.")
    });
  }

  if (req.method === "POST" && url.pathname === "/publications") {
    const decision = publicationRightsDecision(db, body, actor);
    const order = decision.order;
    const delivery = decision.delivery;
    const price = decision.price;
    const platformFeeRate = Number(body.platform_fee_rate ?? 0.15);
    const writerRoyaltyRate = Number(body.writer_royalty_rate ?? 0.25);
    const platformFee = Number.isFinite(platformFeeRate) ? Math.max(0, Math.round(price * platformFeeRate * 100) / 100) : 0;
    const writerRoyalty = Number.isFinite(writerRoyaltyRate) ? Math.max(0, Math.round(price * writerRoyaltyRate * 100) / 100) : 0;
    const item = {
      id: id("pub"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      delivery_id: body.delivery_id || null,
      title: body.title || "Untitled memoir excerpt",
      subtitle: body.subtitle || null,
      public_preview: delivery ? publicPreviewForPublication(delivery, body) : previewText(body.public_preview || body.preview || "", 720),
      preview_word_count: decision.preview_words,
      price,
      platform_fee: platformFee,
      writer_royalty: writerRoyalty,
      rights_holder_earnings: Math.max(0, Math.round((price - platformFee - writerRoyalty) * 100) / 100),
      payee_addr: body.payee_addr || body.rights_holder_addr || order?.actor?.address || null,
      rights_holder_addr: body.rights_holder_addr || order?.actor?.address || null,
      writer_addr: order?.payee_addr || null,
      buyer_consent: body.buyer_consent === true || body.rights_holder_consent === true,
      writer_consent: Boolean(decision.writer_consent),
      verified_writer_consent_id: decision.writer_consent?.id || null,
      writer_consent_evidence: body.writer_consent_evidence || null,
      rights_scope: body.rights_scope || null,
      reader_license_terms: body.reader_license_terms || "personal_read_access_only_no_reuse_no_training_no_redistribution",
      rights_verified_after_release: Boolean(decision.released),
      rights_verification_failures: decision.failures,
      raw: body,
      status: decision.ok ? "listed" : "blocked_rights_or_release_missing"
    };
    db.publications.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: item.status === "listed",
      publication: publicPublication(db, item, actor),
      rights_gate: {
        ok: decision.ok,
        failures: decision.failures
      },
      ui: ui(
        item.status === "listed" ? "Publication listed" : "Publication blocked",
        item.status === "listed"
          ? "Catalog shows only the rights-scoped preview. Readers need verified payment for full access."
          : "Reader sales require released paid delivery, buyer consent, signed writer consent, explicit reader-sale rights, a positive price, and a short preview."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/catalog") {
    let publications = db.publications.filter((publication) => publication.status === "listed");
    const writerFilter = url.searchParams.get("writer_addr");
    const rightsHolderFilter = url.searchParams.get("rights_holder_addr");
    if (writerFilter) publications = publications.filter((publication) => isSameAddress(publication.writer_addr, writerFilter));
    if (rightsHolderFilter) publications = publications.filter((publication) => isSameAddress(publication.rights_holder_addr, rightsHolderFilter));
    writeDb(db);
    return send(res, 200, {
      catalog: publications.map((publication) => publicPublication(db, publication, actor)),
      metrics: {
        listed_publications: publications.length,
        paid_reader_purchases: db.reader_purchases.filter((purchase) => purchase.status === "verified_paid_read_access").length,
        verified_reader_reviews: db.reader_reviews.filter((review) => review.status === "verified_reader_review").length
      },
      ui: ui("Reader catalog", "Only rights-cleared released memoir material is listed; previews are short and paid access gates the full text.")
    });
  }

  if (req.method === "GET" && url.pathname.startsWith("/catalog/") && url.pathname.endsWith("/read")) {
    const publicationId = url.pathname.split("/")[2];
    const publication = db.publications.find((candidate) => candidate.id === publicationId);
    const purchase = verifiedReaderPurchaseForPublication(db, publication, actor);
    const order = publication ? db.orders.find((candidate) => candidate.id === publication.order_id) : null;
    const delivery = publication ? db.deliveries.find((candidate) => candidate.id === publication.delivery_id) : null;
    const canRead = Boolean(publication?.status === "listed" && (purchase || actorCanViewOrderPrivate(order, actor)));
    writeDb(db);
    if (!publication) return send(res, 404, { error: "publication_not_found", ui: ui("Publication not found", "Use GET /catalog.") });
    if (!canRead) {
      return send(res, 402, {
        error: "paid_read_access_required",
        publication: publicPublication(db, publication, actor),
        purchase_hint: {
          method: "POST",
          path: "/reader-purchases",
          body: {
            publication_id: publication.id,
            amount: publication.price,
            payee_addr: publication.payee_addr,
            escrow_ref: publication.id
          }
        },
        ui: ui("Payment required", "Full memoir text is private unless the reader has a verified paid read-access event.")
      });
    }
    return send(res, 200, {
      publication: publicPublication(db, publication, actor),
      reader_purchase: purchase ? publicReaderPurchase(db, purchase, actor) : null,
      full_text: delivery?.draft || delivery?.excerpt || null,
      license: publication.reader_license_terms,
      ui: ui("Paid read access", "This read view is licensed to the verified buyer and must not be redistributed.")
    });
  }

  if (req.method === "POST" && url.pathname === "/reader-purchases") {
    const publication = db.publications.find((candidate) => candidate.id === body.publication_id);
    const chainEscrow = await getChainEscrow(body.escrow_id || body.chain_escrow_id);
    const chainStatus = chainEscrow && String(chainEscrow.status || "").toLowerCase();
    const match = readerPurchaseMatchesPublication(chainEscrow, publication, body, actor);
    const actorFailures = readerPurchaseActorFailures(body, chainEscrow, actor);
    const verificationFailures = [...match.failures, ...actorFailures];
    const verified = Boolean(publication?.status === "listed" && chainEscrow && ["locked", "submitted", "released"].includes(chainStatus) && !verificationFailures.length);
    const amount = Number(body.amount || publication?.price || 0);
    const split = verified ? readerEarningSplit(publication, amount) : readerEarningSplit(null, 0);
    const item = {
      id: id("readbuy"),
      at: new Date().toISOString(),
      actor,
      publication_id: body.publication_id || null,
      escrow_id: body.escrow_id || body.chain_escrow_id || null,
      payer_addr: body.payer_addr || actor.address || null,
      payee_addr: body.payee_addr || publication?.payee_addr || null,
      amount: Number.isFinite(amount) ? amount : null,
      platform_fee: split.platform_fee,
      writer_royalty: split.writer_royalty,
      rights_holder_earnings: split.rights_holder_earnings,
      proof: body.proof || null,
      chain_escrow: chainEscrow,
      verification_failures: verificationFailures,
      raw: body,
      status: verified ? "verified_paid_read_access" : "awaiting_verified_reader_payment"
    };
    db.reader_purchases.push(item);
    if (verified) {
      upsertReaderEarning(db, item, publication);
      recordReaderAdAttribution(db, item, publication, body);
    }
    writeDb(db);
    return send(res, 201, {
      ok: verified,
      reader_purchase: publicReaderPurchase(db, item, actor),
      publication: publication ? publicPublication(db, publication, actor) : null,
      ui: ui(
        verified ? "Read access verified" : "Read access not verified",
        verified ? `Full text is available at /catalog/${publication.id}/read.` : "Reader access requires a listed publication and a funded chain escrow whose ref is the publication id, signed by the chain payer."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/reader-purchases") {
    let purchases = db.reader_purchases.slice();
    const publicationFilter = url.searchParams.get("publication_id");
    const mineOnly = url.searchParams.get("mine") === "true";
    if (publicationFilter) purchases = purchases.filter((purchase) => purchase.publication_id === publicationFilter);
    if (mineOnly) purchases = actor.signed ? purchases.filter((purchase) => isSameAddress(purchase.actor?.address, actor.address)) : [];
    writeDb(db);
    return send(res, 200, {
      reader_purchases: purchases.map((purchase) => publicReaderPurchase(db, purchase, actor)),
      ui: ui("Reader purchases", "Verified purchases unlock read access and reader review eligibility only when the signed reader wallet matches the chain payer.")
    });
  }

  if (req.method === "GET" && url.pathname === "/reader-earnings") {
    let earnings = db.reader_earnings.slice();
    const publicationFilter = url.searchParams.get("publication_id");
    const writerFilter = url.searchParams.get("writer_addr");
    const rightsHolderFilter = url.searchParams.get("rights_holder_addr");
    const statusFilter = url.searchParams.get("status");
    if (publicationFilter) earnings = earnings.filter((earning) => earning.publication_id === publicationFilter);
    if (writerFilter) earnings = earnings.filter((earning) => isSameAddress(earning.writer_addr, writerFilter));
    if (rightsHolderFilter) earnings = earnings.filter((earning) => isSameAddress(earning.rights_holder_addr, rightsHolderFilter));
    if (statusFilter) earnings = earnings.filter((earning) => earning.status === statusFilter);
    const verifiedEarnings = earnings.filter((earning) => earning.status === "earned_from_verified_reader_purchase");
    writeDb(db);
    return send(res, 200, {
      reader_earnings: earnings.map((earning) => publicReaderEarning(db, earning, actor)),
      summary: {
        verified_reader_purchase_count: verifiedEarnings.length,
        reader_revenue: verifiedEarnings.reduce((sum, earning) => sum + Number(earning.amount || 0), 0),
        platform_fees: verifiedEarnings.reduce((sum, earning) => sum + Number(earning.platform_fee || 0), 0),
        writer_royalties: verifiedEarnings.reduce((sum, earning) => sum + Number(earning.writer_royalty || 0), 0),
        rights_holder_earnings: verifiedEarnings.reduce((sum, earning) => sum + Number(earning.rights_holder_earnings || 0), 0)
      },
      filters: {
        publication_id: publicationFilter,
        writer_addr: writerFilter,
        rights_holder_addr: rightsHolderFilter,
        status: statusFilter
      },
      ui: ui("Reader earnings", "Verified paid read access creates a public-safe earnings ledger without exposing memoir text or private reader feedback.")
    });
  }

  if (req.method === "POST" && url.pathname === "/reader-reviews") {
    const publication = db.publications.find((candidate) => candidate.id === body.publication_id);
    const purchase = db.reader_purchases.find((candidate) =>
      candidate.id === body.reader_purchase_id &&
      candidate.publication_id === body.publication_id
    );
    const verified = Boolean(
      publication?.status === "listed" &&
      purchase?.status === "verified_paid_read_access" &&
      actor.signed &&
      isSameAddress(actor.address, purchase.actor?.address)
    );
    const publicProofText = body.public_blurb || body.public_review || body.message || "";
    const leakRisk = readerReviewLeakRisk(publicProofText);
    const item = {
      id: id("readreview"),
      at: new Date().toISOString(),
      actor,
      publication_id: body.publication_id || null,
      reader_purchase_id: body.reader_purchase_id || null,
      rating: body.rating || null,
      private_message: body.message || "",
      message: body.message || "",
      public_blurb: body.public_blurb || body.public_review || null,
      would_buy_more: body.would_buy_more ?? null,
      leak_risk: leakRisk,
      raw: body,
      status: verified
        ? leakRisk.public_safe && String(publicProofText).trim() ? "verified_reader_review" : "verified_reader_review_private_quote_blocked"
        : "unverified_reader_review"
    };
    db.reader_reviews.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: verified && leakRisk.public_safe,
      reader_review: publicReaderReview(db, item, actor),
      ui: ui(
        verified && leakRisk.public_safe
          ? "Reader review verified"
          : verified
            ? "Reader review protected"
            : "Reader review not verified",
        verified && leakRisk.public_safe
          ? "This review counts because it follows verified paid read access and does not expose reusable memoir text."
          : verified
            ? leakRisk.policy
            : "Reader reviews require the same signed reader wallet that made verified paid read access."
      )
    });
  }

  if (req.method === "GET" && url.pathname === "/reader-reviews") {
    let reviews = db.reader_reviews.slice();
    const publicationFilter = url.searchParams.get("publication_id");
    const statusFilter = url.searchParams.get("status");
    if (publicationFilter) reviews = reviews.filter((review) => review.publication_id === publicationFilter);
    if (statusFilter) reviews = reviews.filter((review) => review.status === statusFilter);
    writeDb(db);
    return send(res, 200, {
      reader_reviews: reviews.map((review) => publicReaderReview(db, review, actor)),
      summary: {
        total_reader_reviews: reviews.length,
        verified_reader_reviews: reviews.filter((review) => review.status === "verified_reader_review").length,
        protected_paid_reader_reviews: reviews.filter((review) => review.status === "verified_reader_review_private_quote_blocked").length
      },
      ui: ui("Reader reviews", "Only post-purchase reader reviews that avoid reusable memoir passages count as public reader-facing proof.")
    });
  }

  if (req.method === "GET" && url.pathname === "/ad-readiness") {
    writeDb(db);
    return send(res, 200, {
      ...adReadiness(db),
      publisher_guidance_path: "/publisher-ad-guidance",
      ui: ui("Ad readiness", "Use this before launching ag3ntads campaigns or serving contextual placements.")
    });
  }

  if (req.method === "GET" && url.pathname === "/publisher-ad-guidance") {
    writeDb(db);
    return send(res, 200, {
      ...publisherAdGuidance(db),
      ui: ui("Publisher ad guidance", "Serve memoir service ads only in relevant contexts; suppress reader ads until rights and paid read access are verified.")
    });
  }

  if (req.method === "GET" && url.pathname === "/ad-attributions") {
    writeDb(db);
    return send(res, 200, {
      ad_attributions: db.ad_attributions.map((attribution) => publicAdAttribution(db, attribution, actor)),
      ui: ui("Ad attributions", "Only verified funded orders or verified signed paid read access are ready for advertiser-signed ag3ntads conversion attestation.")
    });
  }

  if (req.method === "GET" && url.pathname === "/reviews") {
    let reviews = db.reviews.slice();
    const statusFilter = url.searchParams.get("status");
    const writerFilter = url.searchParams.get("writer_addr");
    const buyerFilter = url.searchParams.get("buyer_addr");
    if (statusFilter) reviews = reviews.filter((review) => review.status === statusFilter);
    if (writerFilter) reviews = reviews.filter((review) => {
      const order = db.orders.find((candidate) => candidate.id === review.order_id);
      return order && isSameAddress(order.payee_addr, writerFilter);
    });
    if (buyerFilter) reviews = reviews.filter((review) => {
      const order = db.orders.find((candidate) => candidate.id === review.order_id);
      return order && isSameAddress(order.actor?.address, buyerFilter);
    });
    const publicReviews = reviews.map((review) => publicReview(db, review, actor));
    writeDb(db);
    return send(res, 200, {
      reviews: publicReviews,
      reputation_summary: {
        total_reviews: publicReviews.length,
        verified_paid_reviews: publicReviews.filter((review) => review.status === "verified_paid_review").length,
        repeat_buyer_intent: publicReviews.filter((review) => review.status === "verified_paid_review" && review.would_pay_again === true).length
      },
      filters: {
        status: statusFilter,
        writer_addr: writerFilter,
        buyer_addr: buyerFilter
      },
      ui: ui("Reviews", "Only verified paid reviews count toward reputation; public text is truncated and private memoir material is withheld.")
    });
  }

  if (req.method === "GET" && url.pathname.startsWith("/writers/") && url.pathname.endsWith("/reputation")) {
    const writerAddr = url.pathname.split("/")[2];
    if (!AGNT_ADDR.test(writerAddr)) {
      writeDb(db);
      return send(res, 400, { error: "invalid_writer_addr", ui: ui("Invalid writer address", "Use /writers/{agnt...}/reputation.") });
    }
    writeDb(db);
    return send(res, 200, {
      reputation: writerReputation(db, writerAddr, actor),
      ui: ui("Writer reputation", "This page counts paid craft evidence, not self-claimed profile text.")
    });
  }

  if (req.method === "POST" && url.pathname === "/reviews") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const accepted = verifiedAcceptanceForOrder(db, order);
    const released = releasedEscrowForOrder(db, order);
    const reputationReady = Boolean(order && reputationEligibleAcceptance(db, order, accepted?.delivery_id) && released);
    const verifiedPaidReview = Boolean(order && actorIsBuyer(order, actor) && accepted && released && reputationReady);
    const paidButNeedsQuality = Boolean(order && actorIsBuyer(order, actor) && accepted && released && !reputationReady);
    const item = {
      id: id("review"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      rating: body.rating || null,
      message: body.message || "",
      would_pay_again: body.would_pay_again ?? null,
      quality_evidence: accepted ? deliveryQualityEvidence(verifiedWriterDeliveryForOrder(db, order, accepted.delivery_id)) : null,
      raw: body,
      status: verifiedPaidReview ? "verified_paid_review" : paidButNeedsQuality ? "paid_review_needs_memoir_quality_evidence" : "unverified_review"
    };
    db.reviews.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      review: item,
      ui: ui("Review recorded", verifiedPaidReview ? "This paid review can count toward reputation." : "Reviews need paid release plus memoir-specific delivery evidence before they count toward reputation.")
    });
  }

  if (req.method === "GET" && url.pathname === "/activity") {
    writeDb(db);
    return send(res, 200, {
      ...publicActivity(db, actor),
      conversions: db.conversions,
      ui: ui("Learning log", "Use this to decide what to build next.")
    });
  }

  writeDb(db);
  return notFound(req, res);
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error(err);
    send(res, 500, { error: "server_error", message: err.message });
  });
});

server.listen(PORT, () => {
  ensureDb();
  console.log(`Ghostwriter Hub listening on http://localhost:${PORT}`);
});
