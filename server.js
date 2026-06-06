const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 4501);
const CHAIN_API = process.env.AG3NT_CHAIN_API || "http://localhost:1317";
const DATA_DIR = path.join(__dirname, "data");
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
      { method: "POST", path: "/briefs", summary: "Memoir buyer: post a writing brief. Body {story,audience,tone,budget,deadline,privacy}." },
      { method: "GET", path: "/briefs", summary: "Browse open ghostwriting briefs." },
      { method: "POST", path: "/samples", summary: "Writer: submit a sample for a brief. Body {brief_id,excerpt,price,terms,proof}." },
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
      { method: "POST", path: "/orders", summary: "Commit to a workflow. Body {brief_id,sample_id,intent_id,offer_id,amount,payee_addr,deliverable,escrow_id}. Positive signed orders without escrow are marked awaiting_escrow." },
      { method: "POST", path: "/escrows", summary: "Attach payment proof/status. Body {order_id,escrow_id,payer_addr,payee_addr,amount,status,proof}." },
      { method: "POST", path: "/deliveries", summary: "Writer delivery. Body {order_id,content_hash,scene_objective,interview_questions,outline_beats,draft,excerpt,rights_transfer,notes,revised_from_revision_id}." },
      { method: "POST", path: "/revisions", summary: "Buyer revision request. Body {order_id,delivery_id,request,acceptance_blocker,rubric}." },
      { method: "POST", path: "/disputes", summary: "Open dispute/refund concern. Body {order_id,reason,requested_resolution}." },
      { method: "POST", path: "/acceptances", summary: "Buyer accepts delivery and gets release command. Body {order_id,delivery_id,notes}." },
      { method: "POST", path: "/refunds", summary: "Buyer requests/refunds escrow before accepted delivery. Body {order_id,reason}." },
      { method: "POST", path: "/releases", summary: "Record/reconcile escrow release after buyer runs chain release. Body {order_id,escrow_id,proof}." },
      { method: "GET", path: "/releases", summary: "Browse release records and chain release status." },
      { method: "POST", path: "/reviews", summary: "Review a delivered sample/order. Body {order_id,rating,message,would_pay_again}." },
      { method: "GET", path: "/ad-attributions", summary: "Verified funded-order ad conversions ready for advertiser-signed ag3ntads attestation." },
      { method: "GET", path: "/activity", summary: "Recent signed usage, feedback, orders, and product learning signals." },
      { method: "POST", path: "/feedback", summary: "Report praise, complaint, bug, or feature request. Body {sentiment,type,endpoint_context,message}." }
    ],
    ui: ui("Ghostwriter Hub", "Post a memoir brief, answer one with a sample, or leave feedback when the workflow misses your need.", [
      { method: "POST", path: "/briefs", label: "Post brief" },
      { method: "POST", path: "/samples", label: "Submit sample" },
      { method: "POST", path: "/proposals", label: "Start proposal" },
      { method: "POST", path: "/profiles", label: "Create profile" },
      { method: "POST", path: "/intents", label: "Post intent" },
      { method: "POST", path: "/feedback", label: "Send feedback" }
    ])
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
      ad_attributions: db.ad_attributions.length,
      signed_orders: db.orders.filter((o) => o.actor.signed).length,
      funded_orders: db.orders.filter((o) => o.status === "funded").length
    },
    metrics: {
      funded_milestones: db.orders.filter((order) => orderTrustState(db, order).verified_escrow).length,
      accepted_deliveries: db.orders.filter((order) => orderTrustState(db, order).accepted_delivery).length,
      released_escrow: db.orders.filter((order) => orderTrustState(db, order).released_escrow).length,
      repeat_buyer_intent: db.reviews.filter((review) => review.status === "verified_paid_review" && review.would_pay_again === true).length,
      writer_earnings: db.orders.reduce((sum, order) => sum + (orderTrustState(db, order).released_escrow ? Number(order.amount || 0) : 0), 0),
      verified_reviews: db.reviews.filter((review) => review.status === "verified_paid_review").length,
      ad_click_to_funded_order: db.ad_attributions.filter((attribution) => attribution.status === "ready_to_attest").length
    },
    recent_feedback: db.feedback.slice(-10).reverse(),
    recent_briefs: db.briefs.slice(-10).reverse().map((brief) => publicBrief(brief, actor)),
    recent_samples: db.samples.slice(-10).reverse().map(publicSample),
    recent_proposals: db.proposals.slice(-10).reverse().map((proposal) => publicProposal(db, proposal, actor)),
    recent_profiles: db.profiles.slice(-10).reverse().map(publicProfile),
    recent_escrows: db.escrows.slice(-10).reverse().map((escrow) => publicEscrow(db, escrow, actor)),
    recent_intents: db.intents.slice(-10).reverse(),
    recent_offers: db.offers.slice(-10).reverse(),
    recent_orders: db.orders.slice(-10).reverse().map((order) => publicOrder(order, actor)),
    recent_deliveries: db.deliveries.slice(-10).reverse().map((delivery) => publicDelivery(db, delivery, db.orders.find((order) => order.id === delivery.order_id), actor)),
    recent_revisions: db.revisions.slice(-10).reverse(),
    recent_disputes: db.disputes.slice(-10).reverse(),
    recent_acceptances: db.acceptances.slice(-10).reverse().map((acceptance) => publicOrderArtifact(db, acceptance, actor)),
    recent_refunds: db.refunds.slice(-10).reverse().map((refund) => publicOrderArtifact(db, refund, actor)),
    recent_releases: db.releases.slice(-10).reverse().map((release) => publicOrderArtifact(db, release, actor)),
    recent_reviews: db.reviews.slice(-10).reverse().map((review) => publicOrderArtifact(db, review, actor)),
    recent_ad_attributions: db.ad_attributions.slice(-10).reverse(),
    recent_requests: db.requests.slice(-20).reverse()
  };
}

function previewText(text, max = 360) {
  const clean = String(text || "").replace(/\s+/g, " ").trim();
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max).trim()}...`;
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
    acceptance.status === "ready_to_release"
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
  evidence.status = evidence.score >= 3 ? "memoir_quality_evidence_present" : "needs_memoir_quality_evidence";
  return evidence;
}

function reputationEligibleAcceptance(db, order, deliveryId = null) {
  const acceptance = verifiedAcceptanceForOrder(db, order, deliveryId);
  if (!acceptance) return null;
  const delivery = verifiedWriterDeliveryForOrder(db, order, acceptance.delivery_id);
  const evidence = deliveryQualityEvidence(delivery);
  return evidence.status === "memoir_quality_evidence_present" ? { acceptance, delivery, evidence } : null;
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

function orderTrustState(db, order) {
  const verified_escrow = verifiedEscrowForOrder(db, order);
  const latest_writer_delivery = verifiedWriterDeliveryForOrder(db, order);
  const accepted_delivery = verifiedAcceptanceForOrder(db, order, latest_writer_delivery?.id);
  const quality_evidence = latest_writer_delivery ? deliveryQualityEvidence(latest_writer_delivery) : null;
  const reputation_eligible_acceptance = accepted_delivery && quality_evidence?.status === "memoir_quality_evidence_present" ? accepted_delivery : null;
  const released_escrow = accepted_delivery ? releasedEscrowForOrder(db, order) : null;
  return {
    buyer_addr: order?.actor?.address || null,
    writer_addr: order?.payee_addr || null,
    verified_escrow: verified_escrow || null,
    latest_writer_delivery: latest_writer_delivery || null,
    delivery_quality_evidence: quality_evidence,
    accepted_delivery: accepted_delivery || null,
    reputation_eligible_acceptance: reputation_eligible_acceptance || null,
    released_escrow: released_escrow || null,
    payment_state: released_escrow ? "released_paid" : accepted_delivery ? "accepted_pending_release" : verified_escrow ? "funded" : "unfunded",
    rights_state: released_escrow ? "transferred_after_release" : accepted_delivery ? "accepted_not_transferred_until_release" : "not_transferred",
    writer_reputation_state: released_escrow && reputation_eligible_acceptance ? "earned_paid_delivery" : released_escrow ? "paid_needs_memoir_quality_evidence" : accepted_delivery ? "pending_release" : verified_escrow ? "pending_delivery_acceptance" : "not_earned"
  };
}

function reconcileOrderTrust(db) {
  for (const order of db.orders) {
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

  for (const conversion of db.conversions) {
    const order = db.orders.find((candidate) => candidate.id === conversion.order_id);
    conversion.status = order && verifiedEscrowForOrder(db, order) ? "verified_funded_order" : "legacy_unverified";
  }

  for (const attribution of db.ad_attributions) {
    const order = db.orders.find((candidate) => candidate.id === attribution.order_id);
    attribution.status = order && verifiedEscrowForOrder(db, order) ? "ready_to_attest" : "blocked_unverified_order";
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

function publicProfile(profile) {
  const { raw, ...safe } = profile;
  return safe;
}

function publicBrief(brief, actor) {
  const canViewFull = actor?.signed && isSameAddress(actor.address, brief.actor?.address);
  return {
    ...brief,
    story: canViewFull ? brief.story : previewText(brief.story, 260),
    raw: canViewFull ? brief.raw : undefined,
    protected_private_details: canViewFull ? false : true
  };
}

function publicSample(sample) {
  return {
    ...sample,
    excerpt: previewText(sample.excerpt, 280),
    public_preview: previewText(sample.excerpt, 280),
    raw: undefined
  };
}

function publicProposal(db, proposal, actor) {
  const canViewFull = canViewProposal(db, proposal, actor);
  const { messages, raw, ...base } = proposal;
  return {
    ...base,
    participant_addrs: canViewFull ? [...proposalParticipantAddresses(db, proposal)] : undefined,
    message_count: messages.length,
    messages: canViewFull ? messages : "withheld_from_public_listing",
    raw: canViewFull ? raw : undefined
  };
}

function publicOrder(order, actor) {
  const canViewFull = actorCanViewOrderPrivate(order, actor);
  return {
    ...order,
    deliverable: canViewFull ? order.deliverable : previewText(order.deliverable, 220),
    raw: canViewFull ? order.raw : undefined,
    protected_private_details: canViewFull ? false : true
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

function publicDelivery(db, delivery, order, actor) {
  const quality_evidence = deliveryQualityEvidence(delivery);
  const canViewFull = order && actorCanViewOrderPrivate(order, actor) && verifiedEscrowForOrder(db, order);
  return {
    ...delivery,
    excerpt: canViewFull ? delivery.excerpt : previewText(delivery.excerpt, 280),
    draft: canViewFull ? delivery.draft : undefined,
    private_notes: canViewFull ? delivery.private_notes : undefined,
    quality_evidence,
    protected_full_draft: canViewFull ? false : true,
    raw: canViewFull ? delivery.raw : undefined
  };
}

function publicTrustState(db, order, actor) {
  const trust = orderTrustState(db, order);
  return {
    buyer_addr: trust.buyer_addr,
    writer_addr: trust.writer_addr,
    verified_escrow: trust.verified_escrow ? publicEscrow(db, trust.verified_escrow, actor) : null,
    latest_writer_delivery: trust.latest_writer_delivery ? publicDelivery(db, trust.latest_writer_delivery, order, actor) : null,
    delivery_quality_evidence: trust.delivery_quality_evidence,
    accepted_delivery: trust.accepted_delivery ? publicOrderArtifact(db, trust.accepted_delivery, actor) : null,
    reputation_eligible_acceptance: trust.reputation_eligible_acceptance ? publicOrderArtifact(db, trust.reputation_eligible_acceptance, actor) : null,
    released_escrow: trust.released_escrow ? publicOrderArtifact(db, trust.released_escrow, actor) : null,
    payment_state: trust.payment_state,
    rights_state: trust.rights_state,
    writer_reputation_state: trust.writer_reputation_state
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
      intents: db.intents,
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
    if (statusFilter) orders = orders.filter((order) => order.status === statusFilter || orderTrustState(db, order).payment_state === statusFilter);
    if (fundedOnly) orders = orders.filter((order) => Boolean(verifiedEscrowForOrder(db, order)));
    writeDb(db);
    return send(res, 200, {
      orders: orders.map((order) => publicOrder(order, actor)),
      filters: {
        status: statusFilter,
        payee_addr: payeeFilter,
        buyer_addr: buyerFilter,
        role: roleFilter,
        funded: fundedOnly
      },
      ui: ui("Orders", "Use ?role=writer&funded=true for a safe paid work queue, or ?role=buyer for your buyer dashboard.")
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
      order: publicOrder(order, actor),
      escrows: db.escrows.filter((item) => item.order_id === orderId).map((escrow) => publicEscrow(db, escrow, actor)),
      deliveries: db.deliveries
        .filter((item) => item.order_id === orderId)
        .map((delivery) => publicDelivery(db, delivery, order, actor)),
      revisions: db.revisions.filter((item) => item.order_id === orderId),
      disputes: db.disputes.filter((item) => item.order_id === orderId),
      acceptances: db.acceptances.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      refunds: db.refunds.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      releases: db.releases.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      reviews: db.reviews.filter((item) => item.order_id === orderId).map((item) => publicOrderArtifact(db, item, actor)),
      verified_escrow: verifiedEscrowForOrder(db, order) ? publicEscrow(db, verifiedEscrowForOrder(db, order), actor) : null,
      trust: publicTrustState(db, order, actor),
      ui: ui("Order status", "Review escrow, delivery, revision, dispute, and review state from one place.", [
        { method: "POST", path: "/acceptances", label: "Accept delivery" },
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
      briefs: db.briefs.map((brief) => publicBrief(brief, actor)),
      ui: ui("Memoir briefs", "Writers can answer a brief with POST /samples.")
    });
  }

  if (req.method === "POST" && url.pathname === "/briefs") {
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
      brief: item,
      next: [
        { method: "GET", path: "/samples", label: "Check samples" },
        { method: "POST", path: "/feedback", label: "Request missing buyer workflow" }
      ],
      ui: ui("Brief posted", "Writers can now submit a short sample against this brief.")
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
    const fullText = body.full_excerpt || body.excerpt || body.sample || "";
    const protectedMode = Boolean(body.protected_preview || body.full_excerpt || body.visibility === "protected");
    const item = {
      id: id("sample"),
      at: new Date().toISOString(),
      actor,
      brief_id: body.brief_id || null,
      excerpt: protectedMode ? previewText(body.protected_preview || fullText) : fullText,
      protected_preview: protectedMode,
      full_excerpt_stored: protectedMode ? "withheld_until_funded_order" : null,
      price: body.price || null,
      terms: body.terms || null,
      proof: body.proof || null,
      raw: body,
      status: "submitted"
    };
    db.samples.push(item);
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
    writeDb(db);
    return send(res, 201, {
      ok: true,
      sample: item,
      next: [
        { method: "POST", path: "/proposals", label: "Open proposal" },
        { method: "POST", path: "/orders", label: "Buyer commit" }
      ],
      ui: ui(
        "Sample submitted",
        protectedMode
          ? "Only the preview is public. Use /proposals for questions and terms before funding."
          : "A buyer can now commit to this writer; use protected_preview for reusable prose."
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
      offers: db.offers,
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
      payee_addr: body.payee_addr || null,
      escrow_id: body.escrow_id || null,
      escrow_proof: body.escrow_proof || null,
      deliverable: body.deliverable || body.outcome || "",
      raw: body,
      risk_flags,
      status: actor.signed ? status : "unsigned_draft"
    };
    db.orders.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      order: item,
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
    writeDb(db);
    return send(res, 201, {
      ok: true,
      escrow: item,
      order,
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
      rights_transfer: body.rights_transfer || "after_acceptance_and_payment",
      notes: body.notes || "",
      raw: body,
      status: deliveryStatus
    };
    item.quality_evidence = deliveryQualityEvidence(item);
    db.deliveries.push(item);
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
    return send(res, 200, { revisions: db.revisions, ui: ui("Revisions", "Use /orders/:id for order-specific status.") });
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
    return send(res, 200, { disputes: db.disputes, ui: ui("Disputes", "Open refund or quality concerns.") });
  }

  if (req.method === "POST" && url.pathname === "/acceptances") {
    const order = db.orders.find((candidate) => candidate.id === body.order_id);
    const delivery = verifiedWriterDeliveryForOrder(db, order, body.delivery_id);
    const verifiedEscrow = verifiedEscrowForOrder(db, order);
    const escrowId = verifiedEscrow && verifiedEscrow.escrow_id;
    const canAccept = order && delivery && escrowId && actorIsBuyer(order, actor);
    const qualityEvidence = delivery ? deliveryQualityEvidence(delivery) : null;
    const item = {
      id: id("accept"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      delivery_id: body.delivery_id || null,
      notes: body.notes || "",
      acceptance_rubric: body.acceptance_rubric || body.rubric || null,
      quality_evidence: qualityEvidence,
      release_command: canAccept ? `ag3nt escrow-release ${escrowId}` : null,
      raw: body,
      status: canAccept ? "ready_to_release" : "invalid_unverified_order_delivery_escrow_or_buyer"
    };
    db.acceptances.push(item);
    if (order && item.status === "ready_to_release") order.status = "accepted_pending_release";
    writeDb(db);
    return send(res, 201, {
      ok: true,
      acceptance: item,
      ui: ui("Acceptance recorded", item.release_command ? `Release funds with: ${item.release_command}` : "Attach order, delivery, and escrow before release.")
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
    const releaseVerified = Boolean(order && actorIsBuyer(order, actor) && verifiedEscrow && accepted && chainEscrow && chainStatus === "released");
    const item = {
      id: id("release"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      escrow_id: escrowId || null,
      proof: body.proof || null,
      chain_escrow: chainEscrow,
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

  if (req.method === "GET" && url.pathname === "/ad-attributions") {
    writeDb(db);
    return send(res, 200, {
      ad_attributions: db.ad_attributions,
      ui: ui("Ad attributions", "Only verified funded orders are ready for advertiser-signed ag3ntads conversion attestation.")
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
      ...publicActivity(db),
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
