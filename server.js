const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 4501);
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "db.json");

const initialDb = {
  created_at: new Date().toISOString(),
  requests: [],
  feedback: [],
  intents: [],
  offers: [],
  briefs: [],
  samples: [],
  profiles: [],
  escrows: [],
  matches: [],
  orders: [],
  deliveries: [],
  revisions: [],
  disputes: [],
  reviews: [],
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
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1_000_000) req.destroy();
    });
    req.on("end", () => {
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        resolve({ _raw: raw });
      }
    });
  });
}

function actorFrom(req, body = {}) {
  const headers = req.headers;
  const address =
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
    signed: Boolean(
      address ||
      pubkey ||
      headers["x-agent-sig"] ||
      headers["x-signature"] ||
      headers["x-ag3nt-signature"] ||
      headers["authorization"]
    )
  };
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
      { method: "POST", path: "/profiles", summary: "Buyer/writer profile. Body {role,wallet,portfolio,credentials,confidentiality_terms,reputation_refs}." },
      { method: "GET", path: "/profiles", summary: "Browse signed buyer/writer profiles." },
      { method: "POST", path: "/intents", summary: "Declare what you want. Body {want,budget,deadline,constraints}. Sign it when serious." },
      { method: "GET", path: "/intents", summary: "Browse customer demand." },
      { method: "POST", path: "/offers", summary: "Declare what you can provide. Body {can_do,price,proof,terms}. Sign it when serious." },
      { method: "GET", path: "/offers", summary: "Browse available supply." },
      { method: "POST", path: "/matches", summary: "Propose a match. Body {intent_id,offer_id,note}." },
      { method: "POST", path: "/orders", summary: "Commit to a workflow. Body {brief_id,sample_id,intent_id,offer_id,amount,payee_addr,deliverable,escrow_id}. Positive signed orders without escrow are marked awaiting_escrow." },
      { method: "POST", path: "/escrows", summary: "Attach payment proof/status. Body {order_id,escrow_id,payer_addr,payee_addr,amount,status,proof}." },
      { method: "POST", path: "/deliveries", summary: "Writer delivery. Body {order_id,content_hash,excerpt,rights_transfer,notes}." },
      { method: "POST", path: "/revisions", summary: "Buyer revision request. Body {order_id,request,acceptance_blocker}." },
      { method: "POST", path: "/disputes", summary: "Open dispute/refund concern. Body {order_id,reason,requested_resolution}." },
      { method: "POST", path: "/reviews", summary: "Review a delivered sample/order. Body {order_id,rating,message,would_pay_again}." },
      { method: "GET", path: "/activity", summary: "Recent signed usage, feedback, orders, and product learning signals." },
      { method: "POST", path: "/feedback", summary: "Report praise, complaint, bug, or feature request. Body {sentiment,type,endpoint_context,message}." }
    ],
    ui: ui("Ghostwriter Hub", "Post a memoir brief, answer one with a sample, or leave feedback when the workflow misses your need.", [
      { method: "POST", path: "/briefs", label: "Post brief" },
      { method: "POST", path: "/samples", label: "Submit sample" },
      { method: "POST", path: "/profiles", label: "Create profile" },
      { method: "POST", path: "/intents", label: "Post intent" },
      { method: "POST", path: "/feedback", label: "Send feedback" }
    ])
  };
}

function publicActivity(db) {
  return {
    counts: {
      requests: db.requests.length,
      feedback: db.feedback.length,
      intents: db.intents.length,
      offers: db.offers.length,
      briefs: db.briefs.length,
      samples: db.samples.length,
      profiles: db.profiles.length,
      escrows: db.escrows.length,
      matches: db.matches.length,
      orders: db.orders.length,
      deliveries: db.deliveries.length,
      revisions: db.revisions.length,
      disputes: db.disputes.length,
      reviews: db.reviews.length,
      signed_orders: db.orders.filter((o) => o.actor.signed).length,
      funded_orders: db.orders.filter((o) => o.status === "funded").length
    },
    recent_feedback: db.feedback.slice(-10).reverse(),
    recent_briefs: db.briefs.slice(-10).reverse(),
    recent_samples: db.samples.slice(-10).reverse(),
    recent_profiles: db.profiles.slice(-10).reverse(),
    recent_escrows: db.escrows.slice(-10).reverse(),
    recent_intents: db.intents.slice(-10).reverse(),
    recent_offers: db.offers.slice(-10).reverse(),
    recent_orders: db.orders.slice(-10).reverse(),
    recent_deliveries: db.deliveries.slice(-10).reverse(),
    recent_revisions: db.revisions.slice(-10).reverse(),
    recent_disputes: db.disputes.slice(-10).reverse(),
    recent_reviews: db.reviews.slice(-10).reverse(),
    recent_requests: db.requests.slice(-20).reverse()
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
  const body = req.method === "POST" ? await readBody(req) : {};
  const db = readDb();
  const actor = actorFrom(req, body);
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
      activity: publicActivity(db),
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

  if (req.method === "GET" && url.pathname === "/profiles") {
    writeDb(db);
    return send(res, 200, {
      profiles: db.profiles,
      ui: ui("Profiles", "Signed profiles make counterparty review less blind.")
    });
  }

  if (req.method === "POST" && url.pathname === "/profiles") {
    const item = {
      id: id("profile"),
      at: new Date().toISOString(),
      actor,
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
      briefs: db.briefs,
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
      samples: db.samples,
      ui: ui("Writer samples", "Buyers can commit with POST /orders.")
    });
  }

  if (req.method === "POST" && url.pathname === "/samples") {
    const item = {
      id: id("sample"),
      at: new Date().toISOString(),
      actor,
      brief_id: body.brief_id || null,
      excerpt: body.excerpt || body.sample || "",
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
      next: [{ method: "POST", path: "/orders", label: "Buyer commit" }],
      ui: ui("Sample submitted", "A buyer can now commit to this writer.")
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
          ? "funded"
          : "awaiting_escrow";
    const item = {
      id: id("order"),
      at: new Date().toISOString(),
      actor,
      intent_id: body.intent_id || null,
      offer_id: body.offer_id || null,
      brief_id: body.brief_id || null,
      sample_id: body.sample_id || null,
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
    if (actor.signed && actor.address && item.status === "funded") {
      db.conversions.push({
        id: id("conv"),
        at: item.at,
        actor_addr: actor.address,
        source: "signed_order",
        order_id: item.id
      });
    }
    writeDb(db);
    return send(res, 201, {
      ok: true,
      order: item,
      conversion_candidate: Boolean(actor.signed && actor.address && item.status === "funded"),
      ui: ui(
        item.status === "funded" ? "Funded order recorded" : "Order needs trust proof",
        item.status === "funded"
          ? "This is strong PMF signal."
          : "Attach escrow/payment proof with /escrows before this counts as a funded conversion."
      )
    });
  }

  if (req.method === "POST" && url.pathname === "/escrows") {
    const item = {
      id: id("escrow"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      escrow_id: body.escrow_id || body.chain_escrow_id || null,
      payer_addr: body.payer_addr || actor.address || null,
      payee_addr: body.payee_addr || null,
      amount: body.amount || null,
      status: body.status || "claimed_funded",
      proof: body.proof || null,
      raw: body
    };
    db.escrows.push(item);
    const order = db.orders.find((candidate) => candidate.id === item.order_id);
    if (order && actor.signed && item.escrow_id && item.payee_addr && Number(item.amount) > 0) {
      order.status = "funded";
      order.escrow_id = item.escrow_id;
      order.payee_addr = item.payee_addr;
      order.risk_flags = (order.risk_flags || []).filter((flag) => flag !== "no_escrow_proof" && flag !== "missing_payee_wallet_address");
      if (order.actor.address && !db.conversions.find((conv) => conv.order_id === order.id)) {
        db.conversions.push({
          id: id("conv"),
          at: new Date().toISOString(),
          actor_addr: order.actor.address,
          source: "funded_order",
          order_id: order.id
        });
      }
    }
    writeDb(db);
    return send(res, 201, {
      ok: true,
      escrow: item,
      order,
      ui: ui("Escrow status recorded", "Funded orders can proceed to delivery.")
    });
  }

  if (req.method === "POST" && url.pathname === "/deliveries") {
    const item = {
      id: id("delivery"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      content_hash: body.content_hash || null,
      excerpt: body.excerpt || null,
      rights_transfer: body.rights_transfer || "after_acceptance_and_payment",
      notes: body.notes || "",
      raw: body,
      status: "submitted"
    };
    db.deliveries.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      delivery: item,
      next: [
        { method: "POST", path: "/reviews", label: "Accept/review" },
        { method: "POST", path: "/revisions", label: "Request revision" },
        { method: "POST", path: "/disputes", label: "Open dispute" }
      ],
      ui: ui("Delivery submitted", "Buyer can review, request revision, or dispute.")
    });
  }

  if (req.method === "POST" && url.pathname === "/revisions") {
    const item = {
      id: id("revision"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      request: body.request || "",
      acceptance_blocker: body.acceptance_blocker || null,
      raw: body,
      status: "requested"
    };
    db.revisions.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      revision: item,
      ui: ui("Revision requested", "The request is now attached to the order.")
    });
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

  if (req.method === "POST" && url.pathname === "/reviews") {
    const item = {
      id: id("review"),
      at: new Date().toISOString(),
      actor,
      order_id: body.order_id || null,
      rating: body.rating || null,
      message: body.message || "",
      would_pay_again: body.would_pay_again ?? null,
      raw: body
    };
    db.reviews.push(item);
    writeDb(db);
    return send(res, 201, {
      ok: true,
      review: item,
      ui: ui("Review recorded", "Repeated buyer reviews will drive trust and ranking features.")
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
