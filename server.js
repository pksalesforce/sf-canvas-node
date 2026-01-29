// server.js
const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

// Canvas usually posts application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "1mb" }));

// Serve static assets (your logo)
app.use("/public", express.static(path.join(__dirname, "public")));

// Allow Salesforce to iframe this app (Canvas runs in an iframe)
app.use((req, res, next) => {
  const ancestors = [
    "https://*.salesforce.com",
    "https://*.my.salesforce.com",
    "https://*.sandbox.my.salesforce.com",
    "https://*.force.com",
    "https://*.lightning.force.com",
    "https://*.visual.force.com",
    "https://*.salesforce-setup.com",
    "https://*.my.salesforce-setup.com",
  ].join(" ");

  res.setHeader("Content-Security-Policy", `frame-ancestors ${ancestors}`);
  next();
});

function b64ToBuf(s) {
  // supports base64url and base64
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? b64 : b64 + "=".repeat(4 - (b64.length % 4));
  return Buffer.from(pad, "base64");
}

function verifyAndDecodeSignedRequest(signedRequest, consumerSecret) {
  if (!consumerSecret) throw new Error("Missing CANVAS_CONSUMER_SECRET env var.");
  if (!signedRequest || !signedRequest.includes(".")) throw new Error("Invalid signed_request format.");

  const [sigPart, payloadPart] = signedRequest.split(".", 2);

  const actualSig = b64ToBuf(sigPart);
  const expectedSig = crypto.createHmac("sha256", consumerSecret).update(payloadPart).digest();

  // constant-time compare
  if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) {
    throw new Error("Signature verification failed.");
  }

  const payloadJson = b64ToBuf(payloadPart).toString("utf8");
  return JSON.parse(payloadJson);
}

function redactTokens(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(redactTokens);
  if (typeof obj !== "object") return obj;

  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k.toLowerCase().includes("token")) out[k] = "***REDACTED***";
    else out[k] = redactTokens(v);
  }
  return out;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function pickSummary(decoded) {
  const user = decoded?.context?.user || {};
  const client = decoded?.client || {};

  const recordId =
    decoded?.context?.environment?.parameters?.recordId ||
    decoded?.context?.environment?.record?.Id ||
    decoded?.context?.recordId ||
    decoded?.context?.record?.Id ||
    null;

  const orgId =
    decoded?.context?.organization?.organizationId ||
    decoded?.context?.organization?.id ||
    decoded?.context?.org?.id ||
    decoded?.context?.orgId ||
    null;

  return {
    userId: decoded?.userId || user?.userId,
    username: user?.userName,
    fullName: user?.fullName,
    email: user?.email,
    orgId,
    recordId,
    instanceUrl: client?.instanceUrl,
    targetOrigin: client?.targetOrigin,
    instanceId: client?.instanceId,
  };
}

function renderStyledPage({ title, summary, jsonObj }) {
  const jsonPretty = JSON.stringify(jsonObj, null, 2);

  const rows = [
    ["User", summary.fullName || summary.username || summary.userId || "-"],
    ["User Id", summary.userId || "-"],
    ["Record Id", summary.recordId || "(not provided on this surface)"],
    ["Org Id", summary.orgId || "-"],
    ["Instance", summary.instanceUrl || "-"],
    ["Target Origin", summary.targetOrigin || "-"],
  ];

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root{
      --bg:#0b1020;
      --panel:rgba(255,255,255,0.06);
      --panel2:rgba(255,255,255,0.09);
      --text:#e6edf3;
      --muted:rgba(230,237,243,0.70);
      --border:rgba(255,255,255,0.12);
      --accent:#7dd3fc;
      --ok:#86efac;
    }
    body{
      margin:0;
      background:
        radial-gradient(1200px 600px at 20% 0%, rgba(125,211,252,0.18), transparent 60%),
        radial-gradient(900px 600px at 90% 20%, rgba(134,239,172,0.12), transparent 55%),
        var(--bg);
      color:var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    }
    .wrap{max-width:1100px;margin:0 auto;padding:22px 18px 40px;}
    .header{
      display:flex;align-items:center;gap:12px;
      padding:14px 14px;
      background:linear-gradient(180deg,var(--panel2),var(--panel));
      border:1px solid var(--border);
      border-radius:14px;
      backdrop-filter: blur(6px);
    }
    .logo{
      width:44px;height:44px;border-radius:12px;
      display:flex;align-items:center;justify-content:center;
      background:rgba(125,211,252,0.10);
      border:1px solid rgba(125,211,252,0.22);
      overflow:hidden;
      flex:0 0 auto;
    }
    .logo img{width:100%;height:100%;object-fit:cover;}
    .title{font-size:18px;font-weight:700;margin:0;}
    .subtitle{margin:3px 0 0;color:var(--muted);font-size:13px;}
    .grid{display:grid;grid-template-columns:1fr;gap:14px;margin-top:14px;}
    @media(min-width:900px){.grid{grid-template-columns:420px 1fr;}}
    .card{
      background:var(--panel);
      border:1px solid var(--border);
      border-radius:14px;
      padding:14px;
    }
    .card h3{margin:0 0 10px;font-size:14px;color:var(--muted);font-weight:600;letter-spacing:0.2px;}
    .kv{display:grid;grid-template-columns:120px 1fr;gap:8px 10px;}
    .k{color:var(--muted);font-size:12.5px;}
    .v{font-size:12.5px;overflow-wrap:anywhere;}
    .pill{
      display:inline-flex;align-items:center;gap:8px;
      padding:6px 10px;border-radius:999px;
      background:rgba(134,239,172,0.10);
      border:1px solid rgba(134,239,172,0.22);
      color:var(--ok);
      font-size:12px;
      margin-top:10px;
    }
    .actions{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap;}
    button{
      cursor:pointer;
      border-radius:10px;
      border:1px solid var(--border);
      padding:8px 10px;
      background:rgba(255,255,255,0.06);
      color:var(--text);
      font-size:12.5px;
    }
    button:hover{background:rgba(255,255,255,0.10);}
    pre{
      margin:0;
      padding:14px;
      border-radius:12px;
      background:rgba(0,0,0,0.35);
      border:1px solid rgba(255,255,255,0.10);
      overflow:auto;
      max-height:680px;
      font-size:12.5px;
      line-height:1.4;
      white-space:pre;
    }
    .foot{color:var(--muted);font-size:12px;margin-top:10px;}
    code{color:rgba(230,237,243,0.9);}
    a{color:var(--accent);text-decoration:none;}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="logo">
        <img src="/public/acralogo.png" alt="Logo" />
      </div>
      <div>
        <p class="title">${escapeHtml(title)}</p>
        <p class="subtitle">Signed request verified (HMAC-SHA256). Tokens are redacted. Use this to inspect Canvas context on record pages.</p>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Summary</h3>
        <div class="kv">
          ${rows
            .map(
              ([k, v]) => `
            <div class="k">${escapeHtml(k)}</div>
            <div class="v">${escapeHtml(v)}</div>
          `
            )
            .join("")}
        </div>

        <div class="pill">✔ Verified signed_request</div>

        <div class="actions">
          <button id="copyBtn" type="button">Copy JSON</button>
          <button id="toggleBtn" type="button">Collapse / Expand JSON</button>
        </div>

        <div class="foot">
          Tip: If Record Id is missing, ensure you embedded on a record page or pass it via Visualforce parameters.
        </div>
      </div>

      <div class="card">
        <h3>Canvas Signed Request JSON</h3>
        <pre id="json">${escapeHtml(jsonPretty)}</pre>
      </div>
    </div>
  </div>

  <script>
    const pre = document.getElementById("json");
    const raw = pre.textContent;

    document.getElementById("copyBtn").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(raw);
        alert("JSON copied to clipboard");
      } catch (e) {
        alert("Copy failed (browser blocked clipboard).");
      }
    });

    document.getElementById("toggleBtn").addEventListener("click", () => {
      pre.style.maxHeight = pre.style.maxHeight === "80px" ? "680px" : "80px";
    });
  </script>
</body>
</html>`;
}

// Routes
app.get("/health", (_, res) => res.send("ok"));

app.get("/canvas", (req, res) => {
  // If SF hits GET (approval flows / debug), show query params in a minimal page
  res.type("html").send(
    renderStyledPage({
      title: "External Node.js Canvas Inspector (GET)",
      summary: {
        userId: "-",
        username: "-",
        fullName: "-",
        email: "-",
        orgId: "-",
        recordId: "-",
        instanceUrl: "-",
        targetOrigin: "-",
        instanceId: "-",
      },
      jsonObj: { message: "Canvas endpoint ready. Salesforce should POST signed_request here.", query: req.query },
    })
  );
});

app.post("/canvas", (req, res) => {
  const signedRequest = req.body.signed_request || req.body.signedRequest;
  if (!signedRequest) return res.status(400).send("Missing signed_request");

  let decoded;
  try {
    decoded = verifyAndDecodeSignedRequest(signedRequest, process.env.CANVAS_CONSUMER_SECRET);
  } catch (e) {
    return res.status(401).send(`Unauthorized: ${e.message}`);
  }

  const mask = (process.env.MASK_TOKENS || "true").toLowerCase() === "true";
  const output = mask ? redactTokens(decoded) : decoded;

  const wantsJson = (req.headers.accept || "").includes("application/json");
  if (wantsJson) return res.json(output);

  const summary = pickSummary(output);

  return res
    .status(200)
    .type("html")
    .send(
      renderStyledPage({
        title: "External Node.js Canvas Inspector",
        summary,
        jsonObj: output,
      })
    );
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
