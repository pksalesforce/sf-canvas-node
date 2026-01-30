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

  const userId = decoded?.userId || user?.userId || null;
  const instanceUrl = client?.instanceUrl || null;

  return {
    userId,
    username: user?.userName,
    fullName: user?.fullName,
    email: user?.email,
    orgId,
    recordId,
    instanceUrl,
    targetOrigin: client?.targetOrigin,
    instanceId: client?.instanceId,
  };
}

function getKeyPaths(summary, jsonObj) {
  // These are best-effort common Canvas paths; you can tweak based on what you see in your payload.
  return [
    {
      label: "User Id",
      path: "context.user.userId",
      value: summary.userId || "-",
    },
    {
      label: "Record Id",
      path: "context.environment.parameters.recordId (or record.Id)",
      value: summary.recordId || "-",
    },
    {
      label: "Org Id",
      path: "context.organization.organizationId",
      value: summary.orgId || "-",
    },
    {
      label: "Instance URL",
      path: "client.instanceUrl",
      value: summary.instanceUrl || "-",
    },
    {
      label: "Target Origin",
      path: "client.targetOrigin",
      value: summary.targetOrigin || "-",
    },
  ];
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

  const keyPaths = getKeyPaths(summary, jsonObj);

  const recordUrl = summary.instanceUrl && summary.recordId ? `${summary.instanceUrl}/${summary.recordId}` : "";
  const userUrl = summary.instanceUrl && summary.userId ? `${summary.instanceUrl}/${summary.userId}` : "";

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
      --warn:#fbbf24;
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
    button.primary{
      border-color: rgba(125,211,252,0.25);
      background: rgba(125,211,252,0.10);
    }
    button.primary:hover{
      background: rgba(125,211,252,0.16);
    }
    button.warn{
      border-color: rgba(251,191,36,0.22);
      background: rgba(251,191,36,0.08);
    }
    button.warn:hover{
      background: rgba(251,191,36,0.14);
    }
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

    .keypaths{
      margin-top: 12px;
      padding: 10px;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.10);
      background: rgba(0,0,0,0.22);
    }
    .kpRow{
      display:grid;
      grid-template-columns: 90px 1fr;
      gap: 6px 10px;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }
    .kpRow:last-child{ border-bottom:none; }
    .kpLabel{ color: var(--muted); font-size:12px; }
    .kpValue{ font-size:12px; overflow-wrap:anywhere; }
    .kpPath{ color: rgba(230,237,243,0.55); font-size:11.5px; margin-top:2px; }
    .search{
      display:flex; gap:10px; align-items:center; flex-wrap:wrap;
      margin: 0 0 10px;
    }
    .search input{
      width: min(520px, 100%);
      border-radius: 10px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(255,255,255,0.06);
      color: var(--text);
      padding: 9px 10px;
      font-size: 12.5px;
      outline: none;
    }
    .search small{ color: var(--muted); }
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

        <div class="keypaths">
          <div style="color: var(--muted); font-size: 12px; font-weight: 600; margin-bottom: 6px;">Key Paths</div>
          ${keyPaths
            .map(
              (kp) => `
              <div class="kpRow">
                <div class="kpLabel">${escapeHtml(kp.label)}</div>
                <div>
                  <div class="kpValue">${escapeHtml(kp.value)}</div>
                  <div class="kpPath">${escapeHtml(kp.path)}</div>
                </div>
              </div>
            `
            )
            .join("")}
        </div>

        <div class="actions">
          <button id="copyBtn" type="button">Copy JSON</button>
          <button id="toggleBtn" type="button">Collapse / Expand JSON</button>
          <button id="openRecordBtn" class="primary" type="button">Open Record</button>
          <button id="openUserBtn" class="primary" type="button">Open User</button>
        </div>

        <div class="foot">
          Tip: If Record Id is missing, ensure you embedded on a record page or pass it via Visualforce parameters.
        </div>
      </div>

      <div class="card">
        <h3>Canvas Signed Request JSON</h3>

        <div class="search">
          <input id="searchInput" type="text" placeholder="Search inside JSON (e.g. recordId, instanceUrl, profileId)..." />
          <button id="findNextBtn" class="warn" type="button">Find Next</button>
          <small id="searchStatus"></small>
        </div>

        <pre id="json">${escapeHtml(jsonPretty)}</pre>
      </div>
    </div>
  </div>

  <script>
    const pre = document.getElementById("json");
    const raw = pre.textContent;

    // Links
    const recordUrl = ${JSON.stringify(recordUrl)};
    const userUrl = ${JSON.stringify(userUrl)};

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

    document.getElementById("openRecordBtn").addEventListener("click", () => {
      if (!recordUrl) return alert("Record URL not available.");
      window.open(recordUrl, "_blank");
    });

    document.getElementById("openUserBtn").addEventListener("click", () => {
      if (!userUrl) return alert("User URL not available.");
      window.open(userUrl, "_blank");
    });

    // JSON search / find-next
    const input = document.getElementById("searchInput");
    const status = document.getElementById("searchStatus");
    const findNextBtn = document.getElementById("findNextBtn");

    let lastQuery = "";
    let lastIndex = -1;

    function findNext() {
      const q = (input.value || "").trim();
      if (!q) {
        status.textContent = "";
        return;
      }

      const hay = raw.toLowerCase();
      const needle = q.toLowerCase();

      // Reset if query changed
      if (needle !== lastQuery) {
        lastQuery = needle;
        lastIndex = -1;
      }

      const start = lastIndex < 0 ? 0 : lastIndex + 1;
      let idx = hay.indexOf(needle, start);

      // Wrap around
      if (idx === -1 && start > 0) idx = hay.indexOf(needle, 0);

      if (idx === -1) {
        status.textContent = "No matches";
        return;
      }

      lastIndex = idx;
      status.textContent = "Match at index " + idx;

      // Scroll roughly to the match (line-based approximation)
      const before = raw.slice(0, idx);
      const lineCount = before.split("\\n").length;
      const lineHeight = 18; // approx for 12.5px font
      pre.scrollTop = Math.max(0, (lineCount - 3) * lineHeight);
    }

    findNextBtn.addEventListener("click", findNext);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") findNext();
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
