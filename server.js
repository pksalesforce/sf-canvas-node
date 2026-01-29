const express = require("express");
const crypto = require("crypto");

const app = express();

// Canvas usually posts application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: "1mb" }));

// Allow Salesforce to iframe this app (Canvas runs in an iframe)
app.use((req, res, next) => {
  const ancestors = [
    "https://*.salesforce.com",
    "https://*.my.salesforce.com",
    "https://*.sandbox.my.salesforce.com",
    "https://*.force.com",
    "https://*.lightning.force.com",
    "https://*.visual.force.com"
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

app.get("/health", (_, res) => res.send("ok"));

app.get("/canvas", (req, res) => {
  // Sometimes Salesforce may hit GET during auth/approval flows; show what we got.
  res.type("html").send(`<pre>${JSON.stringify(req.query, null, 2)}</pre>`);
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

  // return pretty HTML in Canvas iframe
  res.type("html").send(`<pre>${escapeHtml(JSON.stringify(output, null, 2))}</pre>`);
});

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
