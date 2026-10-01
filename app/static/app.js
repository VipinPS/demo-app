/* ─── Utility helpers ─────────────────────────────────────────── */

function showResult(id, data, isError) {
  const el = document.getElementById(id);
  el.classList.add("visible");
  el.classList.toggle("ok",    !isError);
  el.classList.toggle("error",  isError);
  el.textContent = isError
    ? "ERROR: " + data
    : JSON.stringify(data, null, 2);
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
}

/* ─── Session state (mirrors server-side in-memory keys) ─────── */
let rsaState   = {};   // { ciphertext, signature }
let ecdsaState = {};   // { signature }
let aesState   = {};   // { ciphertext, nonce, aad }

/* ─── RSA ─────────────────────────────────────────────────────── */

async function rsaGenerate() {
  const r = await apiPost("/api/rsa/generate", {});
  showResult("rsa-result", r.ok ? r.result : r.error, !r.ok);
}

async function rsaEncrypt() {
  const plaintext = document.getElementById("rsa-plaintext").value;
  const r = await apiPost("/api/rsa/encrypt", { plaintext });
  if (r.ok) rsaState.ciphertext = r.result.ciphertext;
  showResult("rsa-result", r.ok ? r.result : r.error, !r.ok);
}

async function rsaDecrypt() {
  const ciphertext = rsaState.ciphertext;
  if (!ciphertext) { showResult("rsa-result", "Encrypt a message first.", true); return; }
  const r = await apiPost("/api/rsa/decrypt", { ciphertext });
  showResult("rsa-result", r.ok ? r.result : r.error, !r.ok);
}

async function rsaSign() {
  const message = document.getElementById("rsa-message").value;
  const r = await apiPost("/api/rsa/sign", { message });
  if (r.ok) rsaState.signature = r.result.signature;
  showResult("rsa-result", r.ok ? r.result : r.error, !r.ok);
}

async function rsaVerify() {
  const message   = document.getElementById("rsa-message").value;
  const signature = rsaState.signature;
  if (!signature) { showResult("rsa-result", "Sign a message first.", true); return; }
  const r = await apiPost("/api/rsa/verify", { message, signature });
  showResult("rsa-result", r.ok ? r.result : r.error, !r.ok);
}

/* ─── ECDSA ───────────────────────────────────────────────────── */

async function ecdsaGenerate() {
  const r = await apiPost("/api/ecdsa/generate", {});
  showResult("ecdsa-result", r.ok ? r.result : r.error, !r.ok);
}

async function ecdsaSign() {
  const message = document.getElementById("ecdsa-message").value;
  const r = await apiPost("/api/ecdsa/sign", { message });
  if (r.ok) ecdsaState.signature = r.result.signature;
  showResult("ecdsa-result", r.ok ? r.result : r.error, !r.ok);
}

async function ecdsaVerify() {
  const message   = document.getElementById("ecdsa-message").value;
  const signature = ecdsaState.signature;
  if (!signature) { showResult("ecdsa-result", "Sign a message first.", true); return; }
  const r = await apiPost("/api/ecdsa/verify", { message, signature });
  showResult("ecdsa-result", r.ok ? r.result : r.error, !r.ok);
}

/* ─── ECDH ────────────────────────────────────────────────────── */

async function ecdhExchange() {
  const r = await apiPost("/api/ecdh/exchange", {});
  showResult("ecdh-result", r.ok ? r.result : r.error, !r.ok);
}

/* ─── DH ──────────────────────────────────────────────────────── */

async function dhExchange() {
  const r = await apiPost("/api/dh/exchange", {});
  showResult("dh-result", r.ok ? r.result : r.error, !r.ok);
}

/* ─── AES ─────────────────────────────────────────────────────── */

async function aesEncrypt() {
  const plaintext = document.getElementById("aes-plaintext").value;
  const aad       = document.getElementById("aes-aad").value;
  const r = await apiPost("/api/aes/encrypt", { plaintext, aad });
  if (r.ok) { aesState.ciphertext = r.result.ciphertext; aesState.nonce = r.result.nonce; aesState.aad = aad; }
  showResult("aes-result", r.ok ? r.result : r.error, !r.ok);
}

async function aesDecrypt() {
  if (!aesState.ciphertext) { showResult("aes-result", "Encrypt a message first.", true); return; }
  const r = await apiPost("/api/aes/decrypt", {
    ciphertext: aesState.ciphertext,
    nonce:      aesState.nonce,
    aad:        aesState.aad || "",
  });
  showResult("aes-result", r.ok ? r.result : r.error, !r.ok);
}

/* ─── Hash ────────────────────────────────────────────────────── */

async function hashSHA256() {
  const text = document.getElementById("hash-text").value;
  const r = await apiPost("/api/hash/sha256", { text });
  showResult("hash-result", r.ok ? r.result : r.error, !r.ok);
}

async function hashSHA512() {
  const text = document.getElementById("hash-text").value;
  const r = await apiPost("/api/hash/sha512", { text });
  showResult("hash-result", r.ok ? r.result : r.error, !r.ok);
}

/* ─── TLS ─────────────────────────────────────────────────────── */

async function tlsRequest() {
  const url = document.getElementById("tls-url").value;
  const r = await apiPost("/api/tls/request", { url });
  showResult("tls-result", r.ok ? r.result : r.error, !r.ok);
}
