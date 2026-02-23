// server/index.js (ESM)

import dns from "dns";
dns.setDefaultResultOrder("ipv4first");

import "dotenv/config";
import express from "express";
import cors from "cors";
import crypto from "crypto";
import multer from "multer";
import pdf from "pdf-parse";
import ExcelJS from "exceljs";
import { Pool } from "pg";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("etag", false);

// ===============================
// Config
// ===============================
const IS_PROD = process.env.NODE_ENV === "production";
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const SESSION_SECRET = String(process.env.SESSION_SECRET || "");
const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();

if (!ADMIN_PASSWORD) console.warn("[WARN] ADMIN_PASSWORD não configurado.");
if (!SESSION_SECRET) console.warn("[WARN] SESSION_SECRET não configurado.");
if (!DATABASE_URL) console.warn("[WARN] DATABASE_URL não configurado.");

// ===============================
// Sessão stateless via cookie assinado (sem Map)
// sid = base64url(JSON payload).hexHmac
// payload: { iat, exp }
// ===============================
function b64urlEncode(str) {
  return Buffer.from(str, "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function b64urlDecode(b64url) {
  const b64 = String(b64url).replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
  return Buffer.from(b64 + pad, "base64").toString("utf8");
}

function sign(value) {
  if (!SESSION_SECRET) return "";
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function makeSessionToken() {
  const now = Date.now();
  const payload = {
    iat: now,
    exp: now + 7 * 24 * 60 * 60 * 1000, // 7 dias
  };
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = sign(body);
  return `${body}.${sig}`;
}

function parseSessionToken(raw) {
  const s = String(raw || "");
  const [body, sig] = s.split(".");
  if (!body || !sig) return null;
  if (!SESSION_SECRET) return null;
  if (sign(body) !== sig) return null;

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(body));
  } catch {
    return null;
  }

  const exp = Number(payload?.exp || 0);
  if (!Number.isFinite(exp) || exp <= Date.now()) return null;

  return payload;
}

function setSessionCookie(res) {
  const token = makeSessionToken();
  const parts = [
    `sid=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${60 * 60 * 24 * 7}`,
  ];
  if (IS_PROD) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearSessionCookie(res) {
  const parts = ["sid=", "Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=0"];
  if (IS_PROD) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function parseCookies(req) {
  const header = String(req.headers.cookie || "");
  const out = {};
  header.split(";").forEach((part) => {
    const p = part.trim();
    if (!p) return;
    const idx = p.indexOf("=");
    if (idx < 0) return;
    const k = decodeURIComponent(p.slice(0, idx).trim());
    const v = decodeURIComponent(p.slice(idx + 1).trim());
    out[k] = v;
  });
  return out;
}

function isAuthed(req) {
  const cookies = parseCookies(req);
  return !!parseSessionToken(cookies.sid);
}

function requireAuth(req, res, next) {
  if (!isAuthed(req)) return res.status(401).json({ ok: false, error: "Não autenticado." });
  next();
}

// ===============================
// Middlewares base
// ===============================
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json({ limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ===============================
// Páginas (com login na inicial)
// ===============================
function loginPageHtml(message = "") {
  const msg = message
    ? `<div style="margin-top:10px;color:#ffcc66;font-size:13px;">${message}</div>`
    : "";

  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Login - Sistema de Notas</title>
  <style>
    :root{
      --bg:#0b1020; --panel:#121a33; --text:#e8ecff; --muted:#aab3d6;
      --shadow: 0 10px 25px rgba(0,0,0,.35); --line:#243055;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial, "Noto Sans";
      background: radial-gradient(1200px 600px at 20% 0%, #172350 0%, transparent 50%),
                  radial-gradient(900px 500px at 100% 20%, #1a2a66 0%, transparent 55%),
                  var(--bg);
      color:var(--text);
      min-height:100vh;
      display:flex;align-items:center;justify-content:center;padding:16px;
    }
    .card{
      width:min(440px, 100%);
      background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
      border:1px solid rgba(255,255,255,.08);
      border-radius:14px;
      box-shadow: var(--shadow);
      padding:16px;
    }
    h1{margin:0 0 6px 0;font-size:18px}
    .sub{color:var(--muted);font-size:13px;margin-bottom:14px}
    label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}
    input{
      width:100%; padding:10px 10px; border-radius:10px;
      border:1px solid rgba(255,255,255,.10); outline:none;
      background: rgba(10,16,36,.55); color: var(--text);
    }
    button{
      width:100%; margin-top:12px; padding:10px 12px;
      border-radius:10px; border:1px solid rgba(255,255,255,.14);
      background: rgba(110,168,254,.14); color:var(--text);
      cursor:pointer; font-weight:650;
    }
    .links{
      margin-top:12px; display:flex; gap:10px; justify-content:space-between;
      color:var(--muted); font-size:12px; flex-wrap:wrap;
    }
    a{color:#6ea8fe;text-decoration:none}
    a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="card">
    <h1>Entrar</h1>
    <div class="sub">Digite a senha de administrador para acessar o sistema.</div>

    <label for="pw">Senha</label>
    <input id="pw" type="password" autocomplete="current-password" placeholder="Sua senha" />
    <button id="btn" type="button">Entrar</button>
    ${msg}

    <div class="links">
      <span>Após logar, você poderá acessar:</span>
      <span>
        <a href="/financeiro">Financeiro</a> •
        <a href="/importar">Importar</a> •
        <a href="/upload">Upload unitário</a>
      </span>
    </div>
  </div>

<script>
  async function login() {
    const password = document.getElementById("pw").value;
    const btn = document.getElementById("btn");
    btn.disabled = true;
    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ password })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok) {
        alert(data.error || "Falha no login.");
        return;
      }
      location.href = "/financeiro";
    } finally {
      btn.disabled = false;
    }
  }
  document.getElementById("btn").addEventListener("click", login);
  document.getElementById("pw").addEventListener("keydown", (e) => {
    if (e.key === "Enter") login();
  });
</script>
</body>
</html>`;
}

app.get("/", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml());
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/financeiro", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml("Faça login para acessar o Financeiro."));
  return res.sendFile(path.join(__dirname, "public", "financeiro.html"));
});

app.get("/importar", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml("Faça login para acessar a Importação."));
  return res.sendFile(path.join(__dirname, "public", "importar.html"));
});

app.get("/upload", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml("Faça login para acessar o Upload unitário."));
  return res.sendFile(path.join(__dirname, "public", "upload.html"));
});

// ===============================
// Auth API
// ===============================
app.get("/api/me", (req, res) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");
  return res.status(200).json({ ok: true, authed: isAuthed(req) });
});

app.post("/api/login", (req, res) => {
  const password = String(req.body?.password || "");

  if (!ADMIN_PASSWORD) {
    return res.status(500).json({ ok: false, error: "ADMIN_PASSWORD não configurado no servidor." });
  }
  if (!SESSION_SECRET) {
    return res.status(500).json({ ok: false, error: "SESSION_SECRET não configurado no servidor." });
  }
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Senha inválida." });
  }

  setSessionCookie(res);
  return res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  clearSessionCookie(res);
  return res.json({ ok: true });
});

// ===============================
// SSE: Financeiro
// ===============================
const financeSseClients = new Set();

function sseBroadcast(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of financeSseClients) {
    try {
      res.write(data);
    } catch {}
  }
}

app.get("/api/financeiro/notas/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
  });

  res.write(`data: ${JSON.stringify({ type: "HELLO", ts: Date.now() })}\n\n`);
  financeSseClients.add(res);

  req.on("close", () => {
    financeSseClients.delete(res);
  });
});

// ===============================
// PostgreSQL (falha cedo se env estiver errada)
// ===============================
if (!DATABASE_URL) {
  console.error("[FATAL] DATABASE_URL não configurado no ambiente (Render).");
  process.exit(1);
}
if (/localhost|127\.0\.0\.1|::1/.test(DATABASE_URL)) {
  console.error("[FATAL] DATABASE_URL aponta para localhost. Isso não funciona no Render:", DATABASE_URL);
  process.exit(1);
}

let dbHost = "UNKNOWN";
try {
  dbHost = new URL(DATABASE_URL).host;
} catch {
  console.error("[FATAL] DATABASE_URL inválida (não é uma URL válida).");
  process.exit(1);
}
console.log("[boot] DATABASE_URL host:", dbHost);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ===============================
// Helpers de data/número
// ===============================
function parseBrDateToISO(br) {
  if (!br) return null;
  const s = String(br).trim();
  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) return null;
  const dd = m[1], mm = m[2], yyyy = m[3];
  return `${yyyy}-${mm}-${dd}`;
}

function toNumberBR(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  if (!s) return null;
  const norm = s.replace(/\./g, "").replace(",", ".");
  const n = Number(norm);
  return Number.isFinite(n) ? n : null;
}

// ===============================
// Utilidades de texto / extração
// ===============================
function normalize(text) {
  return (text || "")
    .replace(/\r/g, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function formatCep(raw) {
  if (!raw) return "";
  const digits = raw.replace(/\D/g, "");
  if (digits.length !== 8) return "";
  if (digits === "00000000") return "";
  return digits.slice(0, 5) + "-" + digits.slice(5);
}

function listCeps(text) {
  const s = text || "";
  const re1 = /(\d{2}\.?\d{3}-?\d{3})/g;
  const re2 = /(\d{8})/g;

  const found = [];
  let m;

  while ((m = re1.exec(s)) !== null) {
    const formatted = formatCep(m[1]);
    if (formatted) found.push(formatted);
  }
  while ((m = re2.exec(s)) !== null) {
    const formatted = formatCep(m[1]);
    if (formatted) found.push(formatted);
  }

  return [...new Set(found)];
}

function nthCep(text, n = 2) {
  const ceps = listCeps(text);
  return ceps[n - 1] || "";
}

function moneyToNumber(v) {
  if (v === null || v === undefined) return NaN;
  const s = String(v).trim();
  if (!s) return NaN;

  const clean = s.replace(/[^\d.,-]/g, "");

  if (clean.includes(",")) {
    const norm = clean.replace(/\./g, "").replace(",", ".");
    const n = Number(norm);
    return Number.isFinite(n) ? n : NaN;
  }
  const n = Number(clean);
  return Number.isFinite(n) ? n : NaN;
}

function numberToBr(n) {
  if (!Number.isFinite(n)) return "";
  return n.toFixed(2).replace(".", ",");
}

function brMoneyToString(s) {
  if (!s && s !== 0) return "";
  const str = String(s).trim();
  if (/^\d+\.\d{2}$/.test(str)) return str.replace(".", ",");
  return str;
}

function extractFormaEnvio(text) {
  const t = (text || "").toUpperCase();

  if (t.includes("TELE-ENTREGA")) return "TELE-ENTREGA";
  if (/\bRETIR(ADA|AR|A)\b/i.test(text)) return "RETIRADA";

  if (t.includes("SEDEX")) return "SEDEX";
  if (/\bPAC\b/i.test(text)) return "PAC";
  if (t.includes("LOGGI")) return "LOGGI";
  if (t.includes("TOTAL EXPRESS") || /\bTEX\b/i.test(text)) return "TOTAL EXPRESS";
  if (t.includes("JADLOG")) return "JADLOG";

  return "NENHUM";
}

function extractTotalProdutos(text, valorTotalNotaStr) {
  const t = text || "";
  const totalNota = moneyToNumber(valorTotalNotaStr);

  const beforeFatura = (t.split(/FATURA\/DUPLICATA/i)[0] || "").trim();
  const moneyAll = beforeFatura.match(/\b[0-9]{1,3}(?:\.[0-9]{3})*(?:[.,][0-9]{2})\b/g) || [];

  const nums = moneyAll
    .map((s) => ({ s, n: moneyToNumber(s) }))
    .filter((x) => Number.isFinite(x.n) && x.n > 0);

  if (!nums.length) return "";

  if (Number.isFinite(totalNota) && totalNota > 0) {
    const below = nums.filter((x) => x.n < totalNota - 0.005);
    if (below.length) {
      below.sort((a, b) => b.n - a.n);
      return below[0].s;
    }
  }

  nums.sort((a, b) => b.n - a.n);
  return nums[0].s;
}

function extractFields(rawText) {
  const text = normalize(rawText);
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);

  const firstMatch = (chunk, re) => {
    const m = (chunk || "").match(re);
    return m ? (m[1] ?? "").trim() : "";
  };

  const numeroNotaFiscal =
    firstMatch(text, /(?:NF-e[\s\S]{0,50}?N[ºo]?\s*)(\d{5,8})/i) ||
    firstMatch(text, /\bN[ºo]\.?\s*(\d{5,8})\b/i) ||
    firstMatch(text, /\b(\d{5,8})\b/);

  const dataEmissao =
    firstMatch(text, /PROTOCOLO DE AUTORIZAÇÃO DE USO[\s\S]{0,80}\b(\d{2}\/\d{2}\/\d{4})\b/i) ||
    firstMatch(text, /DATA DE EMISSÃO[\s\S]{0,40}\b(\d{2}\/\d{2}\/\d{4})\b/i) ||
    firstMatch(text, /\b(\d{2}\/\d{2}\/\d{4})\b/);

  let valorTotalNota =
    firstMatch(text, /VALOR TOTAL DA NOTA[\s\S]{0,80}\b([0-9]+[\,\.][0-9]{2})\b/i) ||
    firstMatch(text, /\bPIX\s*-\s*([0-9]+[\,\.][0-9]{2})\s*-/i) ||
    firstMatch(text, /\bCART[ÃA]O\s*-\s*([0-9]+[\,\.][0-9]{2})\s*-/i) ||
    "";

  let valorTotalProdutos = extractTotalProdutos(text, valorTotalNota);

  const formaPagamento = (
    firstMatch(text, /\b(PIX|BOLETO|DINHEIRO|CARTÃO|CARTAO|CRÉDITO|CREDITO|DÉBITO|DEBITO)\b/i) || ""
  ).toUpperCase();

  const formaEnvio = extractFormaEnvio(text);

  valorTotalNota = brMoneyToString(valorTotalNota);
  valorTotalProdutos = brMoneyToString(valorTotalProdutos);

  const totalN = moneyToNumber(valorTotalNota);
  const prodN = moneyToNumber(valorTotalProdutos);

  let valorEnvio = "";
  if (Number.isFinite(totalN) && Number.isFinite(prodN) && totalN >= prodN) {
    valorEnvio = numberToBr(totalN - prodN);
  }

  const pacote = "";

  let nomeCliente = "";
  let enderecoLocal = "";

  const cpfRe = /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/;
  const cpfLineIdx = lines.findIndex((l) => cpfRe.test(l));

  if (cpfLineIdx >= 0) {
    for (let i = cpfLineIdx + 1; i < Math.min(lines.length, cpfLineIdx + 12); i++) {
      const l = (lines[i] || "").trim();
      if (l && /[A-Za-zÀ-ÿ]/.test(l) && l.split(/\s+/).length >= 2) {
        nomeCliente = l;
        break;
      }
    }

    const cepLooseRe = /(\d{2}\.?\d{3}-?\d{3}|\d{8})/;
    let addrLine = "";

    for (let i = cpfLineIdx + 1; i < Math.min(lines.length, cpfLineIdx + 25); i++) {
      const l = (lines[i] || "").trim();
      if (!l) continue;
      if (cepLooseRe.test(l)) {
        addrLine = l;
        break;
      }
    }

    if (addrLine) {
      const mCep = addrLine.match(cepLooseRe);
      const rawCep = mCep ? mCep[0] : "";
      const beforeCep = rawCep ? addrLine.replace(rawCep, "") : addrLine;

      const afterNumber = beforeCep.replace(/^.*?\d+\s*/i, "").trim();
      const bairro = afterNumber
        .replace(/[^\p{L}\p{N}\s]/gu, " ")
        .replace(/\s{2,}/g, " ")
        .trim();

      if (bairro && bairro.length >= 3) enderecoLocal = bairro;
    }
  }

  const cep = nthCep(text, 4);

  return {
    nomeCliente,
    numeroNotaFiscal,
    formaEnvio,
    valorEnvio,
    pacote,
    formaPagamento,
    enderecoLocal,
    cep,
    dataEmissao,
    valorTotalNota,
    valorTotalProdutos,
    __debugCepsFound: listCeps(text),
    __debugTextPreview: text.slice(0, 2400),
  };
}

// ===============================
// Rotas API
// ===============================
const upload = multer({ storage: multer.memoryStorage() });
const uploadMany = multer({ storage: multer.memoryStorage() });

app.get("/health", (req, res) => res.json({ ok: true }));

// (opcional) proteger parse também:
// app.post("/api/parse", requireAuth, upload.single("file"), async (req, res) => {
app.post("/api/parse", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: "Envie um PDF em file." });

    const data = await pdf(req.file.buffer);
    const fields = extractFields(data.text || "");
    return res.json({ ok: true, fields });
  } catch (err) {
    return res.status(500).json({
      ok: false,
      error: "Falha ao processar o PDF.",
      details: String(err?.message || err),
    });
  }
});

app.post("/api/import-pdfs", requireAuth, uploadMany.array("files", 50), async (req, res) => {
  try {
    const vendedorDefault = String(req.body?.vendedor || "").trim();
    const modo = String(req.body?.modo || "upsert").toLowerCase(); // upsert|skip

    const files = req.files || [];
    if (!files.length) return res.status(400).json({ ok: false, error: "Envie PDFs no campo 'files'." });

    const results = [];
    let okCount = 0;
    let failCount = 0;
    let skipCount = 0;

    async function saveNotaFromFields(fields, vendedorFallback) {
      const dataEmissaoISO = parseBrDateToISO(fields.dataEmissao);
      const nf = String(fields.numeroNotaFiscal || "").trim() || null;

      if (modo === "skip" && nf) {
        const exists = await pool.query("SELECT 1 FROM notas WHERE numero_nota_fiscal = $1 LIMIT 1", [nf]);
        if (exists.rowCount) return { skipped: true, reason: "NF já existe (skip)." };
      }

      const sql = `
        INSERT INTO notas (
          vendedor, nome_cliente, numero_nota_fiscal, forma_envio, valor_envio,
          pacote, forma_pagamento, endereco_local, cep,
          data_emissao, valor_total_nota
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT ON CONSTRAINT notas_numero_nf_uniq
        DO UPDATE SET
          vendedor = EXCLUDED.vendedor,
          nome_cliente = EXCLUDED.nome_cliente,
          forma_envio = EXCLUDED.forma_envio,
          valor_envio = EXCLUDED.valor_envio,
          pacote = EXCLUDED.pacote,
          forma_pagamento = EXCLUDED.forma_pagamento,
          endereco_local = EXCLUDED.endereco_local,
          cep = EXCLUDED.cep,
          data_emissao = EXCLUDED.data_emissao,
          valor_total_nota = EXCLUDED.valor_total_nota
        RETURNING *;
      `;

      const params = [
        fields.vendedor || vendedorFallback || null,
        fields.nomeCliente || null,
        nf,
        fields.formaEnvio || null,
        toNumberBR(fields.valorEnvio),
        fields.pacote || null,
        fields.formaPagamento || null,
        fields.enderecoLocal || null,
        fields.cep || null,
        dataEmissaoISO,
        toNumberBR(fields.valorTotalNota),
      ];

      const { rows } = await pool.query(sql, params);
      return { skipped: false, nota: rows[0] };
    }

    for (const f of files) {
      const item = { fileName: f.originalname, size: f.size, ok: false };

      try {
        const data = await pdf(f.buffer);
        const fields = extractFields(data.text || "");

        const payload = {
          vendedor: vendedorDefault || "",
          nomeCliente: fields.nomeCliente,
          numeroNotaFiscal: fields.numeroNotaFiscal,
          formaEnvio: fields.formaEnvio,
          valorEnvio: fields.valorEnvio,
          pacote: fields.pacote,
          formaPagamento: fields.formaPagamento,
          enderecoLocal: fields.enderecoLocal,
          cep: fields.cep,
          dataEmissao: fields.dataEmissao,
          valorTotalNota: fields.valorTotalNota,
        };

        if (!payload.vendedor && !vendedorDefault) throw new Error("Vendedor ausente. Informe um vendedor no import.");

        const saved = await saveNotaFromFields(payload, vendedorDefault);

        if (saved.skipped) {
          item.ok = true;
          item.skipped = true;
          item.reason = saved.reason;
          skipCount++;
        } else {
          item.ok = true;
          item.skipped = false;
          item.nota = saved.nota;
          okCount++;
          sseBroadcast({ type: "NOTA_CRIADA", nota: saved.nota });
        }
      } catch (err) {
        item.ok = false;
        item.error = String(err?.message || err);
        failCount++;
      }

      results.push(item);
    }

    return res.json({ ok: true, total: results.length, saved: okCount, skipped: skipCount, failed: failCount, results });
  } catch (err) {
    console.error("POST /api/import-pdfs error:", err, err?.stack);
    return res.status(500).json({
      ok: false,
      error: "Falha ao importar PDFs.",
      details: String(err?.stack || err?.message || err),
    });
  }
});

// Salvar nota no DB (por enquanto não protegido)
app.post("/api/notas", async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.vendedor) return res.status(400).json({ ok: false, error: "Vendedor é obrigatório." });

    const dataEmissaoISO = parseBrDateToISO(b.dataEmissao);
    const nf = String(b.numeroNotaFiscal || "").trim() || null;

    const sql = `
      INSERT INTO notas (
        vendedor, nome_cliente, numero_nota_fiscal, forma_envio, valor_envio,
        pacote, forma_pagamento, endereco_local, cep,
        data_emissao, valor_total_nota
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      ON CONFLICT ON CONSTRAINT notas_numero_nf_uniq
      DO UPDATE SET
        vendedor = EXCLUDED.vendedor,
        nome_cliente = EXCLUDED.nome_cliente,
        forma_envio = EXCLUDED.forma_envio,
        valor_envio = EXCLUDED.valor_envio,
        pacote = EXCLUDED.pacote,
        forma_pagamento = EXCLUDED.forma_pagamento,
        endereco_local = EXCLUDED.endereco_local,
        cep = EXCLUDED.cep,
        data_emissao = EXCLUDED.data_emissao,
        valor_total_nota = EXCLUDED.valor_total_nota
      RETURNING *;
    `;

    const params = [
      b.vendedor,
      b.nomeCliente || null,
      nf,
      b.formaEnvio || null,
      toNumberBR(b.valorEnvio),
      b.pacote || null,
      b.formaPagamento || null,
      b.enderecoLocal || null,
      b.cep || null,
      dataEmissaoISO,
      toNumberBR(b.valorTotalNota),
    ];

    const { rows } = await pool.query(sql, params);
    const saved = rows[0];

    sseBroadcast({ type: "NOTA_CRIADA", nota: saved });
    return res.json({ ok: true, nota: saved, upsert: true });
  } catch (err) {
    console.error("POST /api/notas error:", err);
    console.error("stack:", err?.stack);
    return res.status(500).json({
      ok: false,
      error: "Falha ao salvar nota no banco.",
      details: String(err?.stack || err?.message || err),
    });
  }
});

app.delete("/api/notas/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "ID inválido." });

    const { rowCount } = await pool.query("DELETE FROM notas WHERE id = $1", [id]);
    if (!rowCount) return res.status(404).json({ ok: false, error: "Nota não encontrada." });

    sseBroadcast({ type: "NOTA_DELETADA", id });
    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/notas/:id error:", err, err?.stack);
    return res.status(500).json({ ok: false, error: "Falha ao deletar nota.", details: String(err?.stack || err?.message || err) });
  }
});

app.get("/api/notas", requireAuth, async (req, res) => {
  try {
    const { dataDe, dataAte, vendedor, formaEnvio, q, page = "1", pageSize = "50" } = req.query;

    const limit = Math.min(Math.max(parseInt(pageSize, 10) || 50, 1), 200);
    const offset = (Math.max(parseInt(page, 10) || 1, 1) - 1) * limit;

    const where = [];
    const params = [];
    let i = 1;

    if (dataDe) { where.push(`data_emissao >= $${i++}`); params.push(dataDe); }
    if (dataAte) { where.push(`data_emissao <= $${i++}`); params.push(dataAte); }
    if (vendedor) { where.push(`vendedor ILIKE $${i++}`); params.push(`%${vendedor}%`); }
    if (formaEnvio) { where.push(`forma_envio ILIKE $${i++}`); params.push(`%${formaEnvio}%`); }
    if (q) {
      where.push(`(
        nome_cliente ILIKE $${i} OR
        numero_nota_fiscal ILIKE $${i} OR
        cep ILIKE $${i} OR
        endereco_local ILIKE $${i}
      )`);
      params.push(`%${q}%`);
      i++;
    }

    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const countSql = `SELECT COUNT(*)::int AS total FROM notas ${whereSql};`;
    const listSql = `
      SELECT *
      FROM notas
      ${whereSql}
      ORDER BY data_emissao DESC NULLS LAST, created_at DESC
      LIMIT $${i++} OFFSET $${i++};
    `;

    const countResult = await pool.query(countSql, params);
    const listResult = await pool.query(listSql, [...params, limit, offset]);

    return res.json({
      ok: true,
      total: countResult.rows[0]?.total || 0,
      page: Math.max(parseInt(page, 10) || 1, 1),
      pageSize: limit,
      items: listResult.rows,
    });
  } catch (err) {
    console.error("GET /api/notas error:", err, err?.stack);
    return res.status(500).json({ ok: false, error: "Falha ao listar notas.", details: String(err?.stack || err?.message || err) });
  }
});

app.get("/api/relatorio.xlsx", requireAuth, async (req, res) => {
  try {
    // TODO: cole aqui a sua implementação completa do ExcelJS.
    // Deixe exatamente como estava antes, só mantendo o requireAuth.
    return res.status(501).json({ ok: false, error: "Endpoint /api/relatorio.xlsx ainda não foi colado completo." });
  } catch (err) {
    console.error("GET /api/relatorio.xlsx error:", err, err?.stack);
    return res.status(500).json({ ok: false, error: "Falha ao gerar relatório.", details: String(err?.stack || err?.message || err) });
  }
});

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server rodando na porta ${PORT}`);
});
