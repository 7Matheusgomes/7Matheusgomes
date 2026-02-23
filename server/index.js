// server/index.js (backend completo - ESM)
//
// Requisitos:
//   npm i express cors multer pdf-parse exceljs pg dotenv cookie-parser
//
// Variáveis de ambiente:
//   DATABASE_URL      -> string do Supabase Postgres
//   ADMIN_PASSWORD    -> senha do login
//   SESSION_SECRET    -> segredo p/ assinar sessão (32+ chars)
//   NODE_ENV          -> "production" no Render
//
// Endpoints:
//   POST /api/login          (JSON { password }) -> cria sessão
//   POST /api/logout         -> encerra sessão
//   GET  /api/me             -> status auth
//   POST /api/parse          -> extrai campos do PDF
//   POST /api/notas          -> salva nota no PostgreSQL
//   DELETE /api/notas/:id    -> deleta nota (PROTEGIDO - sessão)
//   POST /api/import-pdfs    -> importação em massa (PROTEGIDO - sessão)
//   GET  /api/notas          -> lista notas (financeiro)
//   GET  /api/relatorio.xlsx -> gera excel do banco
//   GET  /api/financeiro/notas/stream (SSE)
//   GET  /health
//   GET  / (home -> login se não autenticado)
//   GET  /financeiro         (PROTEGIDO - sessão)
//   GET  /importar           (PROTEGIDO - sessão)

import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
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

// ===============================
// Config
// ===============================
const IS_PROD = process.env.NODE_ENV === "production";
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const SESSION_SECRET = String(process.env.SESSION_SECRET || "");

if (!ADMIN_PASSWORD) {
  console.warn("[WARN] ADMIN_PASSWORD não configurado. Configure no ambiente (Render).");
}
if (!SESSION_SECRET) {
  console.warn("[WARN] SESSION_SECRET não configurado. Configure no ambiente (Render).");
}

// ===============================
// Sessão simples em memória (cookie httpOnly)
// ===============================
// Obs: em produção, ideal é Redis/DB. Para seu caso, isso resolve.
// Reiniciar o serviço derruba sessões ativas.
const sessions = new Map(); // sid -> { createdAt }

function sign(value) {
  // HMAC do valor para dificultar forja do cookie
  if (!SESSION_SECRET) return "";
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function newSid() {
  return crypto.randomBytes(24).toString("hex");
}

function setSessionCookie(res, sid) {
  const sig = sign(sid);
  const packed = `${sid}.${sig}`;

  res.cookie("sid", packed, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD, // no Render deve ser true
    path: "/",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 dias
  });
}

function clearSessionCookie(res) {
  res.clearCookie("sid", { path: "/" });
}

function readSid(req) {
  const raw = String(req.cookies?.sid || "");
  const [sid, sig] = raw.split(".");
  if (!sid || !sig) return "";
  if (!SESSION_SECRET) return "";
  if (sign(sid) !== sig) return "";
  return sid;
}

function isAuthed(req) {
  const sid = readSid(req);
  if (!sid) return false;
  return sessions.has(sid);
}

function requireAuth(req, res, next) {
  if (!isAuthed(req)) {
    return res.status(401).json({ ok: false, error: "Não autenticado." });
  }
  next();
}

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

// ===============================
// Middlewares base
// ===============================
app.use(
  cors({
    origin: true, // mantém compatível com seu uso atual
    credentials: true,
  })
);
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
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
      --bg:#0b1020;
      --panel:#121a33;
      --text:#e8ecff;
      --muted:#aab3d6;
      --shadow: 0 10px 25px rgba(0,0,0,.35);
      --line:#243055;
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
      display:flex;
      align-items:center;
      justify-content:center;
      padding:16px;
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
      width:100%;
      padding:10px 10px;
      border-radius:10px;
      border:1px solid rgba(255,255,255,.10);
      outline:none;
      background: rgba(10,16,36,.55);
      color: var(--text);
    }
    button{
      width:100%;
      margin-top:12px;
      padding:10px 12px;
      border-radius:10px;
      border:1px solid rgba(255,255,255,.14);
      background: rgba(110,168,254,.14);
      color:var(--text);
      cursor:pointer;
      font-weight:650;
    }
    .links{
      margin-top:12px;
      display:flex;
      gap:10px;
      justify-content:space-between;
      color:var(--muted);
      font-size:12px;
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
      <span><a href="/financeiro">Financeiro</a> • <a href="/importar">Importar</a></span>
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
      // vai para o financeiro por padrão
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

// Home
app.get("/", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml());
  return res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Páginas protegidas
app.get("/financeiro", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml("Faça login para acessar o Financeiro."));
  return res.sendFile(path.join(__dirname, "public", "financeiro.html"));
});

app.get("/importar", (req, res) => {
  if (!isAuthed(req)) return res.status(200).send(loginPageHtml("Faça login para acessar a Importação."));
  return res.sendFile(path.join(__dirname, "public", "importar.html"));
});

// ===============================
// Auth API
// ===============================
app.get("/api/me", (req, res) => {
  return res.json({ ok: true, authed: isAuthed(req) });
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

  const sid = newSid();
  sessions.set(sid, { createdAt: Date.now() });
  setSessionCookie(res, sid);

  return res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const sid = readSid(req);
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

// ===============================
// SSE stream (pode proteger ou deixar aberto)
// ===============================
app.get("/api/financeiro/notas/stream", (req, res) => {
  // Se quiser proteger SSE também, descomente:
  // if (!isAuthed(req)) return res.status(401).end();

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
// PostgreSQL
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

function parseBrDateToISO(br) {
  if (!br) return null;
  const s = String(br).trim();
  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) return null;
  const dd = m[1],
    mm = m[2],
    yyyy = m[3];
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

  const moneyAll =
    beforeFatura.match(/\b[0-9]{1,3}(?:\.[0-9]{3})*(?:[.,][0-9]{2})\b/g) || [];

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
    firstMatch(
      text,
      /PROTOCOLO DE AUTORIZAÇÃO DE USO[\s\S]{0,80}\b(\d{2}\/\d{2}\/\d{4})\b/i
    ) ||
    firstMatch(text, /DATA DE EMISSÃO[\s\S]{0,40}\b(\d{2}\/\d{2}\/\d{4})\b/i) ||
    firstMatch(text, /\b(\d{2}\/\d{2}\/\d{4})\b/);

  let valorTotalNota =
    firstMatch(text, /VALOR TOTAL DA NOTA[\s\S]{0,80}\b([0-9]+[\,\.][0-9]{2})\b/i) ||
    firstMatch(text, /\bPIX\s*-\s*([0-9]+[\,\.][0-9]{2})\s*-/i) ||
    firstMatch(text, /\bCART[ÃA]O\s*-\s*([0-9]+[\,\.][0-9]{2})\s*-/i) ||
    "";

  let valorTotalProdutos = extractTotalProdutos(text, valorTotalNota);

  const formaPagamento = (
    firstMatch(text, /\b(PIX|BOLETO|DINHEIRO|CARTÃO|CARTAO|CRÉDITO|CREDITO|DÉBITO|DEBITO)\b/i) ||
    ""
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

app.post("/api/parse", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: "Envie um PDF em file." });
    }

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

// Importação em massa (PROTEGIDO - sessão)
app.post("/api/import-pdfs", requireAuth, uploadMany.array("files", 50), async (req, res) => {
  try {
    const vendedorDefault = String(req.body?.vendedor || "").trim();
    const modo = String(req.body?.modo || "upsert").toLowerCase(); // upsert|skip

    const files = req.files || [];
    if (!files.length) {
      return res.status(400).json({ ok: false, error: "Envie PDFs no campo 'files'." });
    }

    const results = [];
    let okCount = 0;
    let failCount = 0;
    let skipCount = 0;

    async function saveNotaFromFields(fields, vendedorFallback) {
      const dataEmissaoISO = parseBrDateToISO(fields.dataEmissao);
      const nf = String(fields.numeroNotaFiscal || "").trim() || null;

      if (modo === "skip" && nf) {
        const exists = await pool.query(
          "SELECT 1 FROM notas WHERE numero_nota_fiscal = $1 LIMIT 1",
          [nf]
        );
        if (exists.rowCount) {
          return { skipped: true, reason: "NF já existe (skip)." };
        }
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
      const item = {
        fileName: f.originalname,
        size: f.size,
        ok: false,
      };

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

        if (!payload.vendedor && !vendedorDefault) {
          throw new Error("Vendedor ausente. Informe um vendedor no import.");
        }

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

    return res.json({
      ok: true,
      total: results.length,
      saved: okCount,
      skipped: skipCount,
      failed: failCount,
      results,
    });
  } catch (err) {
    console.error("POST /api/import-pdfs error:", err);
    return res.status(500).json({
      ok: false,
      error: "Falha ao importar PDFs.",
      details: String(err?.message || err),
    });
  }
});

// Salvar nota no DB (não protegido)
app.post("/api/notas", async (req, res) => {
  try {
    const b = req.body || {};

    if (!b.vendedor) {
      return res.status(400).json({ ok: false, error: "Vendedor é obrigatório." });
    }

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

    if (err?.code === "23505") {
      return res.status(409).json({
        ok: false,
        error: "Já existe uma nota com esse número de NF.",
        details: String(err?.detail || err?.message || err),
      });
    }

    return res.status(500).json({
      ok: false,
      error: "Falha ao salvar nota no banco.",
      details: String(err?.message || err),
    });
  }
});

// DELETE nota (PROTEGIDO - sessão)
app.delete("/api/notas/:id", requireAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) {
      return res.status(400).json({ ok: false, error: "ID inválido." });
    }

    const { rowCount } = await pool.query("DELETE FROM notas WHERE id = $1", [id]);

    if (!rowCount) {
      return res.status(404).json({ ok: false, error: "Nota não encontrada." });
    }

    sseBroadcast({ type: "NOTA_DELETADA", id });

    return res.json({ ok: true });
  } catch (err) {
    console.error("DELETE /api/notas/:id error:", err);
    return res.status(500).json({
      ok: false,
      error: "Falha ao deletar nota.",
      details: String(err?.message || err),
    });
  }
});

// Listagem para financeiro + filtros
app.get("/api/notas", async (req, res) => {
  try {
    const { dataDe, dataAte, vendedor, formaEnvio, q, page = "1", pageSize = "50" } = req.query;

    const limit = Math.min(Math.max(parseInt(pageSize, 10) || 50, 1), 200);
    const offset = (Math.max(parseInt(page, 10) || 1, 1) - 1) * limit;

    const where = [];
    const params = [];
    let i = 1;

    if (dataDe) {
      where.push(`data_emissao >= $${i++}`);
      params.push(dataDe);
    }
    if (dataAte) {
      where.push(`data_emissao <= $${i++}`);
      params.push(dataAte);
    }
    if (vendedor) {
      where.push(`vendedor ILIKE $${i++}`);
      params.push(`%${vendedor}%`);
    }
    if (formaEnvio) {
      where.push(`forma_envio ILIKE $${i++}`);
      params.push(`%${formaEnvio}%`);
    }
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
    console.error("GET /api/notas error:", err);
    return res.status(500).json({
      ok: false,
      error: "Falha ao listar notas.",
      details: String(err?.message || err),
    });
  }
});

// Excel gerado a partir do banco
app.get("/api/relatorio.xlsx", async (req, res) => {
  try {
    const tipo = String(req.query.tipo || "").toLowerCase();
    const dataBr = String(req.query.data || "").trim();
    const vendedor = req.query.vendedor ? String(req.query.vendedor) : "";
    const formaEnvio = req.query.formaEnvio ? String(req.query.formaEnvio) : "";

    if (!["diario", "mensal", "anual"].includes(tipo)) {
      return res.status(400).json({ ok: false, error: "tipo inválido: use diario|mensal|anual" });
    }

    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const hojeBr = `${pad(now.getDate())}/${pad(now.getMonth() + 1)}/${now.getFullYear()}`;
    const baseISO = parseBrDateToISO(dataBr || hojeBr);
    if (!baseISO) return res.status(400).json({ ok: false, error: "data inválida (use DD/MM/AAAA)" });

    const [Y, M] = baseISO.split("-").map((x) => parseInt(x, 10));

    let startISO = "";
    let endISO = "";

    if (tipo === "diario") {
      startISO = baseISO;
      endISO = baseISO;
    } else if (tipo === "mensal") {
      startISO = `${Y}-${String(M).padStart(2, "0")}-01`;
      const lastDay = new Date(Y, M, 0).getDate();
      endISO = `${Y}-${String(M).padStart(2, "0")}-${String(lastDay).padStart(2, "0")}`;
    } else {
      startISO = `${Y}-01-01`;
      endISO = `${Y}-12-31`;
    }

    const where = [`data_emissao >= $1`, `data_emissao <= $2`];
    const params = [startISO, endISO];
    let i = 3;

    if (vendedor) {
      where.push(`vendedor ILIKE $${i++}`);
      params.push(`%${vendedor}%`);
    }
    if (formaEnvio) {
      where.push(`forma_envio ILIKE $${i++}`);
      params.push(`%${formaEnvio}%`);
    }

    const sql = `
      SELECT *
      FROM notas
      WHERE ${where.join(" AND ")}
      ORDER BY data_emissao ASC NULLS LAST, created_at ASC;
    `;

    const { rows } = await pool.query(sql, params);

    const wb = new ExcelJS.Workbook();
    wb.creator = "Sistema de Notas";
    wb.created = new Date();

    const ws = wb.addWorksheet("Relatório", {
      properties: { defaultRowHeight: 18 },
      views: [{ state: "frozen", xSplit: 0, ySplit: 5 }],
    });

    const title = `Relatório ${tipo.toUpperCase()}`;
    ws.mergeCells("A1:N1");
    ws.getCell("A1").value = title;
    ws.getCell("A1").font = { size: 16, bold: true, color: { argb: "FFFFFFFF" } };
    ws.getCell("A1").alignment = { vertical: "middle", horizontal: "left" };
    ws.getCell("A1").fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1F4E79" } };
    ws.getRow(1).height = 26;

    ws.mergeCells("A2:N2");
    ws.getCell("A2").value = `Período: ${startISO} até ${endISO}`;
    ws.getCell("A2").font = { italic: true, color: { argb: "FF1F2937" } };
    ws.getCell("A2").alignment = { vertical: "middle", horizontal: "left" };

    ws.mergeCells("A3:N3");
    ws.getCell("A3").value =
      `Filtros: vendedor=${vendedor || "Todos"} | formaEnvio=${formaEnvio || "Todas"} | gerado em ${new Date().toLocaleString("pt-BR")}`;
    ws.getCell("A3").font = { italic: true, color: { argb: "FF374151" } };
    ws.getCell("A3").alignment = { vertical: "middle", horizontal: "left" };

    ws.addRow([]);
    const headerRowIndex = 5;

    const columns = [
      { key: "id", header: "ID", width: 10 },
      { key: "created_at", header: "Criado em", width: 18 },
      { key: "vendedor", header: "Vendedor", width: 18 },
      { key: "nome_cliente", header: "Cliente", width: 26 },
      { key: "numero_nota_fiscal", header: "Nota Fiscal", width: 14 },
      { key: "forma_envio", header: "Forma de envio", width: 16 },
      { key: "valor_envio", header: "Valor envio (R$)", width: 16 },
      { key: "valor_cobrado", header: "Valor cobrado (R$)", width: 18 },
      { key: "pacote", header: "Pacote", width: 14 },
      { key: "forma_pagamento", header: "Pagamento", width: 14 },
      { key: "endereco_local", header: "Endereço", width: 22 },
      { key: "cep", header: "CEP", width: 12 },
      { key: "data_emissao", header: "Emissão", width: 12 },
      { key: "valor_total_nota", header: "Total (R$)", width: 16 },
    ];
    ws.columns = columns;

    const headerRow = ws.getRow(headerRowIndex);
    headerRow.values = columns.map((c) => c.header);
    headerRow.font = { bold: true, color: { argb: "FFFFFFFF" } };
    headerRow.alignment = { vertical: "middle", horizontal: "center", wrapText: true };
    headerRow.height = 20;

    headerRow.eachCell((cell) => {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FF111827" } };
      cell.border = {
        top: { style: "thin", color: { argb: "FF374151" } },
        left: { style: "thin", color: { argb: "FF374151" } },
        bottom: { style: "thin", color: { argb: "FF374151" } },
        right: { style: "thin", color: { argb: "FF374151" } },
      };
    });

    ws.autoFilter = {
      from: { row: headerRowIndex, column: 1 },
      to: { row: headerRowIndex, column: columns.length },
    };

    const toDate = (v) => {
      if (!v) return null;
      const d = new Date(v);
      return Number.isNaN(d.getTime()) ? null : d;
    };

    const colByKey = (key) => ws.getColumn(columns.findIndex((c) => c.key === key) + 1);

    const numPg = (v) => {
      if (v === null || v === undefined || v === "") return 0;
      const n = Number(v);
      return Number.isFinite(n) ? n : 0;
    };

    for (const r of rows) {
      const created = toDate(r.created_at);
      const emissao = r.data_emissao ? new Date(r.data_emissao) : null;

      const row = ws.addRow({
        id: r.id,
        created_at: created,
        vendedor: r.vendedor || "",
        nome_cliente: r.nome_cliente || "",
        numero_nota_fiscal: r.numero_nota_fiscal || "",
        forma_envio: r.forma_envio || "",
        valor_envio: numPg(r.valor_envio),
        valor_cobrado: null,
        pacote: r.pacote || "",
        forma_pagamento: r.forma_pagamento || "",
        endereco_local: r.endereco_local || "",
        cep: r.cep || "",
        data_emissao: emissao,
        valor_total_nota: numPg(r.valor_total_nota),
      });

      const isEven = row.number % 2 === 0;
      row.eachCell((cell) => {
        cell.fill = {
          type: "pattern",
          pattern: "solid",
          fgColor: { argb: isEven ? "FFF9FAFB" : "FFFFFFFF" },
        };
        cell.border = {
          top: { style: "thin", color: { argb: "FFE5E7EB" } },
          left: { style: "thin", color: { argb: "FFE5E7EB" } },
          bottom: { style: "thin", color: { argb: "FFE5E7EB" } },
          right: { style: "thin", color: { argb: "FFE5E7EB" } },
        };
        cell.alignment = { vertical: "middle", horizontal: "left", wrapText: true };
      });
    }

    colByKey("created_at").numFmt = "dd/mm/yyyy hh:mm";
    colByKey("data_emissao").numFmt = "dd/mm/yyyy";

    colByKey("valor_envio").numFmt = "R$ #,##0.00";
    colByKey("valor_cobrado").numFmt = "R$ #,##0.00";
    colByKey("valor_total_nota").numFmt = "R$ #,##0.00";

    ws.addRow([]);

    const firstDataRow = headerRowIndex + 1;
    const lastDataRow = ws.lastRow.number - 1;

    const idxEnvio = columns.findIndex((c) => c.key === "valor_envio") + 1;
    const idxCobrado = columns.findIndex((c) => c.key === "valor_cobrado") + 1;
    const idxTotalNota = columns.findIndex((c) => c.key === "valor_total_nota") + 1;

    const colLetter = (n) => {
      let s = "";
      while (n > 0) {
        const m = (n - 1) % 26;
        s = String.fromCharCode(65 + m) + s;
        n = Math.floor((n - 1) / 26);
      }
      return s;
    };

    const envioCol = colLetter(idxEnvio);
    const cobradoCol = colLetter(idxCobrado);
    const totalNotaCol = colLetter(idxTotalNota);

    const totalRow = ws.addRow({
      id: "",
      created_at: null,
      vendedor: "",
      nome_cliente: "",
      numero_nota_fiscal: "",
      forma_envio: "TOTAIS",
      valor_envio: { formula: `SUM(${envioCol}${firstDataRow}:${envioCol}${lastDataRow})` },
      valor_cobrado: { formula: `SUM(${cobradoCol}${firstDataRow}:${cobradoCol}${lastDataRow})` },
      pacote: "",
      forma_pagamento: "",
      endereco_local: "",
      cep: "",
      data_emissao: null,
      valor_total_nota: { formula: `SUM(${totalNotaCol}${firstDataRow}:${totalNotaCol}${lastDataRow})` },
    });

    totalRow.eachCell((cell) => {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFE5E7EB" } };
      cell.font = { bold: true };
      cell.border = {
        top: { style: "thin", color: { argb: "FF9CA3AF" } },
        bottom: { style: "double", color: { argb: "FF111827" } },
      };
    });

    const diffRow = ws.addRow({
      id: "",
      created_at: null,
      vendedor: "",
      nome_cliente: "",
      numero_nota_fiscal: "",
      forma_envio: "DIFERENÇA (Cobrado - Envio)",
      valor_envio: "",
      valor_cobrado: { formula: `${cobradoCol}${totalRow.number}-${envioCol}${totalRow.number}` },
      pacote: "",
      forma_pagamento: "",
      endereco_local: "",
      cep: "",
      data_emissao: null,
      valor_total_nota: "",
    });

    diffRow.eachCell((cell) => {
      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFF3F4F6" } };
      cell.font = { bold: true };
    });

    ws.pageSetup = {
      orientation: "landscape",
      fitToPage: true,
      fitToWidth: 1,
      fitToHeight: 0,
    };

    const fileName =
      tipo === "diario"
        ? `relatorio-diario-${baseISO}.xlsx`
        : tipo === "mensal"
          ? `relatorio-mensal-${Y}-${String(M).padStart(2, "0")}.xlsx`
          : `relatorio-anual-${Y}.xlsx`;

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);

    await wb.xlsx.write(res);
    res.end();
  } catch (err) {
    console.error("GET /api/relatorio.xlsx error:", err);
    return res.status(500).json({
      ok: false,
      error: "Falha ao gerar relatório.",
      details: String(err?.message || err),
    });
  }
});

const PORT = Number(process.env.PORT || 3001);
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server rodando na porta ${PORT}`);
});
