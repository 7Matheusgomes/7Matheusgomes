// public/upload.js (corrigido p/ evitar problema de cache/304 no /api/me)
// - Não faz redirect automático (quem está redirecionando é outro script da página).
// - Mesmo assim, este arquivo agora:
//   1) força "cache: no-store" em todas as chamadas fetch deste fluxo;
//   2) trata respostas 304/204/HTML de forma segura (não tenta dar resp.json() cegamente);
//   3) opcionalmente verifica sessão em /api/me sem quebrar se vier 304 (apenas avisa).

const API_PARSE_URL = "/api/parse";
const API_SALVAR_URL = "/api/notas";
const API_RELATORIO_URL = "/api/relatorio.xlsx";
const API_ME_URL = "/api/me";

const $ = (id) => document.getElementById(id);

function on(id, event, handler) {
  const el = $(id);
  if (!el) {
    console.warn(`[upload.js] Elemento #${id} não encontrado no HTML.`);
    return;
  }
  el.addEventListener(event, handler);
}

function setValue(id, value) {
  const el = $(id);
  if (!el) return;
  el.value = value ?? "";
}

function setText(id, value) {
  const el = $(id);
  if (!el) return;
  el.textContent = value ?? "";
}

function fill(fields) {
  const f = fields || {};
  setValue("nomeCliente", f.nomeCliente || "");
  setValue("numeroNotaFiscal", f.numeroNotaFiscal || "");
  setValue("formaEnvio", f.formaEnvio || "");
  setValue("valorEnvio", f.valorEnvio || "");
  setValue("pacote", f.pacote || "");
  setValue("formaPagamento", f.formaPagamento || "");
  setValue("enderecoLocal", f.enderecoLocal || "");
  setValue("cep", f.cep || "");
  setValue("dataEmissao", f.dataEmissao || "");
  setValue("valorTotalNota", f.valorTotalNota || "");
  setText("debug", f.__debugDestChunk || f.__debugTextPreview || "");
}

function getPayloadFromForm() {
  return {
    vendedor: $("vendedor")?.value || "",
    nomeCliente: $("nomeCliente")?.value || "",
    numeroNotaFiscal: $("numeroNotaFiscal")?.value || "",
    formaEnvio: $("formaEnvio")?.value || "",
    valorEnvio: $("valorEnvio")?.value || "",
    pacote: $("pacote")?.value || "",
    formaPagamento: $("formaPagamento")?.value || "",
    enderecoLocal: $("enderecoLocal")?.value || "",
    cep: $("cep")?.value || "",
    dataEmissao: $("dataEmissao")?.value || "",
    valorTotalNota: $("valorTotalNota")?.value || "",
  };
}

// --- helpers robustos p/ fetch/JSON (evita quebrar com 304 ou HTML) ---
async function safeReadJson(resp) {
  // 304/204 não traz body
  if (resp.status === 304 || resp.status === 204) return null;

  const ct = resp.headers.get("content-type") || "";
  if (!ct.includes("application/json")) {
    // Se vier HTML (ex: página inicial), não tenta parsear
    const txt = await resp.text().catch(() => "");
    return { ok: false, error: "Resposta não-JSON do servidor.", __raw: txt.slice(0, 500) };
  }

  return resp.json().catch(() => null);
}

function withNoStore(init = {}) {
  return {
    ...init,
    credentials: "include",
    cache: "no-store", // evita 304 em endpoints dinâmicos (quando o browser respeita)
    headers: {
      ...(init.headers || {}),
      // Ajuda alguns proxies/CDNs a não reusar resposta
      "Cache-Control": "no-cache",
      Pragma: "no-cache",
    },
  };
}

// (Opcional) check de sessão apenas informativo — NÃO redireciona
async function checkSessionSoft() {
  try {
    const resp = await fetch(API_ME_URL, withNoStore({ method: "GET" }));
    const data = await safeReadJson(resp);

    // Se deu 304, não conclui nada (evita falso "deslogado")
    if (resp.status === 304) {
      console.warn("[upload.js] /api/me retornou 304 (cache). Ideal corrigir no backend com Cache-Control: no-store.");
      return;
    }

    if (!resp.ok) {
      console.warn("[upload.js] /api/me falhou:", resp.status, data);
      return;
    }

    if (data && data.ok && data.authed === false) {
      console.warn("[upload.js] Sessão aparentemente não autenticada (data.authed=false).");
      // NÃO redireciona aqui. O redirecionamento que você vê vem de outro script.
    }
  } catch (e) {
    console.warn("[upload.js] Erro ao checar sessão:", e?.message || e);
  }
}

// roda somente depois do HTML existir
document.addEventListener("DOMContentLoaded", () => {
  // Não resolve o redirect (isso é em outro script), mas ajuda a diagnosticar.
  checkSessionSoft();

  // =========================
  // Upload / Processar PDF
  // =========================
  on("btnProcessar", "click", async () => {
    const vendedor = $("vendedor")?.value;
    if (!vendedor) {
      alert("Selecione o vendedor primeiro.");
      return;
    }

    const file = $("file")?.files?.[0];
    if (!file) {
      alert("Selecione um PDF.");
      return;
    }

    const fd = new FormData();
    fd.append("file", file);

    const btn = $("btnProcessar");
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Processando...";
    }

    try {
      const resp = await fetch(API_PARSE_URL, withNoStore({ method: "POST", body: fd }));
      const data = await safeReadJson(resp);

      if (!resp.ok || !data || !data.ok) {
        const msg = data?.error || `Falha ao processar (HTTP ${resp.status}).`;
        console.warn("[upload.js] parse fail:", resp.status, data);
        alert(msg);
        return;
      }

      fill(data.fields);
    } catch (e) {
      alert("Erro de rede/servidor: " + (e?.message || e));
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = "Processar PDF";
      }
    }
  });

  // =========================
  // Salvar
  // =========================
  on("btnSalvar", "click", async () => {
    const payload = getPayloadFromForm();

    if (!payload.vendedor) {
      alert("Selecione o vendedor antes de salvar.");
      return;
    }

    const btn = $("btnSalvar");
    const oldText = btn?.textContent || "Salvar";
    if (btn) {
      btn.disabled = true;
      btn.textContent = "Salvando...";
    }

    try {
      const resp = await fetch(
        API_SALVAR_URL,
        withNoStore({
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })
      );

      const data = await safeReadJson(resp);

      if (!resp.ok || !data || !data.ok) {
        setText("saida", JSON.stringify(data, null, 2));
        const msg = data?.error || `Falha ao salvar (HTTP ${resp.status}).`;
        console.warn("[upload.js] salvar fail:", resp.status, data);
        alert(msg);
        return;
      }

      setText("saida", JSON.stringify(data, null, 2));
    } catch (e) {
      alert("Erro de rede/servidor ao salvar: " + (e?.message || e));
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = oldText;
      }
    }
  });

  // =========================
  // Menu flutuante (download)
  // =========================
  function toggleMenu(open) {
    const menu = $("downloadMenu");
    if (!menu) return;

    const isHidden = menu.hasAttribute("hidden");
    const shouldOpen = typeof open === "boolean" ? open : isHidden;

    if (shouldOpen) menu.removeAttribute("hidden");
    else menu.setAttribute("hidden", "");
  }

  on("btnDownloadToggle", "click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    toggleMenu();
  });

  document.addEventListener("click", (e) => {
    const root = $("floatingDownload");
    if (!root) return;
    if (!root.contains(e.target)) toggleMenu(false);
  });

  const menu = $("downloadMenu");
  if (menu) {
    menu.querySelectorAll(".fd-item").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        const tipo = btn.getAttribute("data-tipo") || "diario";
        const data = $("dataEmissao")?.value || "";

        toggleMenu(false);

        const url = new URL(API_RELATORIO_URL, window.location.origin);
        url.searchParams.set("tipo", tipo);
        if (data) url.searchParams.set("data", data);

        window.location.href = url.toString();
      });
    });
  }

  // =========================
  // Extra: mostrar nome do arquivo
  // =========================
  const fileEl = $("file");
  const fileNameEl = $("fileName");
  if (fileEl && fileNameEl) {
    fileEl.addEventListener("change", () => {
      const f = fileEl.files && fileEl.files[0];
      fileNameEl.textContent = f ? f.name : "—";
    });
  }
});
