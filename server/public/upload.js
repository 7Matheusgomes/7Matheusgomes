// public/upload.js (pronto e robusto)
// - Versão adaptada do seu app.js para uso exclusivo do upload.html
// - Use no HTML: <script src="/upload.js"></script>

const API_PARSE_URL = "/api/parse";
const API_SALVAR_URL = "/api/notas";
const API_RELATORIO_URL = "/api/relatorio.xlsx";

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

  // compatível com diferentes chaves de debug
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

// roda somente depois do HTML existir
document.addEventListener("DOMContentLoaded", () => {
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
      const resp = await fetch(API_PARSE_URL, {
        method: "POST",
        body: fd,
        credentials: "include", // importante se sua sessão for por cookie
      });

      const data = await resp.json().catch(() => ({}));

      if (!resp.ok || !data.ok) {
        alert(data.error || `Falha ao processar (HTTP ${resp.status}).`);
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
  // Salvar (gera/atualiza relatórios no servidor)
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
      const resp = await fetch(API_SALVAR_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include", // importante se sua sessão for por cookie
        body: JSON.stringify(payload),
      });

      const data = await resp.json().catch(() => ({}));

      if (!resp.ok || !data.ok) {
        setText("saida", JSON.stringify(data, null, 2));
        alert(data?.error || `Falha ao salvar (HTTP ${resp.status}).`);
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

  // Fecha o menu ao clicar fora (sem quebrar se não existir)
  document.addEventListener("click", (e) => {
    const root = $("floatingDownload");
    if (!root) return;
    if (!root.contains(e.target)) toggleMenu(false);
  });

  // Clique em Diário/Mensal/Anual -> download (se o menu existir)
  const menu = $("downloadMenu");
  if (menu) {
    menu.querySelectorAll(".fd-item").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        const tipo = btn.getAttribute("data-tipo") || "diario";
        const data = $("dataEmissao")?.value || ""; // DD/MM/AAAA (se vazio, backend usa hoje)

        toggleMenu(false);

        const url = new URL(API_RELATORIO_URL, window.location.origin);
        url.searchParams.set("tipo", tipo);
        if (data) url.searchParams.set("data", data);

        // força download
        window.location.href = url.toString();
      });
    });
  }

  // =========================
  // Extra: mostrar nome do arquivo (se existir #fileName)
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
