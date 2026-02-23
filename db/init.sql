CREATE TABLE IF NOT EXISTS notas (
  id                BIGSERIAL PRIMARY KEY,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  vendedor          TEXT NOT NULL,
  nome_cliente      TEXT,
  numero_nota_fiscal TEXT,
  forma_envio       TEXT,
  valor_envio       NUMERIC(14,2),
  pacote            TEXT,
  forma_pagamento   TEXT,
  endereco_local    TEXT,
  cep               TEXT,
  data_emissao      DATE,
  valor_total_nota  NUMERIC(14,2)
);

CREATE INDEX IF NOT EXISTS idx_notas_data_emissao ON notas (data_emissao);
CREATE INDEX IF NOT EXISTS idx_notas_vendedor ON notas (vendedor);
CREATE INDEX IF NOT EXISTS idx_notas_forma_envio ON notas (forma_envio);
