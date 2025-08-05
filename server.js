import express from "express";
import cors from "cors";
import portscanner from "portscanner";
import pkg from "pg";
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

// Configuração do Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // Render vai setar essa env
  ssl: { rejectUnauthorized: false }
});

// Função para verificar status das portas
async function checkPort(ip, port) {
  try {
    return await portscanner.checkPortStatus(port, ip);
  } catch {
    return "error";
  }
}

// Criar tabela se não existir
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS monitors (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      ip TEXT NOT NULL,
      port INTEGER NOT NULL
    )
  `);
})();

// Rota para escanear portas pontualmente
app.post("/scan", async (req, res) => {
  const { ip, ports } = req.body;
  if (!ip || !Array.isArray(ports) || ports.length === 0) {
    return res.status(400).json({ error: "IP e lista de portas são obrigatórios" });
  }
  const results = [];
  for (const port of ports) {
    const status = await checkPort(ip, port);
    results.push({ port, status });
  }
  res.json({ ip, results });
});

// Adicionar IP:Porta para monitoramento
app.post("/add-monitor", async (req, res) => {
  const { ip, port } = req.body;
  if (!ip || !port) {
    return res.status(400).json({ error: "IP e porta são obrigatórios" });
  }
  const result = await pool.query(
    "INSERT INTO monitors (ip, port) VALUES ($1, $2) RETURNING *",
    [ip, port]
  );
  res.json({ message: "Monitor adicionado", monitor: result.rows[0] });
});

// Retornar todos monitores com status atualizado
app.get("/monitors", async (req, res) => {
  const dbMonitors = await pool.query("SELECT * FROM monitors");
  const updated = [];

  for (const m of dbMonitors.rows) {
    const status = await checkPort(m.ip, m.port);
    updated.push({
      id: m.id,
      name: m.name,     // Nome do computador
      ip: m.ip,
      port: m.port,
      status: status
    });
  }

  res.json(updated);
});

// Remover monitor
app.delete("/monitor/:id", async (req, res) => {
  const { id } = req.params;
  await pool.query("DELETE FROM monitors WHERE id = $1", [id]);
  res.json({ message: "Monitor removido" });
});

// Adicionar ou atualizar IP/porta por computador
app.post("/register-monitor", async (req, res) => {
  let { computerId, name, ip, port } = req.body;
  
  // Forçar id e port como número
  computerId = parseInt(computerId, 10);
  port = parseInt(port, 10);

  if (!computerId || !name || !ip || !port) {
    return res.status(400).json({ error: "computerId, name, ip e port são obrigatórios" });
  }

  // Verifica se já existe registro para esse computador
  const exists = await pool.query("SELECT * FROM monitors WHERE id = $1", [computerId]);

  if (exists.rows.length > 0) {
    // Atualiza registro existente
    await pool.query(
      "UPDATE monitors SET name = $1, ip = $2, port = $3 WHERE id = $4",
      [name, ip, port, computerId]
    );
    return res.json({ message: "Monitor atualizado", id: computerId, name, ip, port });
  } else {
    // Cria novo registro
    await pool.query(
      "INSERT INTO monitors (id, name, ip, port) VALUES ($1, $2, $3, $4)",
      [computerId, name, ip, port]
    );
    return res.json({ message: "Monitor registrado", id: computerId, name, ip, port });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
