import express from "express";
import cors from "cors";
import portscanner from "portscanner";
import { randomUUID } from "crypto";

const app = express();
app.use(cors());
app.use(express.json());

let monitors = []; // Lista de IPs e portas para monitorar

// Função para verificar status das portas
async function checkPort(ip, port) {
  try {
    return await portscanner.checkPortStatus(port, ip);
  } catch {
    return "error";
  }
}

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
app.post("/add-monitor", (req, res) => {
  const { ip, port } = req.body;
  if (!ip || !port) {
    return res.status(400).json({ error: "IP e porta são obrigatórios" });
  }
  const newMonitor = { id: randomUUID(), ip, port };
  monitors.push(newMonitor);
  res.json({ message: "Monitor adicionado", monitor: newMonitor });
});

// Retornar todos monitores com status atualizado
app.get("/monitors", async (req, res) => {
  const updated = [];
  for (const m of monitors) {
    const status = await checkPort(m.ip, m.port);
    updated.push({ ...m, status });
  }
  res.json(updated);
});

// Remover monitor
app.delete("/monitor/:id", (req, res) => {
  const { id } = req.params;
  monitors = monitors.filter(m => m.id !== id);
  res.json({ message: "Monitor removido" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
