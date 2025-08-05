import express from "express";
import cors from "cors";
import portscanner from "portscanner";

const app = express();
app.use(cors());
app.use(express.json());

// Rota para escanear portas
app.post("/scan", async (req, res) => {
  const { ip, ports } = req.body;

  if (!ip || !Array.isArray(ports) || ports.length === 0) {
    return res.status(400).json({ error: "IP e lista de portas são obrigatórios" });
  }

  const results = [];
  for (const port of ports) {
    try {
      const status = await portscanner.checkPortStatus(port, ip);
      results.push({ port, status });
    } catch (err) {
      results.push({ port, status: "error" });
    }
  }

  res.json({ ip, results });
});

// Porta para Render
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
