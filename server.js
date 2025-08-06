import express from "express";
import cors from "cors";
import portscanner from "portscanner";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

// Configuração JWT
const JWT_SECRET = process.env.JWT_SECRET || 'monitor_app_secret_key_2024';

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token de acesso requerido' });
  }

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido' });
    }
    
    // Buscar dados completos do usuário incluindo role
    try {
      const userResult = await pool.query('SELECT id, email, name, role FROM users WHERE id = $1::uuid', [user.userId]);
      if (userResult.rows.length === 0) {
        return res.status(403).json({ error: 'Usuário não encontrado' });
      }
      
      req.user = {
        ...user,
        role: userResult.rows[0].role,
        name: userResult.rows[0].name
      };
      next();
    } catch (error) {
      console.error('Erro ao buscar dados do usuário:', error);
      return res.status(500).json({ error: 'Erro interno do servidor' });
    }
  });
};

// Middleware para verificar se usuário pode criar/editar (USER ou ADMIN)
const requireUserRole = (req, res, next) => {
  if (req.user.role === 'VIEWER') {
    return res.status(403).json({ error: 'Permissão insuficiente. Necessário role USER ou ADMIN.' });
  }
  next();
};

// Middleware para verificar se usuário é ADMIN
const requireAdminRole = (req, res, next) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Permissão insuficiente. Necessário role ADMIN.' });
  }
  next();
};

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

// Criar tabelas se não existirem
(async () => {
  // Criar tabela de usuários se não existir
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      name VARCHAR(255) NOT NULL,
      role VARCHAR(20) DEFAULT 'USER' CHECK (role IN ('VIEWER', 'USER', 'ADMIN')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Adicionar coluna role se não existir (migração)
  try {
    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'USER' 
      CHECK (role IN ('VIEWER', 'USER', 'ADMIN'))
    `);
  } catch (error) {
    // Coluna já existe, ignorar erro
  }

  // Tabela de monitors (atualizada com user_id e is_public)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS monitors (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id) ON DELETE CASCADE,
      name TEXT,
      ip TEXT NOT NULL,
      port INTEGER NOT NULL,
      is_public BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Adicionar coluna is_public se não existir (para bancos existentes)
  try {
    await pool.query(`
      ALTER TABLE monitors 
      ADD COLUMN IF NOT EXISTS is_public BOOLEAN DEFAULT FALSE
    `);
  } catch (error) {
    // Ignora erro se coluna já existe
    console.log('Coluna is_public já existe ou erro ao adicionar:', error.message);
  }
})();

// ===== ROTAS DE AUTENTICAÇÃO =====

// Rota de registro
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, role = 'USER' } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Nome, email e senha são obrigatórios" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Senha deve ter pelo menos 6 caracteres" });
    }

    // Verificar se role é válida
    const validRoles = ['VIEWER', 'USER', 'ADMIN'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: "Role deve ser VIEWER, USER ou ADMIN" });
    }

    // Verificar se usuário já existe
    const existingUser = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email já cadastrado" });
    }

    // Hash da senha
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Criar usuário
    const result = await pool.query(
      "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id, name, email, role, created_at",
      [name, email, hashedPassword, role]
    );

    const user = result.rows[0];

    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: "Usuário criado com sucesso",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error("Erro no registro:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota de login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email e senha são obrigatórios" });
    }

    // Buscar usuário
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    const user = result.rows[0];

    // Verificar senha
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Credenciais inválidas" });
    }

    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: "Login realizado com sucesso",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        created_at: user.created_at
      }
    });
  } catch (error) {
    console.error("Erro no login:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Rota para verificar token (opcional)
app.get("/verify-token", authenticateToken, (req, res) => {
  res.json({ message: "Token válido", user: req.user });
});

// ===== ROTAS DE PORT SCANNING =====

// Rota para escanear portas pontualmente
app.post("/scan", async (req, res) => {
  const { ip, port } = req.body;
  console.log(JSON.stringify(req.body));
  if (!ip || !port) {
    return res.status(400).json({ error: "IP e lista de portas são obrigatórios" });
  }
  const results = [];
  
    const status = await checkPort(ip, port);
    results.push({ port, status });
  
  res.json({ ip, status });
});

// Adicionar novo monitor (protegida - apenas USER e ADMIN)
app.post("/add-monitor", authenticateToken, requireUserRole, async (req, res) => {
  try {
    const { ip, port, name, is_public } = req.body;
    if (!ip || !port) {
      return res.status(400).json({ error: "IP e porta são obrigatórios" });
    }
    
    const result = await pool.query(
      "INSERT INTO monitors (user_id, name, ip, port, is_public) VALUES ($1::uuid, $2, $3, $4, $5) RETURNING *",
      [req.user.userId, name || `${ip}:${port}`, ip, port, is_public || false]
    );
    res.json({ message: "Monitor adicionado", monitor: result.rows[0] });
  } catch (error) {
    console.error("Erro ao adicionar monitor:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Retornar monitores com base no role do usuário (protegida)
app.get("/monitors", authenticateToken, async (req, res) => {
  try {
    let dbMonitors;
    
    if (req.user.role === 'ADMIN') {
      // ADMIN vê todos os monitores
      dbMonitors = await pool.query(`
        SELECT m.*, u.name as owner_name 
        FROM monitors m 
        LEFT JOIN users u ON m.user_id = u.id
        ORDER BY m.is_public DESC, m.created_at DESC
      `);
    } else {
      // VIEWER e USER veem monitores públicos + próprios privados
      dbMonitors = await pool.query(`
        SELECT m.*, u.name as owner_name 
        FROM monitors m 
        LEFT JOIN users u ON m.user_id = u.id
        WHERE m.is_public = TRUE OR m.user_id = $1::uuid 
        ORDER BY m.is_public DESC, m.created_at DESC
      `, [req.user.userId]);
    }
    
    const updated = [];

    for (const m of dbMonitors.rows) {
      const status = await checkPort(m.ip, m.port);
      updated.push({
        id: m.id,
        name: m.name,
        ip: m.ip,
        port: m.port,
        status: status,
        is_public: m.is_public,
        owner_name: m.owner_name,
        is_owner: m.user_id === req.user.userId,
        created_at: m.created_at
      });
    }

    res.json(updated);
  } catch (error) {
    console.error("Erro ao buscar monitors:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Alternar status público/privado de um monitor (protegida - USER para próprios, ADMIN para todos)
app.patch("/monitor/:id/toggle-public", authenticateToken, requireUserRole, async (req, res) => {
  try {
    const { id } = req.params;
    
    let checkResult;
    if (req.user.role === 'ADMIN') {
      // ADMIN pode alterar qualquer monitor
      checkResult = await pool.query(
        "SELECT * FROM monitors WHERE id = $1",
        [id]
      );
    } else {
      // USER só pode alterar próprios monitores
      checkResult = await pool.query(
        "SELECT * FROM monitors WHERE id = $1 AND user_id = $2::uuid",
        [id, req.user.userId]
      );
    }
    
    if (checkResult.rows.length === 0) {
      const errorMsg = req.user.role === 'ADMIN' ? "Monitor não encontrado" : "Monitor não encontrado ou não pertence ao usuário";
      return res.status(404).json({ error: errorMsg });
    }
    
    // Alternar o status is_public
    const currentStatus = checkResult.rows[0].is_public;
    const newStatus = !currentStatus;
    
    let result;
    if (req.user.role === 'ADMIN') {
      // ADMIN pode alterar qualquer monitor
      result = await pool.query(
        "UPDATE monitors SET is_public = $1 WHERE id = $2 RETURNING *",
        [newStatus, id]
      );
    } else {
      // USER só pode alterar próprios monitores
      result = await pool.query(
        "UPDATE monitors SET is_public = $1 WHERE id = $2 AND user_id = $3::uuid RETURNING *",
        [newStatus, id, req.user.userId]
      );
    }
    
    res.json({ 
      message: `Monitor ${newStatus ? 'tornado público' : 'tornado privado'}`,
      monitor: result.rows[0]
    });
  } catch (error) {
    console.error("Erro ao alternar status do monitor:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Remover monitor (protegida - USER para próprios, ADMIN para todos)
app.delete("/monitor/:id", authenticateToken, requireUserRole, async (req, res) => {
  try {
    const { id } = req.params;
    
    let result;
    if (req.user.role === 'ADMIN') {
      // ADMIN pode excluir qualquer monitor
      result = await pool.query(
        "DELETE FROM monitors WHERE id = $1 RETURNING *",
        [id]
      );
    } else {
      // USER só pode excluir próprios monitores
      result = await pool.query(
        "DELETE FROM monitors WHERE id = $1 AND user_id = $2::uuid RETURNING *",
        [id, req.user.userId]
      );
    }
    
    if (result.rows.length === 0) {
      const errorMsg = req.user.role === 'ADMIN' ? "Monitor não encontrado" : "Monitor não encontrado ou não pertence ao usuário";
      return res.status(404).json({ error: errorMsg });
    }
    
    res.json({ message: "Monitor removido" });
  } catch (error) {
    console.error("Erro ao remover monitor:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
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

// ===== ROTAS DE GERENCIAMENTO DE USUÁRIOS (APENAS ADMIN) =====

// Listar todos os usuários (apenas ADMIN)
app.get("/admin/users", authenticateToken, requireAdminRole, async (req, res) => {
  try {
    const users = await pool.query(`
      SELECT id, name, email, role, created_at,
             (SELECT COUNT(*) FROM monitors WHERE user_id = users.id) as monitor_count
      FROM users 
      ORDER BY created_at DESC
    `);
    
    res.json(users.rows);
  } catch (error) {
    console.error("Erro ao buscar usuários:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Alterar role de um usuário (apenas ADMIN)
app.patch("/admin/user/:id/role", authenticateToken, requireAdminRole, async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;
    
    // Verificar se role é válida
    const validRoles = ['VIEWER', 'USER', 'ADMIN'];
    if (!validRoles.includes(role)) {
      return res.status(400).json({ error: "Role deve ser VIEWER, USER ou ADMIN" });
    }
    
    const result = await pool.query(
      "UPDATE users SET role = $1 WHERE id = $2::uuid RETURNING id, name, email, role",
      [role, id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }
    
    res.json({ 
      message: `Role do usuário alterada para ${role}`,
      user: result.rows[0]
    });
  } catch (error) {
    console.error("Erro ao alterar role:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Excluir usuário (apenas ADMIN)
app.delete("/admin/user/:id", authenticateToken, requireAdminRole, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Primeiro, excluir todos os monitores do usuário
    await pool.query("DELETE FROM monitors WHERE user_id = $1::uuid", [id]);
    
    // Depois, excluir o usuário
    const result = await pool.query(
      "DELETE FROM users WHERE id = $1::uuid RETURNING name, email",
      [id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }
    
    res.json({ 
      message: `Usuário ${result.rows[0].name} excluído com sucesso`
    });
  } catch (error) {
    console.error("Erro ao excluir usuário:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Obter estatísticas do sistema (apenas ADMIN)
app.get("/admin/stats", authenticateToken, requireAdminRole, async (req, res) => {
  try {
    const stats = await pool.query(`
      SELECT 
        (SELECT COUNT(*) FROM users) as total_users,
        (SELECT COUNT(*) FROM users WHERE role = 'ADMIN') as admin_users,
        (SELECT COUNT(*) FROM users WHERE role = 'USER') as regular_users,
        (SELECT COUNT(*) FROM users WHERE role = 'VIEWER') as viewer_users,
        (SELECT COUNT(*) FROM monitors) as total_monitors,
        (SELECT COUNT(*) FROM monitors WHERE is_public = true) as public_monitors,
        (SELECT COUNT(*) FROM monitors WHERE is_public = false) as private_monitors
    `);
    
    res.json(stats.rows[0]);
  } catch (error) {
    console.error("Erro ao buscar estatísticas:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ===== ROTA TEMPORÁRIA PARA TORNAR PRIMEIRO USUÁRIO ADMIN =====
// REMOVER APÓS USO!
app.post('/make-first-admin', async (req, res) => {
  try {
    console.log('🔍 Buscando primeiro usuário para tornar ADMIN...');
    
    // Buscar o primeiro usuário (por data de criação)
    const result = await pool.query(`
      SELECT id, email, name, role 
      FROM users 
      ORDER BY created_at ASC 
      LIMIT 1
    `);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Nenhum usuário encontrado' });
    }
    
    const user = result.rows[0];
    console.log(`👤 Primeiro usuário: ${user.name} (${user.email})`);
    
    if (user.role === 'ADMIN') {
      return res.json({ 
        message: 'Usuário já é ADMIN',
        user: { name: user.name, email: user.email, role: user.role }
      });
    }
    
    // Alterar role para ADMIN
    await pool.query(`
      UPDATE users 
      SET role = 'ADMIN' 
      WHERE id = $1
    `, [user.id]);
    
    console.log(`🎉 ${user.name} agora é ADMIN!`);
    
    res.json({ 
      message: 'Usuário alterado para ADMIN com sucesso!',
      user: { name: user.name, email: user.email, role: 'ADMIN' }
    });
    
  } catch (error) {
    console.error('❌ Erro ao alterar usuário:', error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
