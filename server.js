import express from "express";
import cors from "cors";
import portscanner from "portscanner";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import https from "https";
import http from "http";
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
  
  // Adicionar coluna is_wakeable se não existir (para Wake-on-LAN)
  try {
    await pool.query(`
      ALTER TABLE monitors 
      ADD COLUMN IF NOT EXISTS is_wakeable BOOLEAN DEFAULT FALSE
    `);
  } catch (error) {
    // Ignora erro se coluna já existe
    console.log('Coluna is_wakeable já existe ou erro ao adicionar:', error.message);
  }

  // Adicionar coluna last_status para rastrear mudanças de status
  try {
    await pool.query(`
      ALTER TABLE monitors 
      ADD COLUMN IF NOT EXISTS last_status BOOLEAN DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    `);
  } catch (error) {
    console.log('Colunas de status já existem ou erro ao adicionar:', error.message);
  }

  // Tabela de notificações (criar sem foreign keys primeiro)
  // Dropar tabela existente para recriar com tipos corretos
  try {
    await pool.query('DROP TABLE IF EXISTS notifications CASCADE');
    console.log('✅ Tabela notifications dropada para recriação');
  } catch (error) {
    console.log('Erro ao dropar tabela notifications:', error.message);
  }
  
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID,
        monitor_id INTEGER,
        type VARCHAR(50) NOT NULL DEFAULT 'server_offline',
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Adicionar foreign keys se as tabelas existirem
    try {
      await pool.query(`
        ALTER TABLE notifications 
        ADD CONSTRAINT fk_notifications_user 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      `);
      console.log('✅ Foreign key notifications -> users criada');
    } catch (error) {
      console.log('Foreign key para users já existe ou erro:', error.message);
    }
    
    try {
      await pool.query(`
        ALTER TABLE notifications 
        ADD CONSTRAINT fk_notifications_monitor 
        FOREIGN KEY (monitor_id) REFERENCES monitors(id) ON DELETE CASCADE
      `);
      console.log('✅ Foreign key notifications -> monitors criada');
    } catch (error) {
      console.log('Foreign key para monitors já existe ou erro:', error.message);
    }
    
  } catch (error) {
    console.log('Erro ao criar tabela notifications:', error.message);
  }

  // Tabela de configurações de notificação por usuário
  // Dropar tabela existente para recriar
  try {
    await pool.query('DROP TABLE IF EXISTS notification_settings CASCADE');
    console.log('✅ Tabela notification_settings dropada para recriação');
  } catch (error) {
    console.log('Erro ao dropar tabela notification_settings:', error.message);
  }
  
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS notification_settings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID UNIQUE,
        enabled BOOLEAN DEFAULT TRUE,
        server_offline BOOLEAN DEFAULT TRUE,
        server_online BOOLEAN DEFAULT TRUE,
        push_notifications BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Adicionar foreign key para users
    try {
      await pool.query(`
        ALTER TABLE notification_settings 
        ADD CONSTRAINT fk_notification_settings_user 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      `);
      console.log('✅ Foreign key notification_settings -> users criada');
    } catch (error) {
      console.log('Foreign key para notification_settings já existe ou erro:', error.message);
    }
    
  } catch (error) {
    console.log('Erro ao criar tabela notification_settings:', error.message);
  }

  // Tabela de tokens de push notification por dispositivo
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS push_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL,
        device_token VARCHAR(255) UNIQUE NOT NULL,
        device_type VARCHAR(20) DEFAULT 'unknown',
        device_name VARCHAR(100),
        app_version VARCHAR(20),
        is_active BOOLEAN DEFAULT TRUE,
        last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    // Adicionar foreign key para users
    try {
      await pool.query(`
        ALTER TABLE push_tokens 
        ADD CONSTRAINT fk_push_tokens_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      `);
      console.log('✅ Foreign key push_tokens -> users criada com sucesso');
    } catch (error) {
      console.log('Foreign key para push_tokens já existe ou erro:', error.message);
    }
    
    console.log('✅ Tabela push_tokens criada com sucesso');
  } catch (error) {
    console.log('Erro ao criar tabela push_tokens:', error.message);
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
    const { ip, port, name, is_public, is_wakeable } = req.body;
    if (!ip || !port) {
      return res.status(400).json({ error: "IP e porta são obrigatórios" });
    }
    
    const result = await pool.query(
      "INSERT INTO monitors (user_id, name, ip, port, is_public, is_wakeable) VALUES ($1::uuid, $2, $3, $4, $5, $6) RETURNING *",
      [req.user.userId, name || `${ip}:${port}`, ip, port, is_public || false, is_wakeable || false]
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
      const monitorData = {
        id: m.id,
        name: m.name,
        ip: m.ip,
        port: m.port,
        status: status,
        is_public: m.is_public,
        is_wakeable: m.is_wakeable,
        owner_name: m.owner_name,
        is_owner: m.user_id === req.user.userId,
        created_at: m.created_at
      };
      console.log(`Monitor ${m.name}: is_wakeable = ${m.is_wakeable}`);
      updated.push(monitorData);
    }

    console.log('Enviando monitors para frontend:', updated.length, 'monitores');
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

// Wake-on-LAN: Ligar servidor remoto (protegida - USER para próprios, ADMIN para todos)
app.post("/wake-server/:id", authenticateToken, requireUserRole, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verificar se o monitor existe e se o usuário tem permissão
    let checkResult;
    if (req.user.role === 'ADMIN') {
      // ADMIN pode acordar qualquer monitor
      checkResult = await pool.query(
        "SELECT * FROM monitors WHERE id = $1",
        [id]
      );
    } else {
      // USER só pode acordar próprios monitores
      checkResult = await pool.query(
        "SELECT * FROM monitors WHERE id = $1 AND user_id = $2::uuid",
        [id, req.user.userId]
      );
    }
    
    if (checkResult.rows.length === 0) {
      const errorMsg = req.user.role === 'ADMIN' ? "Monitor não encontrado" : "Monitor não encontrado ou não pertence ao usuário";
      return res.status(404).json({ error: errorMsg });
    }
    
    const monitor = checkResult.rows[0];
    
    // Verificar se o monitor é acordável
    if (!monitor.is_wakeable) {
      return res.status(400).json({ error: "Este servidor não está configurado para ser acordado remotamente" });
    }
    
    // Buscar o IP externo do computador ID 3 (assumindo que está na tabela monitors)
    const externalIpResult = await pool.query(
      "SELECT ip FROM monitors WHERE id = $1",
      [3] // ID fixo do computador que tem o IP externo
    );
    
    if (externalIpResult.rows.length === 0) {
      return res.status(500).json({ error: "IP externo não encontrado (computador ID 3 não configurado)" });
    }
    
    const externalIp = externalIpResult.rows[0].ip;
    const wakeUrl = `http://${externalIp}:1880/wakepc`;
    
    console.log(`=== WAKE-ON-LAN DEBUG ===`);
    console.log(`Monitor: ${monitor.name} (ID: ${monitor.id})`);
    console.log(`IP Externo encontrado: ${externalIp}`);
    console.log(`URL Wake: ${wakeUrl}`);
    console.log(`Fazendo requisição POST para: ${wakeUrl}`);
    
    // Fazer requisição para acordar o servidor
    try {
      const response = await new Promise((resolve, reject) => {
        const url = new URL(wakeUrl);
        const options = {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname,
          method: 'POST',
          timeout: 10000
        };
        
        const request = http.request(options, (response) => {
          let data = '';
          response.on('data', (chunk) => {
            data += chunk;
          });
          response.on('end', () => {
            resolve({ status: response.statusCode, data });
          });
        });
        
        request.on('error', (error) => {
          reject(error);
        });
        
        request.on('timeout', () => {
          request.destroy();
          reject(new Error('Request timeout'));
        });
        
        // Finalizar a requisição POST
        request.end();
      });
      
      console.log(`Resposta da requisição wake:`);
      console.log(`Status: ${response.status}`);
      console.log(`Data: ${response.data}`);
      console.log(`=== FIM WAKE DEBUG ===`);
      
      res.json({ 
        message: `Comando de ligar enviado para ${monitor.name}`,
        monitor: {
          id: monitor.id,
          name: monitor.name,
          ip: monitor.ip,
          port: monitor.port
        },
        wakeResponse: response.data,
        wakeUrl: wakeUrl
      });
    } catch (wakeError) {
      console.error("Erro ao enviar comando wake:", wakeError.message);
      res.status(500).json({ 
        error: "Falha ao enviar comando de ligar servidor",
        details: wakeError.message
      });
    }
    
  } catch (error) {
    console.error("Erro na rota wake-server:", error);
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

// ===== SISTEMA DE NOTIFICAÇÕES =====

// Função para criar notificação
async function createNotification(userId, monitorId, type, title, message) {
  try {
    await pool.query(`
      INSERT INTO notifications (user_id, monitor_id, type, title, message)
      VALUES ($1::uuid, $2::uuid, $3, $4, $5)
    `, [userId, monitorId, type, title, message]);
  } catch (error) {
    console.error('Erro ao criar notificação:', error);
  }
}

// Função para obter usuários que devem receber notificação de um monitor
async function getUsersForNotification(monitorId) {
  try {
    const result = await pool.query(`
      SELECT DISTINCT u.id, u.name, u.email, ns.enabled, ns.server_offline, ns.server_online
      FROM users u
      LEFT JOIN notification_settings ns ON u.id = ns.user_id
      LEFT JOIN monitors m ON m.id = $1::integer
      WHERE (
        u.role = 'ADMIN' OR 
        (m.user_id = u.id) OR 
        (m.is_public = true AND u.role IN ('USER', 'VIEWER'))
      )
      AND (ns.enabled IS NULL OR ns.enabled = true)
    `, [monitorId]);
    
    return result.rows;
  } catch (error) {
    console.error('Erro ao buscar usuários para notificação:', error);
    return [];
  }
}

// Função para enviar push notifications
async function sendPushNotification(userId, notificationData) {
  try {
    // Buscar tokens ativos do usuário
    const result = await pool.query(`
      SELECT device_token, device_type 
      FROM push_tokens 
      WHERE user_id = $1::uuid AND is_active = true
    `, [userId]);
    
    if (result.rows.length === 0) {
      console.log(`Nenhum token ativo encontrado para usuário ${userId}`);
      return;
    }
    
    const { title, message, serverId, serverName, status } = notificationData;
    
    // Para cada token ativo, "enviar" notificação
    // Como estamos usando notificações locais, apenas registramos no log
    for (const token of result.rows) {
      console.log(`📱 Push notification enviada:`);
      console.log(`   Usuário: ${userId}`);
      console.log(`   Device: ${token.device_type}`);
      console.log(`   Token: ${token.device_token.substring(0, 20)}...`);
      console.log(`   Título: ${title}`);
      console.log(`   Mensagem: ${message}`);
      console.log(`   Servidor: ${serverName} (${serverId})`);
      console.log(`   Status: ${status}`);
      console.log('   ---');
    }
    
    // Atualizar last_used dos tokens
    await pool.query(`
      UPDATE push_tokens 
      SET last_used = CURRENT_TIMESTAMP 
      WHERE user_id = $1::uuid AND is_active = true
    `, [userId]);
    
  } catch (error) {
    console.error('Erro ao enviar push notification:', error);
  }
}

// Sistema de monitoramento contínuo
async function monitorServers() {
  try {
    const monitors = await pool.query('SELECT * FROM monitors ORDER BY name');
    
    for (const monitor of monitors.rows) {
      try {
        // Verificar status atual do servidor
        const isOnline = await new Promise((resolve) => {
          portscanner.checkPortStatus(monitor.port, monitor.ip, (error, status) => {
            resolve(status === 'open');
          });
        });
        
        const previousStatus = monitor.last_status;
        const statusChanged = previousStatus !== null && previousStatus !== isOnline;
        
        // Atualizar status no banco
        await pool.query(`
          UPDATE monitors 
          SET last_status = $1, last_checked = CURRENT_TIMESTAMP 
          WHERE id = $2
        `, [isOnline, monitor.id]);
        
        // Se houve mudança de status, enviar notificações
        if (statusChanged) {
          const users = await getUsersForNotification(monitor.id);
          const statusText = isOnline ? 'online' : 'offline';
          const emoji = isOnline ? '✅' : '❌';
          
          const title = `Servidor ${statusText.toUpperCase()}`;
          const message = `${emoji} O servidor "${monitor.name}" (${monitor.ip}:${monitor.port}) ficou ${statusText}.`;
          
          for (const user of users) {
            // Verificar configurações do usuário
            const shouldNotify = isOnline ? 
              (user.server_online !== false) : 
              (user.server_offline !== false);
              
            if (shouldNotify) {
              await createNotification(
                user.id, 
                monitor.id, 
                `server_${statusText}`, 
                title, 
                message
              );
              
              // Enviar push notification se habilitado
              if (user.push_notifications !== false) {
                await sendPushNotification(user.id, {
                  title,
                  message,
                  serverId: monitor.id,
                  serverName: monitor.name,
                  status: statusText
                });
              }
            }
          }
          
          console.log(`📡 Notificações enviadas: ${monitor.name} ficou ${statusText}`);
        }
        
      } catch (error) {
        console.error(`Erro ao monitorar ${monitor.name}:`, error);
      }
    }
    
  } catch (error) {
    console.error('Erro no sistema de monitoramento:', error);
  }
}

// Iniciar monitoramento a cada 30 segundos
setInterval(monitorServers, 30000);

// API: Buscar notificações do usuário
app.get("/notifications", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 20, unread_only = false } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT n.*, m.name as monitor_name, m.ip, m.port
      FROM notifications n
      LEFT JOIN monitors m ON n.monitor_id = m.id
      WHERE n.user_id = $1::uuid
    `;
    
    const params = [req.user.userId];
    
    if (unread_only === 'true') {
      query += ` AND n.is_read = false`;
    }
    
    query += ` ORDER BY n.created_at DESC LIMIT $2 OFFSET $3`;
    params.push(limit, offset);
    
    const notifications = await pool.query(query, params);
    
    // Contar total de notificações não lidas
    const unreadCount = await pool.query(`
      SELECT COUNT(*) as count 
      FROM notifications 
      WHERE user_id = $1::uuid AND is_read = false
    `, [req.user.userId]);
    
    res.json({
      notifications: notifications.rows,
      unread_count: parseInt(unreadCount.rows[0].count),
      page: parseInt(page),
      limit: parseInt(limit)
    });
    
  } catch (error) {
    console.error("Erro ao buscar notificações:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// API: Marcar notificação como lida
app.patch("/notifications/:id/read", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(`
      UPDATE notifications 
      SET is_read = true 
      WHERE id = $1::uuid AND user_id = $2::uuid
      RETURNING *
    `, [id, req.user.userId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Notificação não encontrada" });
    }
    
    res.json({ message: "Notificação marcada como lida" });
    
  } catch (error) {
    console.error("Erro ao marcar notificação:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// API: Marcar todas as notificações como lidas
app.patch("/notifications/read-all", authenticateToken, async (req, res) => {
  try {
    await pool.query(`
      UPDATE notifications 
      SET is_read = true 
      WHERE user_id = $1::uuid AND is_read = false
    `, [req.user.userId]);
    
    res.json({ message: "Todas as notificações foram marcadas como lidas" });
    
  } catch (error) {
    console.error("Erro ao marcar todas as notificações:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// API: Configurações de notificação do usuário
app.get("/notification-settings", authenticateToken, async (req, res) => {
  try {
    let settings = await pool.query(`
      SELECT * FROM notification_settings WHERE user_id = $1::uuid
    `, [req.user.userId]);
    
    // Se não existir, criar configuração padrão
    if (settings.rows.length === 0) {
      await pool.query(`
        INSERT INTO notification_settings (user_id) VALUES ($1::uuid)
      `, [req.user.userId]);
      
      settings = await pool.query(`
        SELECT * FROM notification_settings WHERE user_id = $1::uuid
      `, [req.user.userId]);
    }
    
    res.json(settings.rows[0]);
    
  } catch (error) {
    console.error("Erro ao buscar configurações:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// API: Atualizar configurações de notificação
app.patch("/notification-settings", authenticateToken, async (req, res) => {
  try {
    const { enabled, server_offline, server_online, push_notifications } = req.body;
    
    const result = await pool.query(`
      UPDATE notification_settings 
      SET enabled = COALESCE($2, enabled),
          server_offline = COALESCE($3, server_offline),
          server_online = COALESCE($4, server_online),
          push_notifications = COALESCE($5, push_notifications),
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $1::uuid
      RETURNING *
    `, [req.user.userId, enabled, server_offline, server_online, push_notifications]);
    
    if (result.rows.length === 0) {
      // Criar se não existir
      await pool.query(`
        INSERT INTO notification_settings (user_id, enabled, server_offline, server_online, push_notifications)
        VALUES ($1::uuid, $2, $3, $4, $5)
      `, [req.user.userId, enabled ?? true, server_offline ?? true, server_online ?? true, push_notifications ?? true]);
    }
    
    res.json({ message: "Configurações atualizadas com sucesso" });
    
  } catch (error) {
    console.error("Erro ao atualizar configurações:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// ===== APIS DE PUSH NOTIFICATIONS =====

// API: Registrar token de push notification
app.post("/push-token", authenticateToken, async (req, res) => {
  try {
    const { device_token, device_type = 'unknown', device_name, app_version } = req.body;
    
    if (!device_token) {
      return res.status(400).json({ error: "Token do dispositivo é obrigatório" });
    }
    
    // Verificar se o token já existe para este usuário
    const existingToken = await pool.query(`
      SELECT id FROM push_tokens 
      WHERE user_id = $1::uuid AND device_token = $2
    `, [req.user.userId, device_token]);
    
    if (existingToken.rows.length > 0) {
      // Atualizar token existente
      await pool.query(`
        UPDATE push_tokens 
        SET device_type = $3,
            device_name = $4,
            app_version = $5,
            is_active = TRUE,
            last_used = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = $1::uuid AND device_token = $2
      `, [req.user.userId, device_token, device_type, device_name, app_version]);
      
      res.json({ message: "Token atualizado com sucesso" });
    } else {
      // Criar novo token
      await pool.query(`
        INSERT INTO push_tokens (user_id, device_token, device_type, device_name, app_version)
        VALUES ($1::uuid, $2, $3, $4, $5)
      `, [req.user.userId, device_token, device_type, device_name, app_version]);
      
      res.json({ message: "Token registrado com sucesso" });
    }
    
  } catch (error) {
    console.error("Erro ao registrar token:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// API: Remover token de push notification (logout)
app.delete("/push-token", authenticateToken, async (req, res) => {
  try {
    const { device_token } = req.body;
    
    if (!device_token) {
      return res.status(400).json({ error: "Token do dispositivo é obrigatório" });
    }
    
    await pool.query(`
      UPDATE push_tokens 
      SET is_active = FALSE,
          updated_at = CURRENT_TIMESTAMP
      WHERE user_id = $1::uuid AND device_token = $2
    `, [req.user.userId, device_token]);
    
    res.json({ message: "Token removido com sucesso" });
    
  } catch (error) {
    console.error("Erro ao remover token:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// API: Listar tokens do usuário (para debug)
app.get("/push-tokens", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT device_token, device_type, device_name, app_version, is_active, last_used, created_at
      FROM push_tokens 
      WHERE user_id = $1::uuid
      ORDER BY last_used DESC
    `, [req.user.userId]);
    
    res.json(result.rows);
    
  } catch (error) {
    console.error("Erro ao buscar tokens:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
