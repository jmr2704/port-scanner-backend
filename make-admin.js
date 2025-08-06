import pkg from "pg";
const { Pool } = pkg;

// Configuração do Postgres
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function makeFirstUserAdmin() {
  try {
    console.log('🔍 Buscando primeiro usuário...');
    
    // Buscar o primeiro usuário (por data de criação)
    const result = await pool.query(`
      SELECT id, email, name, role 
      FROM users 
      ORDER BY created_at ASC 
      LIMIT 1
    `);
    
    if (result.rows.length === 0) {
      console.log('❌ Nenhum usuário encontrado no banco de dados');
      return;
    }
    
    const user = result.rows[0];
    console.log(`👤 Primeiro usuário encontrado: ${user.name} (${user.email})`);
    console.log(`📋 Role atual: ${user.role}`);
    
    if (user.role === 'ADMIN') {
      console.log('✅ Usuário já é ADMIN!');
      return;
    }
    
    // Alterar role para ADMIN
    await pool.query(`
      UPDATE users 
      SET role = 'ADMIN' 
      WHERE id = $1
    `, [user.id]);
    
    console.log('🎉 Usuário alterado para ADMIN com sucesso!');
    console.log(`👑 ${user.name} agora é administrador`);
    
  } catch (error) {
    console.error('❌ Erro ao alterar usuário:', error);
  } finally {
    await pool.end();
  }
}

// Executar se chamado diretamente
if (import.meta.url === `file://${process.argv[1]}`) {
  makeFirstUserAdmin();
}

export default makeFirstUserAdmin;
