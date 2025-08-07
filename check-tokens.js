const { Pool } = require('pg');

// Configuração do banco
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://username:password@localhost:5432/dbname',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function checkTokens() {
  try {
    console.log('🔍 Verificando tokens de push...\n');
    
    // Buscar tokens ativos
    const tokens = await pool.query(`
      SELECT pt.*, u.name, u.email 
      FROM push_tokens pt 
      JOIN users u ON pt.user_id = u.id 
      WHERE pt.is_active = true 
      ORDER BY pt.created_at DESC
    `);
    
    console.log(`📱 Total de tokens ativos: ${tokens.rows.length}\n`);
    
    if (tokens.rows.length === 0) {
      console.log('⚠️ Nenhum token ativo encontrado!');
      console.log('💡 Faça login no app para registrar um token.\n');
      return;
    }
    
    tokens.rows.forEach((token, index) => {
      console.log(`${index + 1}. 👤 ${token.name} (${token.email})`);
      console.log(`   📱 Device: ${token.device_type}`);
      console.log(`   🔑 Token: ${token.device_token.substring(0, 30)}...`);
      console.log(`   📅 Criado: ${new Date(token.created_at).toLocaleString('pt-BR')}`);
      console.log(`   🔄 Usado: ${new Date(token.last_used).toLocaleString('pt-BR')}`);
      console.log('');
    });
    
    // Verificar notificações recentes
    const notifications = await pool.query(`
      SELECT n.*, u.name 
      FROM notifications n 
      JOIN users u ON n.user_id = u.id 
      ORDER BY n.created_at DESC 
      LIMIT 5
    `);
    
    console.log(`🔔 Últimas ${notifications.rows.length} notificações:`);
    notifications.rows.forEach((notif, index) => {
      console.log(`${index + 1}. ${notif.title} → ${notif.name}`);
      console.log(`   📝 ${notif.message}`);
      console.log(`   📅 ${new Date(notif.created_at).toLocaleString('pt-BR')}`);
      console.log('');
    });
    
  } catch (error) {
    console.error('❌ Erro:', error.message);
  } finally {
    await pool.end();
  }
}

checkTokens();
