const { Pool } = require('pg');

// Configuração do banco (mesma do server.js)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function checkTables() {
  try {
    console.log('🔍 Verificando estrutura das tabelas...\n');

    // Verificar tabela users
    console.log('📋 TABELA USERS:');
    const usersInfo = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_name = 'users'
      ORDER BY ordinal_position;
    `);
    
    if (usersInfo.rows.length === 0) {
      console.log('❌ Tabela users não encontrada!');
    } else {
      usersInfo.rows.forEach(row => {
        console.log(`  ${row.column_name}: ${row.data_type} ${row.is_nullable === 'NO' ? '(NOT NULL)' : '(NULLABLE)'} ${row.column_default ? `DEFAULT ${row.column_default}` : ''}`);
      });
    }

    console.log('\n📋 TABELA MONITORS:');
    const monitorsInfo = await pool.query(`
      SELECT column_name, data_type, is_nullable, column_default
      FROM information_schema.columns 
      WHERE table_name = 'monitors'
      ORDER BY ordinal_position;
    `);
    
    if (monitorsInfo.rows.length === 0) {
      console.log('❌ Tabela monitors não encontrada!');
    } else {
      monitorsInfo.rows.forEach(row => {
        console.log(`  ${row.column_name}: ${row.data_type} ${row.is_nullable === 'NO' ? '(NOT NULL)' : '(NULLABLE)'} ${row.column_default ? `DEFAULT ${row.column_default}` : ''}`);
      });
    }

    // Verificar se há dados nas tabelas
    console.log('\n📊 CONTAGEM DE REGISTROS:');
    
    try {
      const usersCount = await pool.query('SELECT COUNT(*) FROM users');
      console.log(`  Users: ${usersCount.rows[0].count} registros`);
    } catch (error) {
      console.log(`  Users: Erro ao contar - ${error.message}`);
    }

    try {
      const monitorsCount = await pool.query('SELECT COUNT(*) FROM monitors');
      console.log(`  Monitors: ${monitorsCount.rows[0].count} registros`);
    } catch (error) {
      console.log(`  Monitors: Erro ao contar - ${error.message}`);
    }

    // Verificar tipos específicos que podem estar causando problema
    console.log('\n🔍 VERIFICAÇÃO DE COMPATIBILIDADE:');
    
    try {
      const typeCheck = await pool.query(`
        SELECT 
          u.data_type as users_id_type,
          m.data_type as monitors_user_id_type,
          CASE 
            WHEN u.data_type = m.data_type THEN '✅ COMPATÍVEL'
            ELSE '❌ INCOMPATÍVEL'
          END as compatibility
        FROM information_schema.columns u
        CROSS JOIN information_schema.columns m
        WHERE u.table_name = 'users' AND u.column_name = 'id'
        AND m.table_name = 'monitors' AND m.column_name = 'user_id';
      `);
      
      if (typeCheck.rows.length > 0) {
        const result = typeCheck.rows[0];
        console.log(`  users.id: ${result.users_id_type}`);
        console.log(`  monitors.user_id: ${result.monitors_user_id_type}`);
        console.log(`  Status: ${result.compatibility}`);
      }
    } catch (error) {
      console.log(`  Erro na verificação: ${error.message}`);
    }

    // Verificar se coluna is_public existe
    console.log('\n🌍 VERIFICAÇÃO COLUNA IS_PUBLIC:');
    const isPublicExists = monitorsInfo.rows.find(row => row.column_name === 'is_public');
    if (isPublicExists) {
      console.log(`  ✅ Coluna is_public existe: ${isPublicExists.data_type}`);
    } else {
      console.log('  ❌ Coluna is_public NÃO existe!');
    }

  } catch (error) {
    console.error('❌ Erro ao verificar tabelas:', error);
  } finally {
    await pool.end();
  }
}

checkTables();
