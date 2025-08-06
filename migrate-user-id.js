const { Pool } = require('pg');

// Configuração do banco (use suas variáveis de ambiente)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function addUserIdColumn() {
  const client = await pool.connect();
  
  try {
    console.log('🔄 Iniciando migração...');
    
    // Verificar se a coluna já existe
    const checkColumn = await client.query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name = 'monitors' AND column_name = 'user_id'
    `);
    
    if (checkColumn.rows.length > 0) {
      console.log('✅ Coluna user_id já existe na tabela monitors');
      return;
    }
    
    // Verificar o tipo da coluna id na tabela users
    const userIdType = await client.query(`
      SELECT data_type 
      FROM information_schema.columns 
      WHERE table_name = 'users' AND column_name = 'id'
    `);
    
    const idType = userIdType.rows[0]?.data_type || 'integer';
    console.log(`📋 Tipo do id da tabela users: ${idType}`);
    
    // Adicionar coluna user_id com o tipo correto
    if (idType === 'integer' || idType === 'bigint') {
      await client.query('ALTER TABLE monitors ADD COLUMN user_id INTEGER');
    } else {
      // Para UUID ou outros tipos string
      await client.query('ALTER TABLE monitors ADD COLUMN user_id VARCHAR(255)');
    }
    console.log('✅ Coluna user_id adicionada à tabela monitors');
    
    // Criar índice para performance
    await client.query('CREATE INDEX idx_monitors_user_id ON monitors(user_id)');
    console.log('✅ Índice criado para user_id');
    
    // Opcional: definir um valor padrão para registros existentes
    const existingMonitors = await client.query('SELECT COUNT(*) FROM monitors WHERE user_id IS NULL');
    if (existingMonitors.rows[0].count > 0) {
      console.log(`📝 Encontrados ${existingMonitors.rows[0].count} monitors sem user_id`);
      console.log('💡 Você pode definir um user_id padrão ou deixar como NULL');
      
      // Descomente a linha abaixo se quiser definir user_id = 1 para todos os registros existentes
      // await client.query('UPDATE monitors SET user_id = 1 WHERE user_id IS NULL');
      // console.log('✅ user_id padrão definido para registros existentes');
    }
    
    console.log('🎉 Migração concluída com sucesso!');
    
  } catch (error) {
    console.error('❌ Erro na migração:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Executar migração
addUserIdColumn()
  .then(() => {
    console.log('✅ Script executado com sucesso');
    process.exit(0);
  })
  .catch((error) => {
    console.error('❌ Erro ao executar script:', error);
    process.exit(1);
  });
