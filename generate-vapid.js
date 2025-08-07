import webpush from 'web-push';

console.log('🔑 Gerando chaves VAPID para Web Push...\n');

const keys = webpush.generateVAPIDKeys();

console.log('\n📋 Adicione essas variáveis ao seu .env:');
console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
console.log(`VAPID_EMAIL=jeffmr2704@gmail.com`);

console.log('\n✅ Chaves geradas com sucesso!');
console.log('\n🔑 Chaves VAPID:');
console.log('Public Key:', keys.publicKey);
console.log('Private Key:', keys.privateKey);
