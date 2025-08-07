import apn from 'node-apn';
import webpush from 'web-push';
import dotenv from 'dotenv';

// Carregar variáveis de ambiente
dotenv.config();

class PushNotificationService {
  constructor() {
    this.apnProvider = null;
    this.initialized = false;
  }

  // Inicializar serviços de push
  async init() {
    if (this.initialized) return;

    try {
      console.log('🚀 Inicializando serviços de push notifications...');

      // Configurar APNs para iOS (quando tivermos certificados)
      // this.setupAPNs();

      // Configurar Web Push para Android
      this.setupWebPush();

      this.initialized = true;
      console.log('✅ Serviços de push inicializados');
    } catch (error) {
      console.error('❌ Erro ao inicializar push services:', error);
    }
  }

  // Configurar APNs para iOS
  setupAPNs() {
    try {
      // Configuração para produção (quando tivermos certificados)
      const options = {
        token: {
          key: process.env.APNS_KEY_PATH || './certs/AuthKey.p8',
          keyId: process.env.APNS_KEY_ID || 'your-key-id',
          teamId: process.env.APNS_TEAM_ID || 'your-team-id'
        },
        production: process.env.NODE_ENV === 'production'
      };

      this.apnProvider = new apn.Provider(options);
      console.log('📱 APNs configurado para iOS');
    } catch (error) {
      console.error('❌ Erro ao configurar APNs:', error);
    }
  }

  // Configurar Web Push para Android
  setupWebPush() {
    try {
      const publicKey = process.env.VAPID_PUBLIC_KEY;
      const privateKey = process.env.VAPID_PRIVATE_KEY;
      const email = process.env.VAPID_EMAIL || 'jeffmr2704@gmail.com';

      if (!publicKey || !privateKey) {
        console.log('⚠️ Chaves VAPID não encontradas no .env');
        return;
      }

      webpush.setVapidDetails(
        `mailto:${email}`,
        publicKey,
        privateKey
      );

      console.log('🤖 Web Push configurado com chaves VAPID');
      console.log(`   Email: ${email}`);
      console.log(`   Public Key: ${publicKey.substring(0, 20)}...`);
    } catch (error) {
      console.error('❌ Erro ao configurar Web Push:', error);
    }
  }

  // Enviar push notification para iOS
  async sendToiOS(deviceToken, notification) {
    if (!this.apnProvider) {
      console.log('⚠️ APNs não configurado, pulando iOS push');
      return false;
    }

    try {
      const note = new apn.Notification();
      note.expiry = Math.floor(Date.now() / 1000) + 3600; // Expira em 1 hora
      note.badge = 1;
      note.sound = 'ping.aiff';
      note.alert = {
        title: notification.title,
        body: notification.message
      };
      note.payload = {
        serverId: notification.serverId,
        serverName: notification.serverName,
        status: notification.status
      };
      note.topic = process.env.IOS_BUNDLE_ID || 'com.yourapp.monitorapp';

      const result = await this.apnProvider.send(note, deviceToken);
      
      if (result.sent.length > 0) {
        console.log('✅ Push enviado para iOS:', deviceToken.substring(0, 20) + '...');
        return true;
      } else {
        console.log('❌ Falha ao enviar para iOS:', result.failed);
        return false;
      }
    } catch (error) {
      console.error('❌ Erro ao enviar push iOS:', error);
      return false;
    }
  }

  // Enviar push notification para Android
  async sendToAndroid(deviceToken, notification) {
    try {
      const payload = JSON.stringify({
        title: notification.title,
        body: notification.message,
        icon: '/icon-192x192.png',
        badge: '/badge-72x72.png',
        data: {
          serverId: notification.serverId,
          serverName: notification.serverName,
          status: notification.status,
          url: '/'
        }
      });

      const result = await webpush.sendNotification(
        {
          endpoint: deviceToken,
          keys: {
            p256dh: 'user-p256dh-key',
            auth: 'user-auth-key'
          }
        },
        payload
      );

      console.log('✅ Push enviado para Android');
      return true;
    } catch (error) {
      console.error('❌ Erro ao enviar push Android:', error);
      return false;
    }
  }

  // Método principal para enviar push
  async sendPushNotification(deviceToken, deviceType, notification) {
    if (!this.initialized) {
      await this.init();
    }

    console.log(`📱 Enviando push notification:`);
    console.log(`   Device: ${deviceType}`);
    console.log(`   Token: ${deviceToken.substring(0, 30)}...`);
    console.log(`   Título: ${notification.title}`);
    console.log(`   Mensagem: ${notification.message}`);

    try {
      let success = false;

      if (deviceType === 'ios') {
        success = await this.sendToiOS(deviceToken, notification);
      } else if (deviceType === 'android') {
        success = await this.sendToAndroid(deviceToken, notification);
      } else {
        console.log('⚠️ Tipo de device desconhecido:', deviceType);
      }

      if (success) {
        console.log('🎉 Push notification enviada com sucesso!');
      } else {
        console.log('⚠️ Push notification falhou');
      }

      return success;
    } catch (error) {
      console.error('❌ Erro geral ao enviar push:', error);
      return false;
    }
  }

  // Gerar chaves VAPID para Web Push
  generateVapidKeys() {
    const vapidKeys = webpush.generateVAPIDKeys();
    console.log('🔑 Chaves VAPID geradas:');
    console.log('Public Key:', vapidKeys.publicKey);
    console.log('Private Key:', vapidKeys.privateKey);
    return vapidKeys;
  }
}

// Singleton
const pushService = new PushNotificationService();

export default pushService;
