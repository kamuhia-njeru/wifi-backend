require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const WebSocket = require('ws');
const app = express();

// **🔐 Configuration**
const PORT = process.env.PORT || 3001;
const ROUTER_IP = process.env.ROUTER_IP || '192.168.0.1';
const ROUTER_USERNAME = process.env.ROUTER_USERNAME || 'pat';
const ROUTER_PASSWORD = process.env.ROUTER_PASSWORD || '1758000pA';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://wifi-green.vercel.app';
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');
const WS_PORT = process.env.WS_PORT || 8080;

// **🛡️ Middleware**
app.use(helmet());
app.use(cors({
  origin: FRONTEND_URL,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(morgan('combined'));

// **⏱️ Rate Limiting**
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// **🔒 Authentication Middleware**
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || authHeader !== `Bearer ${AUTH_SECRET}`) {
    return res.status(401).json({ 
      error: 'Unauthorized',
      message: 'Invalid or missing authentication token'
    });
  }
  next();
};

// **📡 WebSocket Server (For Real-Time Notifications)**
const wss = new WebSocket.Server({ port: WS_PORT });
const connectedClients = new Set();

wss.on('connection', (ws) => {
  connectedClients.add(ws);
  ws.on('close', () => connectedClients.delete(ws));
});

// **📨 Broadcast Notification to All Connected Clients**
const broadcastNotification = (message) => {
  connectedClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  });
};

// **🔄 Tenda Router API Client (Production-Grade)**
class TendaRouterClient {
  constructor() {
    this.sessionCookie = null;
    this.lastAuthTime = 0;
    this.authTimeout = 300000; // 5 minutes
    this.retryCount = 0;
    this.maxRetries = 3;
  }

  async authenticate() {
    try {
      const authUrl = `http://${ROUTER_IP}/login/Auth`;
      const response = await axios.post(authUrl, {
        username: ROUTER_USERNAME,
        password: ROUTER_PASSWORD
      }, {
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400,
        timeout: 5000
      });

      const cookies = response.headers['set-cookie'];
      if (!cookies || cookies.length === 0) {
        throw new Error('No session cookie received');
      }

      this.sessionCookie = cookies[0].split(';')[0];
      this.lastAuthTime = Date.now();
      this.retryCount = 0;
      return true;
    } catch (error) {
      this.retryCount++;
      console.error(`Authentication attempt ${this.retryCount} failed:`, error.message);
      
      if (this.retryCount >= this.maxRetries) {
        throw new Error(`Failed to authenticate after ${this.maxRetries} attempts`);
      }
      
      await new Promise(resolve => setTimeout(resolve, 2000));
      return this.authenticate();
    }
  }

  async ensureAuthenticated() {
    if (!this.sessionCookie || (Date.now() - this.lastAuthTime) > this.authTimeout) {
      await this.authenticate();
    }
  }

  async getConnectedDevices() {
    await this.ensureAuthenticated();
    
    try {
      const response = await axios.get(`http://${ROUTER_IP}/getClientList`, {
        headers: { Cookie: this.sessionCookie },
        timeout: 10000
      });

      if (!response.data || !response.data.clientList) {
        throw new Error('Invalid response format from router');
      }

      return response.data.clientList.map(client => ({
        id: client.mac.replace(/:/g, '').toLowerCase(),
        name: client.hostname || `Device_${client.mac.slice(-6)}`,
        ip: client.ip,
        mac: client.mac,
        connection: client.type === '0' ? 'WiFi' : 'Ethernet',
        status: client.online === '1' ? 'online' : 'offline',
        type: this.classifyDevice(client.hostname || client.mac),
        lastSeen: new Date().toISOString(),
        signalStrength: client.signal || null,
        connectionTime: client.uptime || null
      }));
    } catch (error) {
      console.error('Error fetching devices:', error.message);
      throw new Error('Failed to retrieve connected devices');
    }
  }

  async getNetworkStats() {
    await this.ensureAuthenticated();
    
    try {
      const [trafficResponse, wifiResponse] = await Promise.all([
        axios.get(`http://${ROUTER_IP}/getTraffic`, {
          headers: { Cookie: this.sessionCookie },
          timeout: 5000
        }),
        axios.get(`http://${ROUTER_IP}/getWifiConfig`, {
          headers: { Cookie: this.sessionCookie },
          timeout: 5000
        })
      ]);

      return {
        download: trafficResponse.data.downstream || 0,
        upload: trafficResponse.data.upstream || 0,
        wifiClients: wifiResponse.data.staCount || 0,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error fetching network stats:', error.message);
      throw new Error('Failed to retrieve network statistics');
    }
  }

  async getNetworkInfo() {
    await this.ensureAuthenticated();
    
    try {
      const [statusResponse, systemResponse] = await Promise.all([
        axios.get(`http://${ROUTER_IP}/getStatus`, {
          headers: { Cookie: this.sessionCookie },
          timeout: 5000
        }),
        axios.get(`http://${ROUTER_IP}/getSystemInfo`, {
          headers: { Cookie: this.sessionCookie },
          timeout: 5000
        })
      ]);

      return {
        uptime: statusResponse.data.uptime || 0,
        firmwareVersion: systemResponse.data.fwVersion || 'unknown',
        model: systemResponse.data.model || 'Tenda Router',
        wifiStatus: statusResponse.data.wifi === '1' ? 'enabled' : 'disabled',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error fetching network info:', error.message);
      throw new Error('Failed to retrieve network information');
    }
  }

  classifyDevice(deviceName) {
    const lowerName = (deviceName || '').toLowerCase();
    if (/iphone|android|mobile|phone/i.test(lowerName)) return 'phone';
    if (/ipad|tablet/i.test(lowerName)) return 'tablet';
    if (/laptop|macbook|notebook/i.test(lowerName)) return 'laptop';
    if (/tv|smarttv|roku|firetv/i.test(lowerName)) return 'tv';
    if (/printer|hp|epson/i.test(lowerName)) return 'printer';
    if (/tenda|router|ap/i.test(lowerName)) return 'router';
    return 'unknown';
  }
}

const router = new TendaRouterClient();

// **📡 API Endpoints**

// **🌐 Health Check**
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    router: {
      type: 'Tenda',
      ip: ROUTER_IP,
      connected: !!router.sessionCookie
    }
  });
});

// **📱 Get Connected Devices**
app.get('/api/devices', authenticate, async (req, res) => {
  try {
    const devices = await router.getConnectedDevices();
    res.json(devices);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      details: 'Failed to fetch connected devices from router'
    });
  }
});

// **📊 Get Network Stats**
app.get('/api/stats', authenticate, async (req, res) => {
  try {
    const stats = await router.getNetworkStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      details: 'Failed to fetch network statistics from router'
    });
  }
});

// **ℹ️ Get Network Info**
app.get('/api/network', authenticate, async (req, res) => {
  try {
    const info = await router.getNetworkInfo();
    res.json(info);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      details: 'Failed to fetch network information from router'
    });
  }
});

// **📨 Send Message to Device (With Dark Mode UI Support)**
app.post('/api/message', authenticate, async (req, res) => {
  try {
    const { deviceId, type, content, theme = 'dark' } = req.body;
    
    if (!deviceId || !content) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // **🎨 Dark Mode UI Support (Red/Green Notifications)**
    const notification = {
      type: 'notification',
      theme: theme === 'dark' ? 'dark' : 'light',
      color: type === 'alert' ? 'red' : 'green',
      deviceId,
      content,
      timestamp: new Date().toISOString()
    };

    // **📢 Broadcast to WebSocket Clients**
    broadcastNotification(notification);

    // **📝 Log the message (In production, integrate with a real delivery system)**
    console.log(`Message sent to ${deviceId}:`, notification);

    res.json({
      success: true,
      message: 'Notification sent successfully',
      notification
    });
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      details: 'Failed to send message to device'
    });
  }
});

// **⚡ WebSocket Endpoint for Real-Time Updates**
app.get('/api/ws', (req, res) => {
  res.json({
    wsEndpoint: `ws://your-render-url:${WS_PORT}`
  });
});

// **🚨 Error Handling Middleware**
app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ 
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// **🚀 Start HTTP & WebSocket Servers**
const server = app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌐 WebSocket server running on port ${WS_PORT}`);
  
  try {
    await router.authenticate();
    console.log('🔑 Successfully authenticated with Tenda router');
  } catch (error) {
    console.error('❌ Failed to connect to Tenda router:', error.message);
  }
});

// **🛑 Graceful Shutdown**
process.on('SIGTERM', () => {
  console.log('🔻 SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('🛑 Server closed');
    process.exit(0);
  });
});
