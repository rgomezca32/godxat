// src/config.js
const configs = {
  development: {
    apiUrl: 'http://localhost:8000',
    wsUrl: 'ws://localhost:8000/ws',
  },
  production: {
    apiUrl: 'https://godxat-api.onrender.com', // URL del backend en Render.com
    wsUrl: 'wss://godxat-api.onrender.com/ws', // URL de WebSocket en Render.com
  }
};

// Determinar entorno actual
const currentEnv = import.meta.env.MODE || 'production';

export default configs[currentEnv];