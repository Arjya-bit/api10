const express = require('express');
const http = require('http');
const httpProxy = require('http-proxy');
const path = require('path');
const fs = require('fs');

// Load environment variables
require('dotenv').config();

const app = express();

// Backend URL from environment variable (defaults to localhost for development)
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8001';
console.log(`Backend URL: ${BACKEND_URL}`);

// Create proxy server
const proxy = httpProxy.createProxyServer({});

// Handle proxy errors
proxy.on('error', (err, req, res) => {
    console.error('Proxy error:', err);
    if (res.writeHead) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Proxy error');
    }
});

// Manually route /api/* and /ws/* to backend
app.use((req, res, next) => {
    if (req.url.startsWith('/api/') || req.url.startsWith('/ws/') || req.url === '/health') {
        console.log(`Proxying: ${req.method} ${req.url}`);
        proxy.web(req, res, { target: BACKEND_URL });
    } else {
        next();
    }
});

// Serve static files
app.use(express.static(path.join(__dirname, 'build')));

// Fallback to index.html
app.get(/.*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

const server = http.createServer(app);

// Handle WebSocket upgrade
server.on('upgrade', (req, socket, head) => {
    if (req.url.startsWith('/ws/')) {
        console.log(`WS Upgrade: ${req.url}`);
        proxy.ws(req, socket, head, { target: BACKEND_URL });
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Frontend server running on port ${PORT}`);
});
