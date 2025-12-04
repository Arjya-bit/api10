const express = require('express');
const http = require('http');
const httpProxy = require('http-proxy');
const path = require('path');
const fs = require('fs');

const app = express();

// Create proxy server
const proxy = httpProxy.createProxyServer({});

// Handle proxy errors
proxy.on('error', (err, req, res) => {
    console.error('Proxy error:', err);
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end('Proxy error');
});

// Manually route /api/* and /ws/* to backend
app.use((req, res, next) => {
    if (req.url.startsWith('/api/') || req.url.startsWith('/ws/') || req.url === '/health') {
        console.log(`Proxying: ${req.method} ${req.url}`);
        proxy.web(req, res, { target: 'http://localhost:8001' });
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
        proxy.ws(req, socket, head, { target: 'http://localhost:8001' });
    }
});

const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Frontend server running on port ${PORT}`);
});
