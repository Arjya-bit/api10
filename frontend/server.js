const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

const backendProxy = createProxyMiddleware({
    target: 'http://localhost:8001',
    changeOrigin: true,
    logLevel: 'debug',
    onProxyReq: (proxyReq, req, res) => {
        console.log(`Proxying: ${req.method} ${req.url} -> ${proxyReq.path}`);
    }
});

const wsProxy = createProxyMiddleware({
    target: 'http://localhost:8001',
    changeOrigin: true,
    ws: true
});

// Proxy API routes
app.use('/api', backendProxy);
app.use('/ws', wsProxy);
app.use('/health', backendProxy);

// Serve static files
app.use(express.static(path.join(__dirname, 'build')));

// Fallback
app.get(/.*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Frontend server running on port ${PORT}`);
});
