const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

// Don't use app.use('/api', ...) as it strips the /api prefix
// Instead, use a filter function that checks the path
const apiProxy = createProxyMiddleware({
    target: 'http://localhost:8001',
    changeOrigin: true,
    // Match any path starting with /api, /ws, or /health
    pathFilter: ['/api/**', '/ws/**', '/health'],
    ws: true,
    onProxyReq: (proxyReq, req, res) => {
        console.log(`Proxy: ${req.method} ${req.originalUrl}`);
    }
});

// Use the proxy for matching routes
app.use(apiProxy);

// Serve static files
app.use(express.static(path.join(__dirname, 'build')));

// Fallback to index.html for SPA
app.get(/.*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Frontend server running on port ${PORT}`);
});
