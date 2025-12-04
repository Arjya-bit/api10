const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const path = require('path');

const app = express();

// Proxy /api to backend - preserve the /api prefix
app.use('/api', createProxyMiddleware({
    target: 'http://localhost:8001',
    changeOrigin: true,
    pathRewrite: null  // Don't rewrite paths, keep /api prefix
}));

// Proxy /ws to backend for WebSocket
app.use('/ws', createProxyMiddleware({
    target: 'http://localhost:8001',
    changeOrigin: true,
    ws: true
}));

// Proxy root health endpoint to backend
app.use('/health', createProxyMiddleware({
    target: 'http://localhost:8001',
    changeOrigin: true
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'build')));

// Fallback to index.html for SPA - use regex to avoid path-to-regexp issues
app.get(/.*/, (req, res) => {
    res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Frontend server running on port ${PORT}`);
});
