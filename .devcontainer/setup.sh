#!/bin/bash
set -e

echo "=========================================="
echo "  APIGuardian - Codespace Setup"
echo "=========================================="

# Create /app symlink for compatibility
echo "[1/5] Creating /app symlink..."
sudo ln -sf /workspaces/api10 /app

# Install Python dependencies
echo "[2/5] Installing Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Setup environment file
echo "[3/5] Setting up environment..."
if [ ! -f backend/.env ]; then
    cp backend/.env.example backend/.env
    echo "Created .env from template"
else
    echo ".env already exists"
fi

# Initialize database (if needed)
echo "[4/5] Checking database..."
if [ ! -f backend/apiguardian.db ]; then
    echo "Database will be created on first run"
else
    echo "Database exists"
fi

# Create run script for convenience
echo "[5/5] Creating convenience scripts..."
cat > /workspaces/api10/start.sh << 'EOF'
#!/bin/bash
cd /workspaces/api10/backend
echo "Starting APIGuardian on http://localhost:8001"
python server.py
EOF
chmod +x /workspaces/api10/start.sh

cat > /workspaces/api10/test.sh << 'EOF'
#!/bin/bash
cd /workspaces/api10
python -m pytest tests/ -v
EOF
chmod +x /workspaces/api10/test.sh

echo ""
echo "=========================================="
echo "  Setup Complete!"
echo "=========================================="
echo ""
echo "Quick commands:"
echo "  ./start.sh    - Start the server"
echo "  ./test.sh     - Run tests"
echo ""
echo "Dashboard: http://localhost:8001"
echo "=========================================="
