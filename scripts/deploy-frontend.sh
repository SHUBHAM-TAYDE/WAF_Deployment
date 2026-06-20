#!/bin/bash
set -e

echo "=== CyberSentinel static UI deployment script ==="
echo "Copying site configuration..."
sudo cp /home/soc/.gemini/antigravity-ide/brain/4f872ac7-c11e-4da1-9006-1ad1c69ef10d/cybersentinel.nginx /etc/nginx/sites-available/cybersentinel

echo "Verifying OpenResty configuration syntax..."
sudo openresty -t

echo "Reloading OpenResty service..."
sudo systemctl reload openresty

echo "=== Deployment successful! ==="
