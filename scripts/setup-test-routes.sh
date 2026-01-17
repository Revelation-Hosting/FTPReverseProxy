#!/bin/bash
# Setup test routes for end-to-end testing
# Run this after docker-compose.test.yml is up and running

API_URL="http://localhost:8080"

echo "Waiting for API to be ready..."
MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    HEALTH=$(curl -s "$API_URL/health" 2>/dev/null)
    if echo "$HEALTH" | grep -q '"status":"healthy"'; then
        echo "API is healthy!"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    echo "Waiting for API... ($RETRY_COUNT/$MAX_RETRIES)"
    sleep 2
done

if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
    echo "ERROR: API did not become healthy in time"
    exit 1
fi

echo ""
echo "Creating test backend server..."

BACKEND_RESPONSE=$(curl -s -X POST "$API_URL/api/backends" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "test-ftp",
        "host": "test-ftp-server",
        "port": 21,
        "protocol": 0,
        "credentialMapping": 0,
        "isEnabled": true,
        "description": "Test FTP server for e2e testing",
        "connectionTimeoutMs": 30000
    }')

if echo "$BACKEND_RESPONSE" | grep -q '"error"'; then
    echo "Backend may already exist, fetching..."
    BACKENDS=$(curl -s "$API_URL/api/backends")
    BACKEND_ID=$(echo "$BACKENDS" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
else
    BACKEND_ID=$(echo "$BACKEND_RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
fi

echo "Using backend ID: $BACKEND_ID"

echo ""
echo "Creating test route mapping..."

ROUTE_RESPONSE=$(curl -s -X POST "$API_URL/api/routes" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"testuser\",
        \"backendServerId\": \"$BACKEND_ID\",
        \"isEnabled\": true,
        \"priority\": 100,
        \"description\": \"Test route for testuser\"
    }")

echo "Route response: $ROUTE_RESPONSE"

echo ""
echo "========================================="
echo "Test setup complete!"
echo ""
echo "To test FTP proxy:"
echo "  1. Connect: ftp localhost 21"
echo "  2. Login: USER testuser"
echo "  3. Password: PASS testpass"
echo ""
echo "Or use curl:"
echo "  curl ftp://testuser:testpass@localhost/"
echo "========================================="
