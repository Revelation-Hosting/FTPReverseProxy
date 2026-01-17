# Setup test routes for end-to-end testing
# Run this after docker-compose.test.yml is up and running

$apiUrl = "http://localhost:8080"

Write-Host "Waiting for API to be ready..."
$maxRetries = 30
$retryCount = 0
while ($retryCount -lt $maxRetries) {
    try {
        $health = Invoke-RestMethod -Uri "$apiUrl/health" -Method Get -ErrorAction Stop
        if ($health.status -eq "healthy") {
            Write-Host "API is healthy!"
            break
        }
    }
    catch {
        $retryCount++
        Write-Host "Waiting for API... ($retryCount/$maxRetries)"
        Start-Sleep -Seconds 2
    }
}

if ($retryCount -ge $maxRetries) {
    Write-Error "API did not become healthy in time"
    exit 1
}

Write-Host ""
Write-Host "Creating test backend server..."

$backendBody = @{
    name = "test-ftp"
    host = "test-ftp-server"
    port = 21
    protocol = 0  # FTP
    credentialMapping = 0  # Passthrough
    isEnabled = $true
    description = "Test FTP server for e2e testing"
    connectionTimeoutMs = 30000
} | ConvertTo-Json

try {
    $backend = Invoke-RestMethod -Uri "$apiUrl/api/backends" -Method Post -Body $backendBody -ContentType "application/json"
    Write-Host "Created backend: $($backend.id) - $($backend.name)"
}
catch {
    if ($_.Exception.Response.StatusCode -eq 409) {
        Write-Host "Backend 'test-ftp' already exists, fetching..."
        $backends = Invoke-RestMethod -Uri "$apiUrl/api/backends" -Method Get
        $backend = $backends | Where-Object { $_.name -eq "test-ftp" } | Select-Object -First 1
        Write-Host "Found existing backend: $($backend.id)"
    }
    else {
        throw
    }
}

Write-Host ""
Write-Host "Creating test route mapping..."

$routeBody = @{
    username = "testuser"
    backendServerId = $backend.id
    isEnabled = $true
    priority = 100
    description = "Test route for testuser"
} | ConvertTo-Json

try {
    $route = Invoke-RestMethod -Uri "$apiUrl/api/routes" -Method Post -Body $routeBody -ContentType "application/json"
    Write-Host "Created route: $($route.id) - $($route.username) -> $($route.backendServerName)"
}
catch {
    if ($_.Exception.Response.StatusCode -eq 400) {
        Write-Host "Route for 'testuser' may already exist"
    }
    else {
        throw
    }
}

Write-Host ""
Write-Host "========================================="
Write-Host "Test setup complete!"
Write-Host ""
Write-Host "To test FTP proxy:"
Write-Host "  1. Connect: ftp localhost 21"
Write-Host "  2. Login: USER testuser"
Write-Host "  3. Password: PASS testpass"
Write-Host ""
Write-Host "Or use curl/PowerShell:"
Write-Host "  curl ftp://testuser:testpass@localhost/"
Write-Host "========================================="
