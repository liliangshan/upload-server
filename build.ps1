# Build script - Build Windows and Linux versions
# Disable CGO

Write-Host "Starting build..." -ForegroundColor Green

# Set environment variable to disable CGO
$env:CGO_ENABLED = "0"

# Build Windows version
Write-Host "`nBuilding Windows version..." -ForegroundColor Yellow
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o upload.exe -ldflags="-s -w" .
if ($LASTEXITCODE -eq 0) {
    Write-Host "Windows build successful: upload.exe" -ForegroundColor Green
} else {
    Write-Host "Windows build failed" -ForegroundColor Red
    exit 1
}

# Build Linux version
Write-Host "`nBuilding Linux version..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o upload-linux -ldflags="-s -w" .
if ($LASTEXITCODE -eq 0) {
    Write-Host "Linux build successful: upload-linux" -ForegroundColor Green
} else {
    Write-Host "Linux build failed" -ForegroundColor Red
    exit 1
}

# Clean up environment variables
Remove-Item Env:\CGO_ENABLED
Remove-Item Env:\GOOS
Remove-Item Env:\GOARCH

Write-Host "`nAll builds completed!" -ForegroundColor Green
Write-Host "  - Windows: upload.exe" -ForegroundColor Cyan
Write-Host "  - Linux:   upload-linux" -ForegroundColor Cyan

