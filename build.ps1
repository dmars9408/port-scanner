# Crear carpeta de distribución si no existe
if (-not (Test-Path "dist")) {
    New-Item -ItemType Directory -Path "dist" | Out-Null
}

Write-Host "Compilando para Windows (amd64)..." -ForegroundColor Cyan
$env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags="-s -w" -o dist/portscanner-windows-amd64.exe ./cmd/scanner

Write-Host "Compilando para Linux (amd64)..." -ForegroundColor Cyan
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags="-s -w" -o dist/portscanner-linux-amd64 ./cmd/scanner

Write-Host "Compilando para macOS Apple Silicon (arm64)..." -ForegroundColor Cyan
$env:CGO_ENABLED="0"; $env:GOOS="darwin"; $env:GOARCH="arm64"
go build -ldflags="-s -w" -o dist/portscanner-darwin-arm64 ./cmd/scanner

Write-Host "Compilando para macOS Intel (amd64)..." -ForegroundColor Cyan
$env:CGO_ENABLED="0"; $env:GOOS="darwin"; $env:GOARCH="amd64"
go build -ldflags="-s -w" -o dist/portscanner-darwin-amd64 ./cmd/scanner

Write-Host "Compilación finalizada con éxito en la carpeta /dist" -ForegroundColor Green