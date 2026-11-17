$ErrorActionPreference = 'Stop'
$betaRoot = Split-Path -Parent $PSScriptRoot
Push-Location $betaRoot
$betaEnvNames = 'GOOS','GOARCH','CGO_ENABLED','NEXT_EXPORT','NEXT_PUBLIC_MOCK','NEXT_PUBLIC_SSE_BASE'
$betaOriginalEnv = @{}
foreach ($name in $betaEnvNames) { $betaOriginalEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
$betaStage = $null
try {
    $betaRevision = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'A Git checkout is required.' }
    if (& git status --porcelain) { throw 'Commit the source changes before packaging a beta revision.' }
    $betaVersion = 'beta.' + $betaRevision.Substring(0,12)
    $env:NEXT_EXPORT = '1'
    $env:NEXT_PUBLIC_MOCK = '0'
    $env:NEXT_PUBLIC_SSE_BASE = ''
    Push-Location web
    try {
        & npm.cmd ci
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }
        & npx.cmd --no-install tsc --noEmit
        if ($LASTEXITCODE -ne 0) { throw 'TypeScript validation failed.' }
        & npm.cmd run build:static
        if ($LASTEXITCODE -ne 0) { throw 'Frontend export failed.' }
    } finally { Pop-Location }
    $betaEmbedded = [IO.Path]::GetFullPath((Join-Path $betaRoot 'server/webui/dist'))
    if (-not $betaEmbedded.StartsWith($betaRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Embedded output escaped the checkout.' }
    if (Test-Path -LiteralPath $betaEmbedded) { Remove-Item -LiteralPath $betaEmbedded -Recurse -Force }
    New-Item -ItemType Directory -Path $betaEmbedded | Out-Null
    Copy-Item -Path 'web/out/*' -Destination $betaEmbedded -Recurse -Force

    $betaOutput = Join-Path $betaRoot 'dist/beta'
    New-Item -ItemType Directory -Path $betaOutput -Force | Out-Null
    $betaStage = Join-Path $betaOutput ('stage-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $betaStage 'dist/amd64'),(Join-Path $betaStage 'dist/windows'),(Join-Path $betaStage 'dist/agents'),(Join-Path $betaStage 'scripts') | Out-Null
    $env:CGO_ENABLED = '0'
    $env:GOARCH = 'amd64'
    $betaManifest = [ordered]@{commit=$betaRevision;version=$betaVersion;built_at=[DateTime]::UtcNow.ToString('o');binaries=@{}}
    $env:GOOS='linux'
    foreach ($betaArchitecture in 'amd64','arm64') {
        $env:GOARCH=$betaArchitecture
        $betaAgentRelative='dist/agents/linux-'+$betaArchitecture
        $betaAgentBinary=Join-Path $betaStage $betaAgentRelative
        & go build -trimpath -ldflags '-s -w' -o $betaAgentBinary ./cmd/vulnetic-agent
        if($LASTEXITCODE -ne 0){throw ('Agent build failed for '+$betaArchitecture)}
        $betaManifest.binaries['agent-linux-'+$betaArchitecture]=@{path=$betaAgentRelative;sha256=(Get-FileHash -LiteralPath $betaAgentBinary -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    $env:GOARCH='amd64'
    & (Join-Path $PSScriptRoot 'build-windows-agent-preview.ps1') -Release
    $betaWindowsAgent=Get-Content -Raw -LiteralPath 'dist/windows-agent-preview/preview-manifest.json' | ConvertFrom-Json
    if ($betaWindowsAgent.source_dirty -or $betaWindowsAgent.source_revision -ne $betaRevision.Substring(0,12) -or $betaWindowsAgent.mode -ne 'foreground') { throw 'Windows executor source identity mismatch.' }
    $betaWindowsRelative='dist/agents/windows-amd64.exe'
    Copy-Item -LiteralPath 'dist/windows-agent-preview/VulneticExecutor.exe' -Destination (Join-Path $betaStage $betaWindowsRelative)
    $betaManifest.binaries['agent-windows-amd64']=@{path=$betaWindowsRelative;sha256=$betaWindowsAgent.sha256;version=$betaWindowsAgent.version;mode='foreground';authenticode=$betaWindowsAgent.authenticode}
    $env:GOOS='linux'
    $betaGatewayBinary = Join-Path $betaStage 'dist/amd64/vulnetic-gateway'
    & go build -trimpath -ldflags '-s -w' -o $betaGatewayBinary ./cmd/vulnetic-gateway
    if ($LASTEXITCODE -ne 0) { throw 'Gateway build failed.' }
    $betaManifest.binaries['gateway-linux-amd64'] = @{path='dist/amd64/vulnetic-gateway';sha256=(Get-FileHash -LiteralPath $betaGatewayBinary -Algorithm SHA256).Hash.ToLowerInvariant()}
    $betaReconcileBinary = Join-Path $betaStage 'dist/amd64/vulnetic-proof-reconcile'
    & go build -trimpath -ldflags '-s -w' -o $betaReconcileBinary ./cmd/vulnetic-proof-reconcile
    if ($LASTEXITCODE -ne 0) { throw 'Proof reconciliation command build failed.' }
    $betaManifest.binaries['proof-reconcile-linux-amd64'] = @{path='dist/amd64/vulnetic-proof-reconcile';sha256=(Get-FileHash -LiteralPath $betaReconcileBinary -Algorithm SHA256).Hash.ToLowerInvariant()}
    foreach ($betaTarget in @(@{OS='windows';File='dist/windows/vulnetic.exe'},@{OS='linux';File='dist/amd64/vulnetic'})) {
        $env:GOOS = $betaTarget.OS
        $betaBinary = Join-Path $betaStage $betaTarget.File
        & go build -trimpath -tags embedui -ldflags "-s -w -X main.version=$betaVersion" -o $betaBinary ./cmd/vulnetic
        if ($LASTEXITCODE -ne 0) { throw ('Build failed for ' + $betaTarget.OS) }
        $betaManifest.binaries[$betaTarget.OS] = @{path=$betaTarget.File;sha256=(Get-FileHash -LiteralPath $betaBinary -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    Copy-Item -LiteralPath 'docker-compose.beta.yml','docker-compose.protected.yml','LICENSE','THIRD_PARTY_NOTICES.md' -Destination $betaStage
    Copy-Item -LiteralPath 'THIRD_PARTY_LICENSES' -Destination $betaStage -Recurse
    New-Item -ItemType Directory -Path (Join-Path $betaStage 'deploy') | Out-Null
    Copy-Item -LiteralPath 'deploy/beta' -Destination (Join-Path $betaStage 'deploy') -Recurse
    Copy-Item -LiteralPath 'scripts/beta_monitor.py','scripts/check_beta_deployment.py' -Destination (Join-Path $betaStage 'scripts')
    Copy-Item -LiteralPath 'deploy/beta/README.md' -Destination (Join-Path $betaStage 'LEIA-PRIMEIRO.md')
    $betaManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $betaStage 'release-manifest.json') -Encoding utf8
    $betaArchive = Join-Path $betaOutput ('vulnetic-' + $betaVersion + '.zip')
    Compress-Archive -Path (Join-Path $betaStage '*') -DestinationPath $betaArchive -Force
    $betaArchiveHash = (Get-FileHash -LiteralPath $betaArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath ($betaArchive + '.sha256') -Value ($betaArchiveHash + '  ' + [IO.Path]::GetFileName($betaArchive)) -Encoding ascii
    Copy-Item -LiteralPath (Join-Path $betaStage 'release-manifest.json') -Destination (Join-Path $betaOutput 'release-manifest.json') -Force
    Write-Output ('Beta package: ' + $betaArchive)
    Write-Output ('SHA-256: ' + $betaArchiveHash)
} finally {
    foreach ($name in $betaEnvNames) { [Environment]::SetEnvironmentVariable($name, $betaOriginalEnv[$name], 'Process') }
    if ($betaStage -and (Test-Path -LiteralPath $betaStage)) {
        $betaStageAbsolute = [IO.Path]::GetFullPath($betaStage)
        $betaOutputPrefix = [IO.Path]::GetFullPath((Join-Path $betaRoot 'dist/beta')) + [IO.Path]::DirectorySeparatorChar
        if (-not $betaStageAbsolute.StartsWith($betaOutputPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to remove a staging directory outside dist/beta.' }
        Remove-Item -LiteralPath $betaStageAbsolute -Recurse -Force
    }
    Pop-Location
}
