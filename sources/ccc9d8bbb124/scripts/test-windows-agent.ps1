param([switch]$TerminalIntegration,[switch]$ServiceIntegration)
$ErrorActionPreference='Stop'
$agentRoot=Split-Path -Parent $PSScriptRoot
Push-Location $agentRoot
try {
    if (-not $IsWindows -and $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run Windows tests on Windows.' }
    if ($ServiceIntegration) { throw 'Windows service installation was removed. Use -TerminalIntegration for the foreground mode; no administrator prompt is needed.' }
    $agentGo=(Get-Command go.exe -ErrorAction Stop).Source
    & $agentGo test ./internal/winsecure ./internal/reverseagent ./sshexec ./cmd/vulnetic-agent ./internal/agentassets ./internal/agentidentity -count=1
    if ($LASTEXITCODE -ne 0) { throw 'Windows agent unit tests failed.' }
    & $agentGo test ./server -run 'TestWindowsEnrollmentRejectsInvalidIdentity|TestWindowsEnrollmentRequiresAccount|TestWindowsForegroundCommand' -count=1
    if ($LASTEXITCODE -ne 0) { throw 'Windows distribution safety checks failed.' }
    if (-not $TerminalIntegration) { Write-Output 'Unit tests passed. Foreground integration and antivirus review remain separate release requirements.'; return }
    & (Join-Path $PSScriptRoot 'build-windows-agent-preview.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'Foreground build failed.' }
    $agentBinary=Join-Path $agentRoot 'dist/windows-agent-preview/VulneticExecutor.exe'
    $agentArtifacts=Join-Path $agentRoot '.git/codex-windows-agent'
    New-Item -ItemType Directory -Path $agentArtifacts -Force | Out-Null
    $agentTest=Join-Path $agentArtifacts 'terminal.test.exe'
    & $agentGo test -c -tags windowsagentintegration -o $agentTest ./cmd/vulnetic-agent
    if ($LASTEXITCODE -ne 0) { throw 'Foreground integration compilation failed.' }
    $agentResult=Join-Path $agentArtifacts ('terminal-result-'+[Guid]::NewGuid().ToString('N')+'.json')
    Write-Output 'Testing foreground execution as the current non-administrator user. No service, account, startup entry or production connection is created.'
    & $agentTest '-test.run=^TestWindowsTerminalLifecycle$' '-test.v' '-test.timeout=2m' ('-agent-binary='+$agentBinary) ('-agent-results='+$agentResult)
    $agentExit=$LASTEXITCODE
    if (-not (Test-Path -LiteralPath $agentResult)) { throw 'No foreground integration result was produced.' }
    $agentEvidence=Get-Content -LiteralPath $agentResult -Raw | ConvertFrom-Json
    $agentEvidence | ConvertTo-Json -Depth 8 | Write-Output
    if ($agentExit -ne 0 -or -not $agentEvidence.passed) { throw ('Foreground integration failed; inspect '+$agentResult+'.log before retrying.') }
    Write-Output 'Foreground integration passed. Antivirus and release checks are still required for this exact artifact.'
} finally { Pop-Location }
