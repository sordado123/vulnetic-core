param([switch]$All, [switch]$WithoutRLS, [switch]$Json, [switch]$Race)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
$originalDsn = $env:VULNETIC_PG_DSN
$originalRequired = $env:VULNETIC_REQUIRE_PG_TESTS
$originalAppPassword = $env:VULNETIC_PG_APP_PASSWORD
try {
    if (-not $env:VULNETIC_TEST_PG_DSN) { throw 'Set VULNETIC_TEST_PG_DSN to a disposable local PostgreSQL instance. Application credentials are never used by this test script.' }
    $testUri = [UriBuilder]::new($env:VULNETIC_TEST_PG_DSN)
    # Never run destructive fixtures against the configured application's database.
    $testUri.Path = '/vulnetic_beta_verify_' + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + '_' + $PID
    $env:VULNETIC_PG_DSN = $testUri.Uri.AbsoluteUri
    $env:VULNETIC_REQUIRE_PG_TESTS = 'true'
    $env:VULNETIC_PG_APP_PASSWORD = if ($WithoutRLS) { '' } else { 'beta-integration-test-password-only' }
	[string[]]$testOutputFlags = @()
	if ($Json) { $testOutputFlags = @('-json') }
    if ($Race) { $testOutputFlags += '-race' }
    if ($All) {
        & go test @testOutputFlags -p 1 ./... -count=1 -timeout 10m
    } else {
        & go test @testOutputFlags -p 1 ./db ./cvecheck ./cveintel ./internal/evidenceredact ./evidence ./server ./sshexec ./internal/reverseagent ./internal/agentgateway ./internal/platformpolicy ./cmd/vulnetic-agent ./config ./agent ./guard ./intercept ./llmrec ./notify ./enrich ./mcphttp ./internal/artifactquota ./internal/norma/transcript ./internal/norma/agentcore ./internal/norma/skill ./internal/norma/harness ./internal/norma/tool -run 'TestCVE|TestSaaS|TestSaaSNativeTools|TestSaaSLocalExecutor|TestManagedRemoteDNS|TestRuntime|TestGateway|TestProtectedPlatform|TestImmutableTool|TestSaaSPolicy|TestPlatformIngress|TestAgentExecAndCancellationLinux|TestAgentInstallationRequiresOwnedPathsAndSupervisor|TestQueuedToolKeepsExpiredContextDuringSettlement|TestSettlementOnToolOverrunsBudget|TestParentCancelStillAbortsNoSettlement|TestInterceptFilterHTTP|TestCaptureApprovalLifecycle|TestGraphOverviewExpandsAssociatedCompanyScope|TestSideUsageRecordedOnceOnConsumerCancellation|TestAccountStorageFailure|TestAccountTranscript|TestSharedAccountQuota|TestSlowAccountDoesNotBlockOtherAccounts|TestPrepareSkill|TestBeta|TestPilot|TestAuthLimiter|TestTenantResponse|TestPinnedHostKey|TestRevokedLazy|TestRemoteDirectory|TestTaskHandlersRejectWrongAccount|TestRLSEnforcement|TestRLS2Enforcement' -count=1 -timeout 3m
    }
    if ($LASTEXITCODE -ne 0) { throw "Beta verification failed (exit $LASTEXITCODE)." }
} finally {
    $env:VULNETIC_PG_DSN = $originalDsn
    $env:VULNETIC_REQUIRE_PG_TESTS = $originalRequired
    $env:VULNETIC_PG_APP_PASSWORD = $originalAppPassword
    Pop-Location
}
