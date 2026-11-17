"""Reject missing or skipped mandatory beta checks in go test -json output."""
import json
import sys

REQUIRED = {
 "TestTargetTextSentencePunctuationPreservesProtection",
 "TestEvidenceMasksEscapedTextHeaders",
 "TestProofPreviewRemasksLegacyHeadersWithoutChangingOriginal",
 "TestBetaProofArtifactTransactionRollbackAndConcurrentRecovery",
 "TestEvidenceMasksWholeTextHeaders",
 "TestHostRecordsFullResultBeforeModelReduction",
 "TestRunInfoKeepsRetestTaskAndExecutorIdentity",
 "TestCVEDedupMergesAliasBridgeRegardlessOfOrder",
 "TestCVEAuthorizationAndProofIsolation",
 "TestCVEFailedEvidenceCannotVerify",
 "TestCVEVerifierRequiresControlsAndRealMechanism",
 "TestCVEVerifierRejectsProtectedTargetAndChangedRecipe",
 "TestCVEVerifierCancellationAndCatalogue",
 "TestCVEIntelligencePreservesApplicabilityAndSourceState",
 "TestSaaSCatalogFailureCannotRestoreDefaultTools",
 "TestSaaSNativeFileToolsDenyBeforeReading",
 "TestRuntimePreservesStoredEvidence",
 "TestPlatformCannotEnrollAsExecutor",
 "TestAgentDedicatedUserPermissions",
 "TestSaaSNativeToolsCannotReadPlatformFiles",
 "TestSaaSLocalExecutorCannotStartProcess",
    "TestRuntimeRLSWithoutOwnerCredential",
 "TestManagedRemoteDNSProtectsPlatform",
    "TestRuntimeAgentAPILifecycle",
    "TestGatewayRoutesAndCredentials",
    "TestGatewayControlProtocolFailClosed",
    "TestGatewayAgentConnectionAndControlLoss",
    "TestGatewayRemoteExecutionLinux",
    "TestProtectedPlatformTargets",
    "TestImmutableToolPolicy",
    "TestSaaSPolicyPrecedesModelApproval",
    "TestPlatformIngressRejectsExecutorAndSpoofedOrigins",

    "TestBetaAgentEnrollmentLeaseIsolation",
    "TestBetaAgentRLS",
    "TestBetaAgentAPILifecycle",
    "TestBetaAgentTransport",
    "TestBetaAgentWebSocketByteStream",
    "TestBetaAgentURLPolicy",
    "TestBetaAgentRequiresTrustedTLS",
    "TestAgentExecAndCancellationLinux",
    "TestAgentInstallationRequiresOwnedPathsAndSupervisor",
    "TestQueuedToolKeepsExpiredContextDuringSettlement",
    "TestSettlementOnToolOverrunsBudget",
    "TestParentCancelStillAbortsNoSettlement",
    "TestBetaRetryAndHealthPoliciesBelongToAccount",
    "TestBetaSaaSDisablesPlatformAssetProbes",
    "TestBetaOperatorMetricsContainCountsWithoutCustomerContents",
    "TestInterceptFilterHTTP",
    "TestCaptureApprovalLifecycle",
    "TestGraphOverviewExpandsAssociatedCompanyScope",
    "TestSideUsageRecordedOnceOnConsumerCancellation",
}


def check(events):
    passed = set()
    errors = []
    for event in events:
        name = event.get("Test", "")
        root = name.split("/", 1)[0]
        if event.get("Action") == "pass" and name == root:
            passed.add(root)
        if (root in REQUIRED or root.startswith("TestBeta")) and event.get("Action") in {"skip", "fail"}:
            errors.append(f"{event.get('Package', '')}: {name} {event['Action']}")
    errors.extend(f"mandatory check did not pass: {name}" for name in sorted(REQUIRED - passed))
    if not any(name.startswith("TestBeta") for name in passed):
        errors.append("no beta security checks passed")
    return errors


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8-sig") as source:
        errors = check(json.loads(line) for line in source if line.strip())
    if errors:
        raise SystemExit("\n".join(errors))
    print("Mandatory beta checks passed without skips.")
