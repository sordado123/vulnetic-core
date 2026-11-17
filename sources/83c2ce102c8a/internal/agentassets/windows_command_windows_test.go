package agentassets

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsInstallerDisclosureAndVerification(t *testing.T) {
	command := WindowsInstallCommand("https://fixture.invalid/quote'here", "synthetic-one-use-token", 10800)
	for _, required := range []string{"VulneticExecutor.exe", "authenticated remote commands", "without administrator rights", "original access deadline", "Workspace files are preserved", "Get-AuthenticodeSignature", "Publisher not verified", "Read-Host", "-connect", "LocalApplicationData", "Type CONNECT"} {
		if !strings.Contains(command, required) {
			t.Fatalf("installer omits %q", required)
		}
	}
	last := -1
	for _, operation := range []string{"Get-FileHash", "$signature=Get-AuthenticodeSignature", "Read-Host", "[IO.File]::WriteAllText", "& $binary -connect"} {
		index := strings.Index(command, operation)
		if index <= last {
			t.Fatalf("installation happens before validation or consent: %s", operation)
		}
		last = index
	}
	for _, forbidden := range []string{"ExecutionPolicy", "Add-MpPreference", "Set-MpPreference", "EncodedCommand", "Invoke-Expression", "-install", "-service", "ProgramFiles", "Start-Process", "New-Service", "New-LocalUser", "ScheduledTask", "-Recurse"} {
		if strings.Contains(command, forbidden) {
			t.Fatalf("installer weakens protection or obscures execution: %s", forbidden)
		}
	}
	file := filepath.Join(t.TempDir(), "installer-fixture.ps1")
	if err := os.WriteFile(file, []byte(command), 0600); err != nil {
		t.Fatal(err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	parser := exec.Command(filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", `
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:VULNETIC_BOOTSTRAP_FIXTURE,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Show-VulneticPublisher'},$true)
if(-not $function){throw 'Publisher disclosure function missing'}
. ([scriptblock]::Create($function.Extent.Text))
$warningMessages=@(Show-VulneticPublisher ([pscustomobject]@{Status='NotSigned';SignerCertificate=$null}) 3>&1)
if(($warningMessages | Out-String) -notmatch 'Publisher not verified'){throw 'Unsigned publisher warning missing'}
Show-VulneticPublisher ([pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='Synthetic test publisher';Thumbprint='fixture'}})
foreach($status in @('HashMismatch','NotTrusted','UnknownError','NotSupportedFileFormat','Unexpected')){
 $rejected=$false
 try{Show-VulneticPublisher ([pscustomobject]@{Status=$status;SignerCertificate=$null})}catch{$rejected=$true}
 if(-not $rejected){throw ('Invalid signature accepted: '+$status)}
}
$rejected=$false
try{Show-VulneticPublisher ([pscustomobject]@{Status='Valid';SignerCertificate=$null})}catch{$rejected=$true}
if(-not $rejected){throw 'Missing signing identity accepted as verified'}
`)
	parser.Env = append(os.Environ(), "VULNETIC_BOOTSTRAP_FIXTURE="+file)
	if output, err := parser.CombinedOutput(); err != nil {
		t.Fatalf("generated installer is invalid PowerShell: %s %v", output, err)
	}
}
