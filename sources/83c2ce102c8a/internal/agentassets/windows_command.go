package agentassets

import (
	"strconv"
	"strings"

	"github.com/sordado123/vulnetic/internal/agentidentity"
)

// Interactive PowerShell downloads a verified executable; no execution-policy change is needed.
func WindowsInstallCommand(base, token string, lifetime int) string {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	identity := agentidentity.Windows()
	return strings.NewReplacer("__PLATFORM__", quote(base), "__TOKEN__", quote(token), "__LIFETIME__", strconv.Itoa(lifetime), "__FILENAME__", quote(identity.FileName), "__PRODUCT__", quote(identity.ProductName), "__VERSION_PATTERN__", quote(identity.Version+"*")).Replace(windowsBootstrap)
}

const windowsBootstrap = `& {
 $ErrorActionPreference='Stop'
 function Show-VulneticPublisher($signature) {
  if ($signature.Status -eq 'NotSigned') {
   Write-Warning 'Publisher not verified: this executable is unsigned. Do not disable protection or add antivirus exclusions to run it.'
  } elseif ($signature.Status -eq 'Valid' -and $signature.SignerCertificate) {
   Write-Host ('Verified signing certificate: '+$signature.SignerCertificate.Subject)
   Write-Host ('Certificate thumbprint: '+$signature.SignerCertificate.Thumbprint)
  } else {
   throw 'The executor signature is invalid or could not be checked. Connection stopped.'
  }
 }
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal($identity)
 if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Close this elevated terminal. Open a non-administrator PowerShell window.' }
 if ([IntPtr]::Size -ne 8) { throw 'Use 64-bit PowerShell.' }
 $platform=__PLATFORM__
 Write-Host __PRODUCT__
 Write-Host 'This foreground executor accepts authenticated remote commands with your current Windows file and network permissions.'
 Write-Host ('Endpoint: '+$platform+' | Access duration: '+__LIFETIME__+' seconds.')
 Write-Host 'Run without administrator rights. No service, account or automatic startup is created. Use a dedicated VM/VPS or an already restricted account.'
 Write-Host 'Keep this terminal open. Ctrl+C ends access. Reconnection never renews the original access deadline.'
 Write-Host 'After closing this process or restarting Windows, generate and run a new command. Workspace files are preserved.'
 $storage=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Vulnetic'
 $session=[Guid]::NewGuid().ToString('N')
 $directory=Join-Path $storage ('sessions/'+$session)
 $workspace=Join-Path $storage ('workspaces/'+$session)
 [void](New-Item -ItemType Directory -Path $directory -Force)
 [void](New-Item -ItemType Directory -Path $workspace -Force)
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 foreach ($value in @('S-1-5-18','S-1-5-32-544',$identity.User.Value)) {
  $sid=New-Object Security.Principal.SecurityIdentifier($value)
  $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
  $acl.AddAccessRule($rule)
 }
 $acl.SetOwner($identity.User)
 Set-Acl -LiteralPath $directory -AclObject $acl
 Set-Acl -LiteralPath $workspace -AclObject $acl
 Write-Host ('Workspace: '+$workspace)
 $binary=Join-Path $directory __FILENAME__
 $enrollment=Join-Path $directory 'enrollment'
 try {
  Invoke-WebRequest -UseBasicParsing -Uri ($platform+'/agent/binary/windows-amd64') -OutFile $binary
  $expected=((Invoke-WebRequest -UseBasicParsing -Uri ($platform+'/agent/checksum/windows-amd64')).Content.Trim() -split '\s+')[0]
  if ($expected -notmatch '^[0-9a-fA-F]{64}$' -or (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash -ne $expected) { throw 'Executor checksum mismatch. Connection stopped.' }
  $signature=Get-AuthenticodeSignature -LiteralPath $binary
  Show-VulneticPublisher $signature
  $fileInfo=[Diagnostics.FileVersionInfo]::GetVersionInfo($binary)
  if ($fileInfo.ProductName -ne __PRODUCT__ -or $fileInfo.OriginalFilename -ne __FILENAME__) { throw 'The downloaded file does not match the executor product identity. Connection stopped.' }
  if ($fileInfo.ProductVersion -notlike __VERSION_PATTERN__) { throw 'This file is not the supported foreground version. Do not run the old service installer.' }
  Write-Host ('Build version: '+$fileInfo.ProductVersion)
  if ((Read-Host 'Review the publisher status and access above. Type CONNECT to continue') -cne 'CONNECT') { throw 'Connection cancelled.' }
  [IO.File]::WriteAllText($enrollment,__TOKEN__,(New-Object Text.UTF8Encoding($false)))
  & $binary -connect -server $platform -enrollment-file $enrollment -directory $workspace -lease-seconds __LIFETIME__
  if ($LASTEXITCODE -ne 0) { throw 'Executor connection ended with an error. Review the message above.' }
 } finally {
  foreach ($file in @($enrollment,$binary)) { if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force } }
  if (-not (Get-ChildItem -LiteralPath $directory -Force | Select-Object -First 1)) { Remove-Item -LiteralPath $directory -Force }
 }
}`
