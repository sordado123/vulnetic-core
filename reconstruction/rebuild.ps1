param([Parameter(Mandatory)][string]$WorkDirectory,[string]$Go='go.exe')
# Local build only. Does not install/start the executor or deploy the platform.
$ErrorActionPreference='Stop'
$package=Split-Path -Parent $PSScriptRoot
$work=[IO.Path]::GetFullPath($WorkDirectory)
if(Test-Path -LiteralPath $work){throw 'Choose a new empty build directory'}
New-Item -ItemType Directory -Path $work -Force|Out-Null
foreach($rev in @('e70e7e6dc6ab','83c2ce102c8a','f92615b76a05')){
 $source=Join-Path $package ('sources/'+$rev)
 $dest=Join-Path $work ('build/'+$rev)
 New-Item -ItemType Directory -Path $dest -Force|Out-Null
 Copy-Item -Path "$source/*" -Destination $dest -Recurse -Force
}
$env:NEXT_TELEMETRY_DISABLED='1';$env:NEXT_PUBLIC_MOCK='0';$env:NEXT_PUBLIC_SSE_BASE=''
Push-Location (Join-Path $work 'build/e70e7e6dc6ab/web')
try{& npm.cmd ci --ignore-scripts --no-audit --fund=false;if($LASTEXITCODE -ne 0){throw 'npm ci failed'};& node.exe scripts/build-static.mjs;if($LASTEXITCODE -ne 0){throw 'Static frontend build failed'}}finally{Pop-Location}
$out=Join-Path $work 'artifacts'
New-Item -ItemType Directory -Path $out -Force|Out-Null
$web=Join-Path $work 'build/e70e7e6dc6ab/web/out'
if(-not(Test-Path "$web/index.html")){throw 'Fresh static export required'}
$embedded=Join-Path $work 'build/e70e7e6dc6ab/server/webui/dist'
New-Item -ItemType Directory -Path $embedded -Force|Out-Null
Copy-Item -Path "$web/*" -Destination $embedded -Recurse -Force
$env:CGO_ENABLED='0';$env:GOTOOLCHAIN='local';$env:GOPROXY='https://proxy.golang.org,direct'
$targets=@(
 @{name='linux';rev='e70e7e6dc6ab';os='linux';arch='amd64';pkg='./cmd/vulnetic';tags='embedui';flags='-s -w -X main.version=1.1.5+e70e7e6dc6ab';file='vulnetic-linux-amd64'},
 @{name='windows';rev='e70e7e6dc6ab';os='windows';arch='amd64';pkg='./cmd/vulnetic';tags='embedui';flags='-s -w -X main.version=1.1.5+e70e7e6dc6ab';file='vulnetic-windows-amd64.exe'},
 @{name='gateway-linux-amd64';rev='e70e7e6dc6ab';os='linux';arch='amd64';pkg='./cmd/vulnetic-gateway';tags='';flags='-s -w';file='vulnetic-gateway-linux-amd64'},
 @{name='agent-linux-amd64';rev='83c2ce102c8a';os='linux';arch='amd64';pkg='./cmd/vulnetic-agent';tags='';flags='-s -w';file='VulneticExecutor-linux-amd64'},
 @{name='agent-linux-arm64';rev='83c2ce102c8a';os='linux';arch='arm64';pkg='./cmd/vulnetic-agent';tags='';flags='-s -w';file='VulneticExecutor-linux-arm64'},
 @{name='agent-windows-amd64';rev='83c2ce102c8a';os='windows';arch='amd64';pkg='./cmd/vulnetic-agent';tags='';flags='-X main.version=0.2.0-preview+git.83c2ce102c8a';file='VulneticExecutor.exe'},
 @{name='proof-reconcile-linux-amd64';rev='f92615b76a05';os='linux';arch='amd64';pkg='./cmd/vulnetic-proof-reconcile';tags='';flags='-s -w';file='vulnetic-proof-reconcile-linux-amd64'}
)
$results=@()
foreach($t in $targets){
 $env:GOOS=$t.os;$env:GOARCH=$t.arch
 $binary=Join-Path $out $t.file
 $args=@('build','-buildvcs=false','-trimpath','-ldflags',$t.flags,'-o',$binary)
 if($t.tags){$args+=@('-tags',$t.tags)}
 $args+=$t.pkg
 $started=[DateTimeOffset]::UtcNow
 Push-Location (Join-Path $work ('build/'+$t.rev))
 try{& $go @args *> (Join-Path $work ($t.name+'.build.txt'));$code=$LASTEXITCODE}finally{Pop-Location}
 $r=[ordered]@{artifact=$t.name;revision=$t.rev;os=$t.os;arch=$t.arch;file=$t.file;arguments=$args;exit_code=$code;seconds=[Math]::Round(([DateTimeOffset]::UtcNow-$started).TotalSeconds,2)}
 if($code -eq 0){$r.sha256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant();$r.bytes=(Get-Item -LiteralPath $binary).Length;& $go version -m $binary | Set-Content -LiteralPath (Join-Path $work ($t.name+'.buildinfo.txt'))}
 $results+=$r
 $results|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $work 'build-results.json') -Encoding utf8
 Write-Output ($t.name+': '+$code)
}
if(@($results|Where-Object exit_code -ne 0).Count){throw 'One or more independent builds failed; inspect logs.'}
& (Join-Path $PSScriptRoot 'windows-resources.ps1') -Binary (Join-Path $out 'VulneticExecutor.exe') -IdentityFile (Join-Path $work 'build/83c2ce102c8a/internal/agentidentity/windows.json') | Set-Content -LiteralPath (Join-Path $work 'windows-resources.json')
if(-not(Test-Path (Join-Path $work 'windows-resources.json'))){throw 'Windows resource verification failed'}
$win=$results|Where-Object artifact -eq 'agent-windows-amd64'
$win.sha256=(Get-FileHash (Join-Path $out 'VulneticExecutor.exe')).Hash.ToLowerInvariant()
$win.bytes=(Get-Item (Join-Path $out 'VulneticExecutor.exe')).Length
$results|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $work 'build-results.json') -Encoding utf8
