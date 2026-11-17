param([switch]$Release)
$ErrorActionPreference='Stop'
if (-not $IsWindows -and $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Build Windows resources on Windows.' }
$agentRoot=Split-Path -Parent $PSScriptRoot
$agentOriginalEnv=@{}
foreach($name in @('GOOS','GOARCH','CGO_ENABLED')) { $agentOriginalEnv[$name]=[Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location $agentRoot
try {
    $identity=Get-Content -Raw -LiteralPath 'internal/agentidentity/windows.json' | ConvertFrom-Json
    if ($identity.file_name -ne 'VulneticExecutor.exe' -or $identity.version -notmatch '^\d+\.\d+\.\d+-preview$' -or $identity.file_version.Count -ne 4) { throw 'Invalid Windows preview identity.' }
    foreach($part in $identity.file_version) { if ($part -lt 0 -or $part -gt 65535) { throw 'Invalid numeric version.' } }
    $revision=(& git rev-parse --short=12 HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -notmatch '^[0-9a-f]{12}$') { throw 'A Git source revision is required.' }
    $dirty=[bool](& git status --porcelain)
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect source state.' }
    if ($Release -and $dirty) { throw 'Commit the source changes before building a release candidate.' }
    $buildVersion=$identity.version+'+git.'+$revision
    if ($dirty) { $buildVersion+='.dirty' }
    $output=Join-Path $agentRoot 'dist/windows-agent-preview'
    New-Item -ItemType Directory -Path $output -Force | Out-Null
    $binary=Join-Path $output $identity.file_name
    $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    $dependencies=@(& go.exe list -deps ./cmd/vulnetic-agent)
    if ($LASTEXITCODE -ne 0 -or @($dependencies | Where-Object { $_ -match '/windows/svc($|/)' }).Count) { throw 'Foreground executor must not depend on Windows service management.' }
    & go.exe build -trimpath -ldflags ('-X main.version='+$buildVersion) -o $binary ./cmd/vulnetic-agent
    if ($LASTEXITCODE -ne 0) { throw 'Windows preview build failed.' }
    if ((Get-AuthenticodeSignature -LiteralPath $binary).Status -ne 'NotSigned') { throw 'Refusing to modify an already signed executable.' }
    if (-not ('VulneticWindowsResources' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

public static class VulneticWindowsResources {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr BeginUpdateResourceW(string file, bool deleteExisting);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool UpdateResourceW(IntPtr update, IntPtr type, IntPtr name, ushort language, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool EndUpdateResourceW(IntPtr update, bool discard);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr LoadLibraryExW(string file, IntPtr reserved, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
    [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
    public static string ReadManifest(string file) {
        // Load as data only: verification must never start the executor or run initialization code.
        IntPtr module=LoadLibraryExW(file,IntPtr.Zero,0x22);
        if (module==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr resource=FindResourceW(module,(IntPtr)1,(IntPtr)24);
            if(resource==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            uint size=SizeofResource(module,resource);
            if(size==0 || size>65536) throw new InvalidDataException("Invalid manifest size.");
            IntPtr loaded=LoadResource(module,resource), data=LockResource(loaded);
            if(data==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            byte[] bytes=new byte[size]; Marshal.Copy(data,bytes,0,bytes.Length); return Encoding.UTF8.GetString(bytes);
        } finally { FreeLibrary(module); }
    }
    static void Align(BinaryWriter writer) { while (writer.BaseStream.Position % 4 != 0) writer.Write((byte)0); }
    static byte[] Block(string key, ushort type, byte[] value, ushort valueLength, params byte[][] children) {
        using (var memory=new MemoryStream()) using (var writer=new BinaryWriter(memory)) {
            writer.Write((ushort)0); writer.Write(valueLength); writer.Write(type);
            writer.Write(Encoding.Unicode.GetBytes(key+"\0")); Align(writer); writer.Write(value);
            foreach (var child in children) { Align(writer); writer.Write(child); }
            if (memory.Length > ushort.MaxValue) throw new InvalidDataException("Version resource too large.");
            long length=memory.Length; memory.Position=0; writer.Write((ushort)length);
            return memory.ToArray();
        }
    }
    public static void Apply(string file, string product, string description, string brand, string originalName, string version, int[] parts) {
        byte[] fixedInfo;
        using (var memory=new MemoryStream()) using (var writer=new BinaryWriter(memory)) {
            uint high=((uint)parts[0]<<16)|(uint)parts[1], low=((uint)parts[2]<<16)|(uint)parts[3];
            foreach (uint item in new uint[]{0xFEEF04BD,0x00010000,high,low,high,low,0x3F,2,0x00040004,1,0,0,0}) writer.Write(item);
            fixedInfo=memory.ToArray();
        }
        string[,] fields={{"CompanyName",brand},{"FileDescription",description},{"FileVersion",version},
            {"InternalName",Path.GetFileNameWithoutExtension(originalName)},{"OriginalFilename",originalName},
            {"ProductName",product},{"ProductVersion",version},{"Comments","Unsigned temporary foreground executor; no automatic startup."}};
        byte[][] strings=new byte[fields.GetLength(0)][];
        for (int i=0;i<strings.Length;i++) strings[i]=Block(fields[i,0],1,Encoding.Unicode.GetBytes(fields[i,1]+"\0"),checked((ushort)(fields[i,1].Length+1)));
        byte[] versionInfo=Block("VS_VERSION_INFO",0,fixedInfo,52,
            Block("StringFileInfo",1,new byte[0],0,Block("040904b0",1,new byte[0],0,strings)),
            Block("VarFileInfo",1,new byte[0],0,Block("Translation",0,new byte[]{9,4,176,4},4)));
        string manifest="<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"+
            "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">"+
            "<assemblyIdentity name=\"Vulnetic.Executor\" version=\""+string.Join(".",parts)+"\" processorArchitecture=\"amd64\" type=\"win32\"/>"+
            "<description>"+SecurityElement.Escape(description)+"</description>"+
            "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges>"+
            "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo></assembly>";
        byte[] manifestBytes=Encoding.UTF8.GetBytes(manifest);
        IntPtr update=BeginUpdateResourceW(file,false);
        if (update==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        bool commit=false;
        try {
            if (!UpdateResourceW(update,(IntPtr)16,(IntPtr)1,1033,versionInfo,(uint)versionInfo.Length) ||
                !UpdateResourceW(update,(IntPtr)24,(IntPtr)1,0,manifestBytes,(uint)manifestBytes.Length)) throw new Win32Exception(Marshal.GetLastWin32Error());
            commit=true;
        } finally {
            if (!EndUpdateResourceW(update,!commit) && commit) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
    }
    [VulneticWindowsResources]::Apply($binary,$identity.product_name,$identity.description,$identity.brand,$identity.file_name,$buildVersion,[int[]]$identity.file_version)
    $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($binary)
    if ($info.ProductName -ne $identity.product_name -or $info.FileDescription -ne $identity.description -or $info.CompanyName -ne $identity.brand -or $info.OriginalFilename -ne $identity.file_name -or $info.ProductVersion -ne $buildVersion -or -not $info.IsPreRelease) { throw 'Windows did not read the expected product metadata.' }
    $numericVersion=@($info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart)
    if (($numericVersion -join '.') -ne ($identity.file_version -join '.')) { throw 'Windows numeric file version did not match.' }
    [xml]$embeddedManifest=[VulneticWindowsResources]::ReadManifest($binary)
    $level=$embeddedManifest.SelectSingleNode('//*[local-name()="requestedExecutionLevel"]')
    if (-not $level -or $level.level -ne 'asInvoker' -or $level.uiAccess -ne 'false') { throw 'Executor manifest requests unexpected elevation.' }
    $signature=(Get-AuthenticodeSignature -LiteralPath $binary).Status.ToString()
    if ($signature -ne 'NotSigned') { throw 'Unexpected preview signature status; review before proceeding.' }
    $distribution=if($Release){'release-candidate'}else{'local-review-only'}
    $manifest=[ordered]@{product=$info.ProductName;version=$info.ProductVersion;file=$identity.file_name;description=$info.FileDescription;brand=$info.CompanyName;source_revision=$revision;source_dirty=$dirty;sha256=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant();authenticode=$signature;distribution=$distribution;build_starts_executor=$false;mode='foreground';persistent_installation=$false;connection_state='memory-only'}
    $manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output 'preview-manifest.json') -Encoding utf8
    @"
Vulnetic Executor - unsigned development preview
Version: $buildVersion
Distribution: $distribution. Validate this exact file with antivirus active before publishing.
The product brand in file properties does not identify a cryptographically verified publisher.
This foreground version does not install a service, create accounts or configure automatic startup.
Run without administrator rights. Keep the terminal open; Ctrl+C ends access.
Connection credentials are held in memory. Closing the process or rebooting requires a new connection command.
Workspace files are preserved and remain subject to the current Windows user's permissions.
This executable was not started by the build script.
Closing the terminal or restarting Windows ends this authorization; reconnect explicitly with a new command.
"@ | Set-Content -LiteralPath (Join-Path $output 'README.txt') -Encoding utf8
    $manifest | ConvertTo-Json
} finally {
    foreach($name in $agentOriginalEnv.Keys) { [Environment]::SetEnvironmentVariable($name,$agentOriginalEnv[$name],'Process') }
    Pop-Location
}
