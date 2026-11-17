param([Parameter(Mandatory)][string]$Binary,[Parameter(Mandatory)][string]$IdentityFile,[string]$Version='0.2.0-preview+git.83c2ce102c8a')
$ErrorActionPreference='Stop'
$identity=Get-Content -Raw -LiteralPath $IdentityFile|ConvertFrom-Json
if($identity.file_name -ne 'VulneticExecutor.exe' -or $identity.file_version.Count -ne 4){throw 'Unexpected identity'}
if((Get-AuthenticodeSignature -LiteralPath $Binary).Status -ne 'NotSigned'){throw 'Refuse to modify signed executable'}
if(-not('VulneticWindowsResources' -as [type])){
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
[VulneticWindowsResources]::Apply($Binary,$identity.product_name,$identity.description,$identity.brand,$identity.file_name,$Version,[int[]]$identity.file_version)
$info=[Diagnostics.FileVersionInfo]::GetVersionInfo($Binary)
if($info.ProductVersion -ne $Version -or $info.ProductName -ne $identity.product_name -or $info.OriginalFilename -ne $identity.file_name -or $info.FileDescription -ne $identity.description -or $info.CompanyName -ne $identity.brand -or -not $info.IsPreRelease){throw 'Unexpected Windows metadata'}
if((@($info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart)-join '.') -ne ($identity.file_version-join '.')){throw 'Unexpected numeric Windows version'}
[xml]$manifest=[VulneticWindowsResources]::ReadManifest($Binary)
$level=$manifest.SelectSingleNode('//*[local-name()="requestedExecutionLevel"]')
if(-not $level -or $level.level -ne 'asInvoker' -or $level.uiAccess -ne 'false'){throw 'Unexpected elevation manifest'}
[ordered]@{product=$info.ProductName;version=$info.ProductVersion;description=$info.FileDescription;original_filename=$info.OriginalFilename;numeric_version=$info.FileVersion;manifest_level=$level.level;ui_access=$level.uiAccess;signature=(Get-AuthenticodeSignature -LiteralPath $Binary).Status.ToString();binary_executed=$false;sha256=(Get-FileHash -LiteralPath $Binary -Algorithm SHA256).Hash.ToLowerInvariant()}|ConvertTo-Json
