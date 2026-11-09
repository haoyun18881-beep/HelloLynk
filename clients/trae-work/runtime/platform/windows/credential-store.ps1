param(
  [Parameter(Mandatory = $true)]
  [ValidateSet(
    "PrepareRoot",
    "SecureReleaseTree",
    "VerifyReleaseTree",
    "StoreProfile",
    "StoreStatus",
    "ProbeCredential",
    "ValidateManagedFile",
    "SecureManagedFile",
    "Store",
    "Load",
    "Remove",
    "StoreRuntimeSession",
    "LoadRuntimeSession",
    "RemoveRuntimeSession",
    "StoreE2eePrivateKeys",
    "LoadE2eePrivateKeys",
    "LoadE2eePrivateKeysBatch",
    "RemoveE2eePrivateKeys"
  )]
  [string]$Command,

  [Parameter(Mandatory = $true)]
  [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$')]
  [string]$ProfileId,

  [string]$ClientRoot = "",

  [string]$ManagedRelativePath = "",

  [string]$StoreRoot = "",

  [string]$E2eeStoreRoot = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class HelloLynkWindowsFileNative {
  public const uint GENERIC_READ = 0x80000000;
  public const uint FILE_SHARE_READ = 0x00000001;
  public const uint FILE_SHARE_WRITE = 0x00000002;
  public const uint FILE_SHARE_DELETE = 0x00000004;
  public const uint OPEN_EXISTING = 3;
  public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
  public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
  public const uint MOVEFILE_REPLACE_EXISTING = 0x00000001;
  public const uint MOVEFILE_WRITE_THROUGH = 0x00000008;

  [StructLayout(LayoutKind.Sequential)]
  public struct BY_HANDLE_FILE_INFORMATION {
    public uint FileAttributes;
    public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
    public uint VolumeSerialNumber;
    public uint FileSizeHigh;
    public uint FileSizeLow;
    public uint NumberOfLinks;
    public uint FileIndexHigh;
    public uint FileIndexLow;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern SafeFileHandle CreateFileW(
    string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
    uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern uint GetFinalPathNameByHandleW(
    SafeFileHandle file, System.Text.StringBuilder path, uint length, uint flags);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool GetFileInformationByHandle(
    SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION information);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool MoveFileExW(string existingName, string newName, uint flags);

  [StructLayout(LayoutKind.Sequential)]
  private struct SECURITY_ATTRIBUTES {
    public int Length;
    public IntPtr SecurityDescriptor;
    public int InheritHandle;
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  private static extern bool CreateDirectoryW(string path, ref SECURITY_ATTRIBUTES attributes);

  public static bool CreateProtectedDirectory(string path, byte[] descriptor) {
    var pinned = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
    try {
      var attributes = new SECURITY_ATTRIBUTES {
        Length = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
        SecurityDescriptor = pinned.AddrOfPinnedObject(),
        InheritHandle = 0
      };
      return CreateDirectoryW(path, ref attributes);
    } finally { pinned.Free(); }
  }
}
'@

$script:CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$script:SystemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
$script:AdministratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
$script:TrustedInstallerSid = try {
  ([Security.Principal.NTAccount]::new("NT SERVICE", "TrustedInstaller")).Translate(
    [Security.Principal.SecurityIdentifier]
  )
} catch { $null }
$script:AllowedSids = @(
  $script:CurrentSid.Value,
  $script:SystemSid.Value,
  $script:AdministratorsSid.Value
)
$script:TrustedAncestorOwnerSids = @($script:AllowedSids)
if ($null -ne $script:TrustedInstallerSid) {
  $script:TrustedAncestorOwnerSids += $script:TrustedInstallerSid.Value
}

function Fail([string]$Code) {
  [Console]::Error.WriteLine($Code)
  exit 1
}

function Normalize-HelloLynkAbsoluteFixedPath([string]$PathValue) {
  if (
    [string]::IsNullOrWhiteSpace($PathValue) -or
    -not [IO.Path]::IsPathFullyQualified($PathValue) -or
    $PathValue.StartsWith("\\", [StringComparison]::Ordinal) -or
    $PathValue.StartsWith("//", [StringComparison]::Ordinal)
  ) { Fail "client_root_path_invalid" }
  try { $full = [IO.Path]::GetFullPath($PathValue) } catch { Fail "client_root_path_invalid" }
  $trimmedRequested = $PathValue.TrimEnd([char[]]@('\', '/'))
  $trimmedFull = $full.TrimEnd([char[]]@('\', '/'))
  if (-not $trimmedRequested.Equals($trimmedFull, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "client_root_alias_rejected"
  }
  try { $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($full)) } catch { Fail "client_root_volume_invalid" }
  if ($drive.DriveType -ne [IO.DriveType]::Fixed) { Fail "client_root_fixed_local_required" }
  return $full
}

function Assert-HelloLynkNoReparseAncestors([string]$PathValue) {
  $current = $PathValue
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    if ([IO.Directory]::Exists($current) -or [IO.File]::Exists($current)) {
      try { $item = Get-Item -LiteralPath $current -Force } catch { Fail "client_root_path_untrusted" }
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "client_root_reparse_rejected"
      }
    }
    $parent = [IO.Path]::GetDirectoryName($current.TrimEnd([char[]]@('\', '/')))
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) { break }
    $current = $parent
  }
}

function Get-HelloLynkExistingAncestorDirectories([string]$RootPath) {
  $directories = [Collections.Generic.List[string]]::new()
  $current = [IO.Path]::GetDirectoryName($RootPath.TrimEnd([char[]]@('\', '/')))
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    if ([IO.Directory]::Exists($current)) { $directories.Add($current) }
    $parent = [IO.Path]::GetDirectoryName($current.TrimEnd([char[]]@('\', '/')))
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent.Equals($current, [StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $current = $parent
  }
  $ordered = @($directories)
  [Array]::Reverse($ordered)
  return $ordered
}

function Assert-HelloLynkTrustedAncestorAcl([string]$RootPath, [bool]$Create = $false) {
  $rootParent = [IO.Path]::GetDirectoryName($RootPath.TrimEnd([char[]]@('\', '/')))
  $directories = @(Get-HelloLynkExistingAncestorDirectories $RootPath)
  $dangerousRights = (
    [Security.AccessControl.FileSystemRights]::CreateFiles -bor
    [Security.AccessControl.FileSystemRights]::CreateDirectories -bor
    [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [Security.AccessControl.FileSystemRights]::TakeOwnership
  )
  $createRights = [Security.AccessControl.FileSystemRights]::CreateFiles -bor
    [Security.AccessControl.FileSystemRights]::CreateDirectories
  foreach ($directory in $directories) {
    Assert-HelloLynkNoReparseAncestors $directory
    $identity = Open-HelloLynkIdentity $directory $true
    $identity.Handle.Dispose()
    try { $acl = Get-Acl -LiteralPath $directory } catch { Fail "client_root_ancestor_acl_untrusted" }
    try {
      $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
        [Security.Principal.SecurityIdentifier]
      ).Value
    } catch {
      try { $ownerSid = ([Security.Principal.SecurityIdentifier]$acl.Owner).Value } catch {
        Fail "client_root_ancestor_owner_untrusted"
      }
    }
    if ($script:TrustedAncestorOwnerSids -notcontains $ownerSid) {
      Fail "client_root_ancestor_owner_untrusted"
    }

    # Package/capability grants constrain an AppContainer in addition to its
    # user's rights; they are not grants to another Windows user. Only accept
    # specific app identities on this user's own profile ancestors. The actual
    # credential root still requires the closed DACL checked below.
    $userProfile = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile).TrimEnd('\', '/')
    $isOwnProfileAncestor = $ownerSid -eq $script:CurrentSid.Value -and (
      $directory.Equals($userProfile, [StringComparison]::OrdinalIgnoreCase) -or
      $directory.StartsWith($userProfile + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
    )
    $isRootParent = $directory.Equals($rootParent, [StringComparison]::OrdinalIgnoreCase)
    $directoryIndex = [Array]::IndexOf($directories, $directory)
    $willCreateProtectedChild = $Create -and -not $isRootParent -and $directoryIndex -eq $directories.Count - 1
    $nextDirectoryProtected = $false
    if ($directoryIndex -ge 0 -and $directoryIndex + 1 -lt $directories.Count) {
      try {
        $nextDirectoryProtected = (Get-Acl -LiteralPath $directories[$directoryIndex + 1]).AreAccessRulesProtected
      } catch { Fail "client_root_ancestor_acl_untrusted" }
    }
    $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
      if (
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $script:TrustedAncestorOwnerSids -contains $rule.IdentityReference.Value -or
        ($isOwnProfileAncestor -and $rule.IdentityReference.Value -match '^S-1-15-[23]-(?:\d+-){6,7}\d+$') -or
        (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
      ) { continue }
      $rights = $rule.FileSystemRights
      $hasDangerousRights = (($rights -band $dangerousRights) -ne 0)
      # A competing child created by a different user fails our owner check.
      # A grant to alter the ancestor itself still prevents first creation.
      $canCreateProtectedChild = $willCreateProtectedChild -and
        (($rights -band $dangerousRights -band (-bnot $createRights)) -eq 0)
      $hasDeleteChild = (
        ($rights -band [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles) -ne 0
      )
      if (
        $hasDeleteChild -or
        ($hasDangerousRights -and ($isRootParent -or (-not $nextDirectoryProtected -and -not $canCreateProtectedChild)))
      ) { Fail "client_root_ancestor_dacl_untrusted" }
    }
  }
  return $directories[-1]
}

function New-HelloLynkAcl([bool]$Directory) {
  if ($Directory) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $inheritance = [Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetOwner($script:CurrentSid)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($script:CurrentSid, $script:SystemSid, $script:AdministratorsSid)) {
    $rule = if ($Directory) {
      [Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
      )
    } else {
      [Security.AccessControl.FileSystemAccessRule]::new(
        $sid,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
      )
    }
    $null = $acl.AddAccessRule($rule)
  }
  return $acl
}

function Set-HelloLynkSecureAcl([string]$PathValue, [bool]$Directory) {
  try { Set-Acl -LiteralPath $PathValue -AclObject (New-HelloLynkAcl $Directory) } catch { Fail "client_root_acl_apply_failed" }
}

function Assert-HelloLynkSecureAcl([string]$PathValue, [bool]$Directory) {
  try { $acl = Get-Acl -LiteralPath $PathValue } catch { Fail "client_root_acl_untrusted" }
  try { $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value } catch {
    try { $ownerSid = ([Security.Principal.SecurityIdentifier]$acl.Owner).Value } catch { Fail "client_root_owner_untrusted" }
  }
  if ($ownerSid -ne $script:CurrentSid.Value) { Fail "client_root_owner_untrusted" }
  if (-not $acl.AreAccessRulesProtected) { Fail "client_root_dacl_unprotected" }
  $rules = $acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier])
  $currentFullControl = $false
  $systemFullControl = $false
  $administratorsFullControl = $false
  foreach ($rule in $rules) {
    $sid = $rule.IdentityReference.Value
    if ($script:AllowedSids -notcontains $sid) { Fail "client_root_dacl_untrusted" }
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
      Fail "client_root_dacl_untrusted"
    }
    $hasFullControl = (
      ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
      [Security.AccessControl.FileSystemRights]::FullControl
    )
    if ($hasFullControl) {
      if ($sid -eq $script:CurrentSid.Value) { $currentFullControl = $true }
      if ($sid -eq $script:SystemSid.Value) { $systemFullControl = $true }
      if ($sid -eq $script:AdministratorsSid.Value) { $administratorsFullControl = $true }
    }
  }
  if (-not ($currentFullControl -and $systemFullControl -and $administratorsFullControl)) {
    Fail "client_root_dacl_untrusted"
  }
  if ($Directory -and -not [IO.Directory]::Exists($PathValue)) { Fail "client_root_not_directory" }
  if (-not $Directory -and -not [IO.File]::Exists($PathValue)) { Fail "client_file_not_regular" }
}

function Open-HelloLynkIdentity([string]$PathValue, [bool]$Directory) {
  $flags = [HelloLynkWindowsFileNative]::FILE_FLAG_OPEN_REPARSE_POINT
  if ($Directory) { $flags = $flags -bor [HelloLynkWindowsFileNative]::FILE_FLAG_BACKUP_SEMANTICS }
  $handle = [HelloLynkWindowsFileNative]::CreateFileW(
    $PathValue,
    [HelloLynkWindowsFileNative]::GENERIC_READ,
    [HelloLynkWindowsFileNative]::FILE_SHARE_READ -bor
      [HelloLynkWindowsFileNative]::FILE_SHARE_WRITE -bor
      [HelloLynkWindowsFileNative]::FILE_SHARE_DELETE,
    [IntPtr]::Zero,
    [HelloLynkWindowsFileNative]::OPEN_EXISTING,
    $flags,
    [IntPtr]::Zero
  )
  if ($handle.IsInvalid) { Fail "client_file_open_failed" }
  $builder = [Text.StringBuilder]::new(32768)
  $length = [HelloLynkWindowsFileNative]::GetFinalPathNameByHandleW($handle, $builder, $builder.Capacity, 0)
  if ($length -eq 0 -or $length -ge $builder.Capacity) { $handle.Dispose(); Fail "client_file_final_path_failed" }
  $final = $builder.ToString()
  if ($final.StartsWith("\\?\UNC\", [StringComparison]::OrdinalIgnoreCase)) {
    $handle.Dispose(); Fail "client_root_fixed_local_required"
  }
  if ($final.StartsWith("\\?\", [StringComparison]::Ordinal)) { $final = $final.Substring(4) }
  if (-not $final.Equals($PathValue, [StringComparison]::OrdinalIgnoreCase)) {
    $handle.Dispose(); Fail "client_root_alias_rejected"
  }
  $information = [HelloLynkWindowsFileNative+BY_HANDLE_FILE_INFORMATION]::new()
  if (-not [HelloLynkWindowsFileNative]::GetFileInformationByHandle($handle, [ref]$information)) {
    $handle.Dispose(); Fail "client_file_identity_failed"
  }
  return [pscustomobject]@{
    Handle = $handle
    Volume = $information.VolumeSerialNumber
    IndexHigh = $information.FileIndexHigh
    IndexLow = $information.FileIndexLow
  }
}

function Test-HelloLynkSameIdentity($Left, $Right) {
  return (
    $Left.Volume -eq $Right.Volume -and
    $Left.IndexHigh -eq $Right.IndexHigh -and
    $Left.IndexLow -eq $Right.IndexLow
  )
}

function Enter-HelloLynkRootMutex([string]$CanonicalRoot) {
  $material = [Text.Encoding]::UTF8.GetBytes($script:CurrentSid.Value + "`0" + $CanonicalRoot.ToLowerInvariant())
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $hash = [Convert]::ToHexString($sha.ComputeHash($material)).ToLowerInvariant() } finally { $sha.Dispose() }
  $mutex = [Threading.Mutex]::new($false, ("Local\HelloLynk.ClientRoot.{0}" -f $hash))
  try { $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(15)) } catch [Threading.AbandonedMutexException] { $acquired = $true }
  if (-not $acquired) { $mutex.Dispose(); Fail "client_root_mutex_timeout" }
  return $mutex
}

function Exit-HelloLynkRootMutex($Mutex) {
  if ($null -eq $Mutex) { return }
  try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() }
}

function Ensure-HelloLynkSecureDirectory([string]$PathValue, [string]$ExistingAncestor = "") {
  if ([IO.Directory]::Exists($PathValue)) {
    Assert-HelloLynkNoReparseAncestors $PathValue
    Assert-HelloLynkSecureAcl $PathValue $true
    $identity = Open-HelloLynkIdentity $PathValue $true
    $identity.Handle.Dispose()
    return
  }
  $parent = [IO.Path]::GetDirectoryName($PathValue)
  if ($ExistingAncestor) {
    if (-not $parent.Equals($ExistingAncestor, [StringComparison]::OrdinalIgnoreCase)) {
      Ensure-HelloLynkSecureDirectory $parent $ExistingAncestor
    }
  } elseif (-not [IO.Directory]::Exists($parent)) {
    Ensure-HelloLynkSecureDirectory $parent
  }
  Assert-HelloLynkNoReparseAncestors $PathValue
  $descriptor = (New-HelloLynkAcl $true).GetSecurityDescriptorBinaryForm()
  if (-not [HelloLynkWindowsFileNative]::CreateProtectedDirectory($PathValue, $descriptor)) {
    Fail "client_root_create_race"
  }
  Assert-HelloLynkNoReparseAncestors $PathValue
  # Keep the Windows auto-inheritance marker used by child file ACL checks.
  Set-HelloLynkSecureAcl $PathValue $true
  Assert-HelloLynkSecureAcl $PathValue $true
  $identity = Open-HelloLynkIdentity $PathValue $true
  $identity.Handle.Dispose()
}

function Resolve-HelloLynkClientRoot([string]$RootValue, [bool]$Create) {
  $root = Normalize-HelloLynkAbsoluteFixedPath $RootValue
  Assert-HelloLynkNoReparseAncestors $root
  $mutex = Enter-HelloLynkRootMutex $root
  try {
    $existingAncestor = Assert-HelloLynkTrustedAncestorAcl $root $Create
    if ($Create) { Ensure-HelloLynkSecureDirectory $root $existingAncestor }
    if (-not [IO.Directory]::Exists($root)) { Fail "client_root_missing" }
    Assert-HelloLynkNoReparseAncestors $root
    Assert-HelloLynkSecureAcl $root $true
    $identity = Open-HelloLynkIdentity $root $true
    try {
      $null = Assert-HelloLynkTrustedAncestorAcl $root
      $canonical = $root
    } finally { $identity.Handle.Dispose() }
    return [pscustomobject]@{ Root = $canonical; Mutex = $mutex }
  } catch {
    Exit-HelloLynkRootMutex $mutex
    throw
  }
}

function Assert-HelloLynkPathInsideRoot([string]$Root, [string]$Candidate, [string]$Expected) {
  $candidateFull = Normalize-HelloLynkAbsoluteFixedPath $Candidate
  if (-not $candidateFull.Equals($Expected, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "client_root_path_invalid"
  }
  $prefix = $Root.TrimEnd([char[]]@('\')) + '\'
  if (-not $candidateFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "client_root_path_invalid"
  }
  return $candidateFull
}

function Read-HelloLynkSecureText([string]$PathValue, [int]$MaxBytes) {
  Assert-HelloLynkNoReparseAncestors $PathValue
  Assert-HelloLynkSecureAcl ([IO.Path]::GetDirectoryName($PathValue)) $true
  Assert-HelloLynkSecureAcl $PathValue $false
  $first = Open-HelloLynkIdentity $PathValue $false
  try {
    $stream = [IO.FileStream]::new($first.Handle, [IO.FileAccess]::Read)
    try {
      if ($stream.Length -gt $MaxBytes) { Fail "client_file_too_large" }
      $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $true, 4096, $true)
      try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $first.Handle = $null
  } finally {
    if ($null -ne $first.Handle) { $first.Handle.Dispose() }
  }
  Assert-HelloLynkNoReparseAncestors $PathValue
  Assert-HelloLynkSecureAcl $PathValue $false
  $second = Open-HelloLynkIdentity $PathValue $false
  try {
    if (-not (Test-HelloLynkSameIdentity $first $second)) { Fail "client_file_identity_changed" }
  } finally { $second.Handle.Dispose() }
  return $text
}

function Remove-HelloLynkVerifiedTemp([string]$TempPath) {
  if (-not [IO.File]::Exists($TempPath)) { return }
  Assert-HelloLynkNoReparseAncestors $TempPath
  Assert-HelloLynkSecureAcl $TempPath $false
  [IO.File]::Delete($TempPath)
}

function Write-HelloLynkSecureText([string]$PathValue, [string]$TextValue) {
  $parent = [IO.Path]::GetDirectoryName($PathValue)
  Ensure-HelloLynkSecureDirectory $parent
  if ([IO.File]::Exists($PathValue)) {
    Assert-HelloLynkNoReparseAncestors $PathValue
    Assert-HelloLynkSecureAcl $PathValue $false
  }
  $tempPath = Join-Path $parent (".{0}.{1}.tmp" -f [IO.Path]::GetFileName($PathValue), [Guid]::NewGuid().ToString("N"))
  try {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($TextValue)
    $stream = [IO.FileStream]::new($tempPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $stream.Write($bytes, 0, $bytes.Length)
      $stream.Flush($true)
    } finally { $stream.Dispose() }
    Set-HelloLynkSecureAcl $tempPath $false
    Assert-HelloLynkNoReparseAncestors $tempPath
    Assert-HelloLynkSecureAcl $tempPath $false
    $tempIdentity = Open-HelloLynkIdentity $tempPath $false
    $tempIdentity.Handle.Dispose()
    if (-not [HelloLynkWindowsFileNative]::MoveFileExW(
      $tempPath,
      $PathValue,
      [HelloLynkWindowsFileNative]::MOVEFILE_REPLACE_EXISTING -bor [HelloLynkWindowsFileNative]::MOVEFILE_WRITE_THROUGH
    )) { Fail "client_file_replace_failed" }
    Assert-HelloLynkNoReparseAncestors $PathValue
    Assert-HelloLynkSecureAcl $PathValue $false
    $finalIdentity = Open-HelloLynkIdentity $PathValue $false
    try {
      if (-not (Test-HelloLynkSameIdentity $tempIdentity $finalIdentity)) { Fail "client_file_identity_changed" }
    } finally { $finalIdentity.Handle.Dispose() }
  } finally {
    Remove-HelloLynkVerifiedTemp $tempPath
  }
}

# Returns $null when the file is absent. Anything present but unreadable fails:
# a damaged key file is never reported as missing.
function Read-HelloLynkE2eePrivateKeys([string]$KeysPath, [string]$KeysProfileId) {
  Assert-HelloLynkNoReparseAncestors $KeysPath
  if (-not [IO.File]::Exists($KeysPath)) { return $null }
  $serialized = Read-HelloLynkSecureText $KeysPath 524288
  try { $credential = [Management.Automation.PSSerializer]::Deserialize($serialized) } catch { Fail "e2ee_private_key_material_invalid" }
  if (
    $credential -isnot [Management.Automation.PSCredential] -or
    $credential.UserName -ne ("hellolynk-direct-text-e2ee-private-keys:v2:{0}" -f $KeysProfileId)
  ) { Fail "e2ee_private_key_material_binding_invalid" }
  $plain = $credential.GetNetworkCredential().Password
  if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 262144) { Fail "e2ee_private_key_material_too_large" }
  try { $wrapper = $plain | ConvertFrom-Json } catch { Fail "e2ee_private_key_material_invalid" }
  $propertyNames = @($wrapper.PSObject.Properties.Name)
  if (
    $propertyNames.Count -ne 3 -or
    $propertyNames -notcontains "schemaVersion" -or
    $propertyNames -notcontains "format" -or
    $propertyNames -notcontains "privateKeyMaterial" -or
    [int]$wrapper.schemaVersion -ne 2 -or
    [string]$wrapper.format -ne "hellolynk_direct_text_e2ee_private_keys_v2" -or
    [string]::IsNullOrWhiteSpace([string]$wrapper.privateKeyMaterial)
  ) { Fail "e2ee_private_key_material_invalid" }
  try { $null = [string]$wrapper.privateKeyMaterial | ConvertFrom-Json } catch { Fail "e2ee_private_key_material_invalid" }
  return $plain
}

try {
  if (-not $ClientRoot) {
    if ($StoreRoot -and [IO.Path]::GetFileName($StoreRoot.TrimEnd([char[]]@('\', '/'))) -ieq "credentials") {
      $ClientRoot = [IO.Path]::GetDirectoryName($StoreRoot.TrimEnd([char[]]@('\', '/')))
    } else {
      $ClientRoot = if ($StoreRoot) { $StoreRoot } elseif ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA "HelloLynk" } else { "" }
    }
  }
  if (-not $ClientRoot) { Fail "client_root_unavailable" }
  $createRoot = $Command -in @(
    "PrepareRoot", "StoreProfile", "StoreStatus", "Store", "StoreRuntimeSession", "StoreE2eePrivateKeys"
  )
  $rootSession = Resolve-HelloLynkClientRoot $ClientRoot $createRoot
  $clientRootFull = $rootSession.Root

  $expectedCredentialRoot = Join-Path $clientRootFull "credentials"
  $expectedE2eeRoot = Join-Path $clientRootFull "e2ee-private-keys"
  $storeRootFull = if ($StoreRoot) { Normalize-HelloLynkAbsoluteFixedPath $StoreRoot } else { $expectedCredentialRoot }
  $e2eeStoreRootFull = if ($E2eeStoreRoot) { Normalize-HelloLynkAbsoluteFixedPath $E2eeStoreRoot } else { $expectedE2eeRoot }
  if (
    -not $storeRootFull.Equals($clientRootFull, [StringComparison]::OrdinalIgnoreCase) -and
    -not $storeRootFull.Equals($expectedCredentialRoot, [StringComparison]::OrdinalIgnoreCase)
  ) { Fail "credential_store_root_invalid" }
  if (-not $e2eeStoreRootFull.Equals($expectedE2eeRoot, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "e2ee_private_key_store_root_invalid"
  }
  if ($storeRootFull.Equals($e2eeStoreRootFull, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "e2ee_private_key_store_not_separated"
  }
  if ($Command -eq "StoreE2eePrivateKeys") { Ensure-HelloLynkSecureDirectory $e2eeStoreRootFull }
  if (
    $Command -in @(
      "LoadE2eePrivateKeys", "LoadE2eePrivateKeysBatch", "RemoveE2eePrivateKeys"
    ) -and
    [IO.Directory]::Exists($e2eeStoreRootFull)
  ) { Ensure-HelloLynkSecureDirectory $e2eeStoreRootFull }
  if ($Command -in @("Store", "StoreRuntimeSession")) {
    Ensure-HelloLynkSecureDirectory $storeRootFull
  }
  if (
    $Command -in @("Load", "Remove", "ProbeCredential", "LoadRuntimeSession", "RemoveRuntimeSession") -and
    [IO.Directory]::Exists($storeRootFull)
  ) { Ensure-HelloLynkSecureDirectory $storeRootFull }
  $credentialPath = Join-Path $storeRootFull ("credential-{0}.dpapi.clixml" -f $ProfileId)
  $runtimeSessionPath = Join-Path $storeRootFull ("runtime-session-{0}.dpapi.clixml" -f $ProfileId)
  $e2eePrivateKeysPath = Join-Path $e2eeStoreRootFull ("direct-text-private-keys-{0}.dpapi.clixml" -f $ProfileId)

  switch ($Command) {
    "PrepareRoot" {
      foreach ($child in @("profiles", "credentials", "e2ee-private-keys", "status", "core", "platform", "bin", "host", "host\runtime", "releases")) {
        Ensure-HelloLynkSecureDirectory (Join-Path $clientRootFull $child)
      }
      Ensure-HelloLynkSecureDirectory (Join-Path $clientRootFull "platform\windows")
      Ensure-HelloLynkSecureDirectory (Join-Path $clientRootFull "core\vendor")
      [Console]::Out.Write("prepared")
    }
    { $_ -in @("SecureReleaseTree", "VerifyReleaseTree") } {
      if ($ManagedRelativePath -notmatch '^releases\\(?!\.{1,2}$)[A-Za-z0-9.][A-Za-z0-9_.-]{2,191}$') {
        Fail "client_release_path_invalid"
      }
      $releasePath = Assert-HelloLynkPathInsideRoot `
        $clientRootFull `
        (Join-Path $clientRootFull $ManagedRelativePath) `
        (Join-Path $clientRootFull $ManagedRelativePath)
      if (-not [IO.Directory]::Exists($releasePath)) { Fail "client_release_missing" }
      $pending = [Collections.Generic.Stack[string]]::new()
      $pending.Push($releasePath)
      while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        Assert-HelloLynkNoReparseAncestors $directory
        if ($Command -eq "SecureReleaseTree") { Set-HelloLynkSecureAcl $directory $true }
        Assert-HelloLynkSecureAcl $directory $true
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
          if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail "client_release_reparse_rejected"
          }
          if ($item.PSIsContainer) {
            $pending.Push($item.FullName)
          } elseif ([IO.File]::Exists($item.FullName)) {
            if ($Command -eq "SecureReleaseTree") { Set-HelloLynkSecureAcl $item.FullName $false }
            Assert-HelloLynkSecureAcl $item.FullName $false
          } else {
            Fail "client_release_entry_invalid"
          }
        }
      }
      [Console]::Out.Write($(if ($Command -eq "SecureReleaseTree") { "secured" } else { "verified" }))
    }
    "StoreProfile" {
      $path = Join-Path $clientRootFull ("profiles\{0}.json" -f $ProfileId)
      $plain = [Console]::In.ReadToEnd()
      if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 65536) { Fail "client_profile_too_large" }
      Write-HelloLynkSecureText $path $plain
      $plain = $null
      [Console]::Out.Write("stored")
    }
    "StoreStatus" {
      $path = Join-Path $clientRootFull ("status\{0}.json" -f $ProfileId)
      $plain = [Console]::In.ReadToEnd()
      if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 65536) { Fail "host_status_too_large" }
      Write-HelloLynkSecureText $path $plain
      $plain = $null
      [Console]::Out.Write("stored")
    }
    "ProbeCredential" {
      Assert-HelloLynkNoReparseAncestors $credentialPath
      if (-not [IO.File]::Exists($credentialPath)) { Fail "device_credential_missing" }
      Assert-HelloLynkSecureAcl $credentialPath $false
      $probe = Open-HelloLynkIdentity $credentialPath $false
      $probe.Handle.Dispose()
      [Console]::Out.Write("present")
    }
    "ValidateManagedFile" {
      if (
        [string]::IsNullOrWhiteSpace($ManagedRelativePath) -or
        $ManagedRelativePath -notmatch '^(?:core(?:\\vendor)?|platform\\windows|bin)\\[A-Za-z0-9_.-]+$'
      ) { Fail "client_managed_path_invalid" }
      $path = Assert-HelloLynkPathInsideRoot `
        $clientRootFull `
        (Join-Path $clientRootFull $ManagedRelativePath) `
        (Join-Path $clientRootFull $ManagedRelativePath)
      Assert-HelloLynkNoReparseAncestors $path
      if (-not [IO.File]::Exists($path)) { Fail "client_managed_file_missing" }
      Assert-HelloLynkSecureAcl $path $false
      $managedIdentity = Open-HelloLynkIdentity $path $false
      $managedIdentity.Handle.Dispose()
      [Console]::Out.Write("trusted")
    }
    "SecureManagedFile" {
      if (
        [string]::IsNullOrWhiteSpace($ManagedRelativePath) -or
        $ManagedRelativePath -notmatch '^(?:core(?:\\vendor)?|platform\\windows|bin)\\[A-Za-z0-9_.-]+$'
      ) { Fail "client_managed_path_invalid" }
      $path = Assert-HelloLynkPathInsideRoot `
        $clientRootFull `
        (Join-Path $clientRootFull $ManagedRelativePath) `
        (Join-Path $clientRootFull $ManagedRelativePath)
      Assert-HelloLynkNoReparseAncestors $path
      if (-not [IO.File]::Exists($path)) { Fail "client_managed_file_missing" }
      Set-HelloLynkSecureAcl $path $false
      Assert-HelloLynkSecureAcl $path $false
      $managedIdentity = Open-HelloLynkIdentity $path $false
      $managedIdentity.Handle.Dispose()
      [Console]::Out.Write("secured")
    }
    "Store" {
      $plain = [Console]::In.ReadToEnd()
      if ($plain -notmatch '^hellolynk_device_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{32,}$') {
        Fail "device_credential_invalid"
      }
      $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
      $credential = [Management.Automation.PSCredential]::new($ProfileId, $secure)
      try {
        $serialized = [Management.Automation.PSSerializer]::Serialize($credential)
        Write-HelloLynkSecureText $credentialPath $serialized
      } finally {
        $plain = $null
        $secure = $null
        $credential = $null
        $serialized = $null
      }
      [Console]::Out.Write("stored")
    }
    "Load" {
      Assert-HelloLynkNoReparseAncestors $credentialPath
      if (-not [IO.File]::Exists($credentialPath)) { Fail "device_credential_missing" }
      $serialized = Read-HelloLynkSecureText $credentialPath 262144
      try { $credential = [Management.Automation.PSSerializer]::Deserialize($serialized) } catch { Fail "device_credential_invalid" }
      if ($credential -isnot [Management.Automation.PSCredential] -or $credential.UserName -ne $ProfileId) {
        Fail "device_credential_binding_invalid"
      }
      $plain = $credential.GetNetworkCredential().Password
      if ($plain -notmatch '^hellolynk_device_v1_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{32,}$') {
        Fail "device_credential_invalid"
      }
      [Console]::Out.Write($plain)
      $plain = $null
      $credential = $null
      $serialized = $null
    }
    "Remove" {
      if ([IO.File]::Exists($credentialPath)) {
        Assert-HelloLynkNoReparseAncestors $credentialPath
        Assert-HelloLynkSecureAcl $credentialPath $false
        [IO.File]::Delete($credentialPath)
      }
      [Console]::Out.Write("removed")
    }
    "StoreRuntimeSession" {
      $plain = [Console]::In.ReadToEnd()
      if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 65536) { Fail "runtime_session_too_large" }
      try { $session = $plain | ConvertFrom-Json } catch { Fail "runtime_session_invalid" }
      if (
        [int]$session.schemaVersion -ne 1 -or
        [string]$session.sessionId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$' -or
        [string]$session.runtimeId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$' -or
        [string]$session.principalId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$' -or
        [string]$session.agentId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$' -or
        [string]$session.deviceId -notmatch '^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$' -or
        [string]$session.sessionSecret -notmatch '^runtime_[a-f0-9]{48}$' -or
        [double]$session.expiresAtMs -le 0
      ) { Fail "runtime_session_invalid" }
      $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
      $credential = [Management.Automation.PSCredential]::new(("runtime-session:{0}" -f $ProfileId), $secure)
      try {
        $serialized = [Management.Automation.PSSerializer]::Serialize($credential)
        Write-HelloLynkSecureText $runtimeSessionPath $serialized
      } finally {
        $plain = $null
        $session = $null
        $secure = $null
        $credential = $null
        $serialized = $null
      }
      [Console]::Out.Write("stored")
    }
    "LoadRuntimeSession" {
      Assert-HelloLynkNoReparseAncestors $runtimeSessionPath
      if (-not [IO.File]::Exists($runtimeSessionPath)) {
        [Console]::Out.Write("missing")
        break
      }
      $serialized = Read-HelloLynkSecureText $runtimeSessionPath 262144
      try { $credential = [Management.Automation.PSSerializer]::Deserialize($serialized) } catch { Fail "runtime_session_invalid" }
      if (
        $credential -isnot [Management.Automation.PSCredential] -or
        $credential.UserName -ne ("runtime-session:{0}" -f $ProfileId)
      ) { Fail "runtime_session_binding_invalid" }
      $plain = $credential.GetNetworkCredential().Password
      try { $session = $plain | ConvertFrom-Json } catch { Fail "runtime_session_invalid" }
      if (
        [int]$session.schemaVersion -ne 1 -or
        [string]$session.sessionSecret -notmatch '^runtime_[a-f0-9]{48}$' -or
        [double]$session.expiresAtMs -le 0
      ) { Fail "runtime_session_invalid" }
      [Console]::Out.Write($plain)
      $plain = $null
      $session = $null
      $credential = $null
      $serialized = $null
    }
    "RemoveRuntimeSession" {
      if ([IO.File]::Exists($runtimeSessionPath)) {
        Assert-HelloLynkNoReparseAncestors $runtimeSessionPath
        Assert-HelloLynkSecureAcl $runtimeSessionPath $false
        [IO.File]::Delete($runtimeSessionPath)
      }
      [Console]::Out.Write("removed")
    }
    "StoreE2eePrivateKeys" {
      $plain = [Console]::In.ReadToEnd()
      # A SecureString holds at most 65536 characters. Larger keys fail here,
      # before the existing file is touched.
      if ($plain.Length -gt 65536) { Fail "e2ee_private_key_material_too_large" }
      try { $wrapper = $plain | ConvertFrom-Json } catch { Fail "e2ee_private_key_material_invalid" }
      $propertyNames = @($wrapper.PSObject.Properties.Name)
      if (
        $propertyNames.Count -ne 3 -or
        $propertyNames -notcontains "schemaVersion" -or
        $propertyNames -notcontains "format" -or
        $propertyNames -notcontains "privateKeyMaterial" -or
        [int]$wrapper.schemaVersion -ne 2 -or
        [string]$wrapper.format -ne "hellolynk_direct_text_e2ee_private_keys_v2" -or
        [string]::IsNullOrWhiteSpace([string]$wrapper.privateKeyMaterial) -or
        [Text.Encoding]::UTF8.GetByteCount([string]$wrapper.privateKeyMaterial) -gt 98304
      ) { Fail "e2ee_private_key_material_invalid" }
      try {
        $material = [string]$wrapper.privateKeyMaterial | ConvertFrom-Json
      } catch { Fail "e2ee_private_key_material_invalid" }
      if ($null -eq $material -or $material -is [Array]) { Fail "e2ee_private_key_material_invalid" }
      $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
      $credential = [Management.Automation.PSCredential]::new(
        ("hellolynk-direct-text-e2ee-private-keys:v2:{0}" -f $ProfileId),
        $secure
      )
      try {
        $serialized = [Management.Automation.PSSerializer]::Serialize($credential)
        Write-HelloLynkSecureText $e2eePrivateKeysPath $serialized
      } finally {
        $plain = $null
        $wrapper = $null
        $material = $null
        $secure = $null
        $credential = $null
        $serialized = $null
      }
      [Console]::Out.Write("stored")
    }
    "LoadE2eePrivateKeys" {
      $plain = Read-HelloLynkE2eePrivateKeys $e2eePrivateKeysPath $ProfileId
      [Console]::Out.Write($(if ($null -eq $plain) { "missing" } else { $plain }))
      $plain = $null
    }
    "LoadE2eePrivateKeysBatch" {
      # stdin: a JSON array of distinct profile IDs. One root check and one
      # process serve every profile; any damaged file fails the whole batch.
      try { $requested = [Console]::In.ReadToEnd() | ConvertFrom-Json -NoEnumerate } catch { Fail "e2ee_private_key_batch_invalid" }
      if ($requested -isnot [Array] -or $requested.Count -lt 1 -or $requested.Count -gt 64) { Fail "e2ee_private_key_batch_invalid" }
      $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
      foreach ($id in $requested) {
        if ($id -isnot [string] -or $id -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$' -or -not $seen.Add($id)) {
          Fail "e2ee_private_key_batch_invalid"
        }
      }
      $entries = [Collections.Generic.List[string]]::new()
      foreach ($id in $requested) {
        $plain = Read-HelloLynkE2eePrivateKeys (Join-Path $e2eeStoreRootFull ("direct-text-private-keys-{0}.dpapi.clixml" -f $id)) $id
        $entries.Add($(if ($null -eq $plain) { '{{"profileId":"{0}","state":"missing"}}' -f $id } else {
          '{{"profileId":"{0}","state":"present","value":"{1}"}}' -f $id, [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain))
        }))
        $plain = $null
      }
      [Console]::Out.Write("[" + ($entries -join ",") + "]")
      $entries = $null
    }
    "RemoveE2eePrivateKeys" {
      if ([IO.File]::Exists($e2eePrivateKeysPath)) {
        Assert-HelloLynkNoReparseAncestors $e2eePrivateKeysPath
        Assert-HelloLynkSecureAcl $e2eePrivateKeysPath $false
        [IO.File]::Delete($e2eePrivateKeysPath)
      }
      [Console]::Out.Write("removed")
    }
  }
} catch {
  $message = [string]$_.Exception.Message
  if ($message -match '^[a-z][a-z0-9_]{0,127}$') { Fail $message }
  Fail "credential_store_operation_failed"
} finally {
  if ($null -ne $rootSession) { Exit-HelloLynkRootMutex $rootSession.Mutex }
}
