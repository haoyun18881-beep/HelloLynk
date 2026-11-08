param(
  [ValidateSet("OpenClaw")]
  [string]$Client = "OpenClaw",

  [string]$OpenClawConfig = (Join-Path $env:USERPROFILE ".openclaw\openclaw.json"),

  [switch]$WaitForUser,

  [switch]$AtomicReplace
)

$ErrorActionPreference = "Stop"
[Console]::SetIn([IO.StreamReader]::new([Console]::OpenStandardInput(), [Text.UTF8Encoding]::new($false, $true)))

function Write-AtomicResult([string]$Code, [int]$ExitCode) {
  [Console]::Out.Write($Code)
  exit $ExitCode
}

function Assert-PlainPath([string]$Candidate, [string]$ExpectedParent = "") {
  $absolute = [IO.Path]::GetFullPath($Candidate)
  if ($ExpectedParent -and -not [StringComparer]::OrdinalIgnoreCase.Equals([IO.Path]::GetDirectoryName($absolute), $ExpectedParent)) {
    throw "agent_setup_config_path_invalid"
  }
  $cursor = if ([IO.File]::Exists($absolute)) { $absolute } else { [IO.Path]::GetDirectoryName($absolute) }
  while ($cursor) {
    if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "agent_setup_config_reparse_rejected"
    }
    $parent = [IO.Path]::GetDirectoryName($cursor)
    if (-not $parent -or $parent -eq $cursor) { break }
    $cursor = $parent
  }
  return $absolute
}

function Initialize-NativeFileIdentity {
  if ("HelloLynk.NativeFileIdentity" -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace HelloLynk {
  public static class NativeFileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation {
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

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
      SafeFileHandle handle,
      out ByHandleFileInformation information
    );

    public static string Get(SafeFileHandle handle, out uint attributes) {
      ByHandleFileInformation information;
      if (!GetFileInformationByHandle(handle, out information)) {
        throw new Win32Exception(Marshal.GetLastWin32Error());
      }
      attributes = information.FileAttributes;
      return String.Format("{0:X8}:{1:X8}{2:X8}",
        information.VolumeSerialNumber,
        information.FileIndexHigh,
        information.FileIndexLow);
    }
  }
}
'@
}

function Get-FileSnapshot([string]$Candidate) {
  Initialize-NativeFileIdentity
  $stream = [IO.File]::Open($Candidate, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    [uint32]$attributes = 0
    $identity = [HelloLynk.NativeFileIdentity]::Get($stream.SafeFileHandle, [ref]$attributes)
    if (($attributes -band [uint32][IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "agent_setup_config_reparse_rejected"
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $hash = [Convert]::ToHexString($hasher.ComputeHash($stream)) } finally { $hasher.Dispose() }
    $security = [IO.FileSystemAclExtensions]::GetAccessControl($stream)
    return [pscustomobject]@{
      Identity = $identity
      Hash = $hash
      Dacl = $security.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
      Owner = $security.GetOwner([Security.Principal.SecurityIdentifier]).Value
      Group = $security.GetGroup([Security.Principal.SecurityIdentifier]).Value
      Security = $security.GetSecurityDescriptorSddlForm(
        [Security.AccessControl.AccessControlSections]::Access -bor
        [Security.AccessControl.AccessControlSections]::Owner -bor
        [Security.AccessControl.AccessControlSections]::Group
      )
    }
  } finally { $stream.Dispose() }
}

function Set-Dacl([string]$Candidate, [Security.AccessControl.FileSecurity]$Security, [string]$ExpectedHash) {
  $snapshot = Get-FileSnapshot $Candidate
  if (-not [StringComparer]::OrdinalIgnoreCase.Equals($snapshot.Hash, $ExpectedHash)) {
    throw "agent_setup_config_changed"
  }
  [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Candidate), $Security)
}

function Restore-FileSecurity([string]$Candidate, [string]$ExpectedHash, [string]$ExpectedSecurity) {
  $snapshot = Get-FileSnapshot $Candidate
  if ($snapshot.Hash -ne $ExpectedHash) { throw "agent_setup_config_rollback_failed" }
  $security = [Security.AccessControl.FileSecurity]::new()
  $security.SetSecurityDescriptorSddlForm(
    $ExpectedSecurity,
    [Security.AccessControl.AccessControlSections]::Access -bor
    [Security.AccessControl.AccessControlSections]::Owner -bor
    [Security.AccessControl.AccessControlSections]::Group
  )
  [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Candidate), $security)
}

function Invoke-AtomicReplace {
  try {
    $controlText = [Console]::In.ReadToEnd()
    if (-not $controlText -or $controlText.Length -gt 32768) { throw "agent_setup_config_control_invalid" }
    $control = $controlText | ConvertFrom-Json -ErrorAction Stop
    if (@($control.psobject.Properties.Name).Count -ne 4 -or
        -not $control.configPath -or -not $control.temporary -or
        $control.expectedSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or
        $control.replacementSha256 -notmatch '^[A-Fa-f0-9]{64}$') {
      throw "agent_setup_config_control_invalid"
    }

    $target = Assert-PlainPath ([string]$control.configPath)
    $parent = [IO.Path]::GetDirectoryName($target)
    $temporary = Assert-PlainPath ([string]$control.temporary) $parent
    if (-not [IO.File]::Exists($temporary) -or [IO.Directory]::Exists($temporary)) {
      throw "agent_setup_config_temporary_invalid"
    }

    if (-not [IO.File]::Exists($target)) {
      $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
      $security = [Security.AccessControl.FileSecurity]::new()
      $security.SetOwner($identity.User)
      $security.SetAccessRuleProtection($true, $false)
      $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity.User,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
      )
      $security.AddAccessRule($rule)
      Set-Dacl $temporary $security ([string]$control.replacementSha256)
      $securedTemporary = Get-FileSnapshot $temporary
      [IO.File]::Move($temporary, $target, $false)
      $newSnapshot = Get-FileSnapshot $target
      if ($newSnapshot.Hash -ne [string]$control.replacementSha256 -or
          $newSnapshot.Dacl -ne $securedTemporary.Dacl -or
          $newSnapshot.Owner -ne $securedTemporary.Owner -or
          $newSnapshot.Group -ne $securedTemporary.Group) {
        throw "agent_setup_config_acl_unsafe"
      }
      Write-AtomicResult "agent_setup_config_replace_ok" 0
    }

    if ([IO.Directory]::Exists($target)) { throw "agent_setup_config_invalid" }
    $before = Get-FileSnapshot $target
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($before.Hash, [string]$control.expectedSha256)) {
      throw "agent_setup_config_changed"
    }
    $replacement = Get-FileSnapshot $temporary
    if ($replacement.Hash -ne [string]$control.replacementSha256) {
      throw "agent_setup_config_temporary_changed"
    }
    # ReplaceFileW can retain the temporary file's owner and add an explicit ACE
    # for the original owner. Give it the exact original security first; do not
    # weaken the post-replace comparison to accept that metadata change.
    $replacementSecurity = [Security.AccessControl.FileSecurity]::new()
    $replacementSecurity.SetSecurityDescriptorSddlForm(
      $before.Security,
      [Security.AccessControl.AccessControlSections]::Access -bor
      [Security.AccessControl.AccessControlSections]::Owner -bor
      [Security.AccessControl.AccessControlSections]::Group
    )
    Set-Dacl $temporary $replacementSecurity ([string]$control.replacementSha256)
    # HELLOLYNK_TEST_PRE_REPLACE_IDENTITY_INJECTION_POINT
    # A second snapshot narrows the unavoidable path-based ReplaceFileW window. A process
    # already running as this Windows account remains outside this configurator's trust boundary.
    $target = Assert-PlainPath $target
    $immediate = Get-FileSnapshot $target
    if ($immediate.Identity -ne $before.Identity -or
        $immediate.Hash -ne $before.Hash -or
        $immediate.Dacl -ne $before.Dacl -or
        $immediate.Owner -ne $before.Owner -or
        $immediate.Group -ne $before.Group) {
      throw "agent_setup_config_changed"
    }
    $securedReplacement = Get-FileSnapshot $temporary
    if ($securedReplacement.Identity -ne $replacement.Identity -or
        $securedReplacement.Hash -ne [string]$control.replacementSha256 -or
        $securedReplacement.Dacl -ne $before.Dacl -or
        $securedReplacement.Owner -ne $before.Owner -or
        $securedReplacement.Group -ne $before.Group) {
      throw "agent_setup_config_temporary_changed"
    }

    $backup = Join-Path $parent (".{0}.{1}.bak" -f [IO.Path]::GetFileName($target), [guid]::NewGuid().ToString("N"))
    [IO.File]::Replace($temporary, $target, $backup, $true)
    # HELLOLYNK_TEST_POST_REPLACE_ACL_INJECTION_POINT
    try {
      $after = Get-FileSnapshot $target
      if ($after.Hash -ne [string]$control.replacementSha256 -or
          $after.Dacl -ne $before.Dacl -or
          $after.Owner -ne $before.Owner -or
          $after.Group -ne $before.Group) {
        throw "agent_setup_config_acl_unsafe"
      }
      [IO.File]::Delete($backup)
    } catch {
      $failureCode = [string]$_.Exception.Message
      try {
        if (-not [IO.File]::Exists($backup)) { throw "agent_setup_config_rollback_failed" }
        [IO.File]::Replace($backup, $target, $temporary, $true)
        Restore-FileSecurity $target $before.Hash $before.Security
        $restored = Get-FileSnapshot $target
        if ($restored.Hash -ne $before.Hash -or $restored.Dacl -ne $before.Dacl -or
            $restored.Owner -ne $before.Owner -or $restored.Group -ne $before.Group) {
          throw "agent_setup_config_rollback_failed"
        }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
        if ([IO.File]::Exists($temporary) -or [IO.File]::Exists($backup)) {
          throw "agent_setup_config_rollback_failed"
        }
      } catch {
        throw "agent_setup_config_rollback_failed"
      }
      throw $failureCode
    }
    Write-AtomicResult "agent_setup_config_replace_ok" 0
  } catch {
    $code = [string]$_.Exception.Message
    if ($code -notmatch '^[a-z][a-z0-9_]{0,127}$') { $code = "agent_setup_config_replace_failed" }
    Write-AtomicResult $code 1
  }
}

if ($AtomicReplace) { Invoke-AtomicReplace }

$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\..\.."))
$configurator = Join-Path $projectRoot "clients\core\hellolynk-agent-configurator.mjs"
$pluginPath = Join-Path $projectRoot "integrations\openclaw-channel"
$nodePath = (Get-Command node -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source

if (-not (Test-Path -LiteralPath $configurator -PathType Leaf)) { throw "hellolynk_agent_configurator_missing" }
if (-not (Test-Path -LiteralPath (Join-Path $pluginPath "openclaw.plugin.json") -PathType Leaf)) { throw "hellolynk_openclaw_plugin_missing" }
if (-not (Test-Path -LiteralPath $OpenClawConfig -PathType Leaf)) { throw "openclaw_config_missing" }

try {
  Write-Host "HelloLynk 正在为 OpenClaw（开放爪）配置本机中立 Host 表面。" -ForegroundColor Cyan
  Write-Host "本步骤不读取旧 profile、不输入 KEY、不写入设备凭据。"
  Write-Host "OpenClaw 的受保护 capability binding 必须已由 HelloLynk Host 安全配置；若缺失将安全停止。"

  $configureOutput = & $nodePath $configurator openclaw `
    --config-path $OpenClawConfig `
    --plugin-path $pluginPath
  if ($LASTEXITCODE -ne 0) { throw "openclaw_neutral_configuration_failed" }

  Write-Host "配置完成：OpenClaw 将仅通过本机 HelloLynk Host 受限表面工作。" -ForegroundColor Green
  Write-Host "请先关闭本窗口，再由人类重启 OpenClaw；配置程序不会自行启停 Host 或 OpenClaw。" -ForegroundColor Yellow
  Write-Output '{"ok":true,"client":"openclaw","mode":"neutral","bindingRef":"protected-store:openclaw","secretRead":false,"secretPrinted":false,"restartRequired":true}'
} finally {
  if ($WaitForUser) { Read-Host "按回车关闭此窗口" | Out-Null }
}
