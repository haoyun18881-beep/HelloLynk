param(
  [Parameter(Mandatory = $true)]
  [ValidateSet(
    "Issue", "Load", "Revoke", "Rotate", "Status", "DisconnectLocalClient",
    "SaveCodexNeutralBinding", "ResolveCodexNeutralBinding", "VerifyCodexNeutralBinding", "RemoveCodexNeutralBinding", "ReplaceCodexNeutralBinding", "MigrateCodexNeutralBinding",
    "SaveOpenClawNeutralBinding", "ResolveOpenClawNeutralBinding", "VerifyOpenClawNeutralBinding", "RemoveOpenClawNeutralBinding", "MigrateOpenClawNeutralBinding",
    "SaveTraeWorkNeutralBinding", "ResolveTraeWorkNeutralBinding", "VerifyTraeWorkNeutralBinding", "RemoveTraeWorkNeutralBinding", "MigrateTraeWorkNeutralBinding",
    "SaveWorkBuddyNeutralBinding", "ResolveWorkBuddyNeutralBinding", "VerifyWorkBuddyNeutralBinding", "RemoveWorkBuddyNeutralBinding", "MigrateWorkBuddyNeutralBinding",
    "SaveClaudeCodeNeutralBinding", "ResolveClaudeCodeNeutralBinding", "VerifyClaudeCodeNeutralBinding", "RemoveClaudeCodeNeutralBinding", "MigrateClaudeCodeNeutralBinding",
    "SaveCursorNeutralBinding", "ResolveCursorNeutralBinding", "VerifyCursorNeutralBinding", "RemoveCursorNeutralBinding", "MigrateCursorNeutralBinding",
    "SaveDshNeutralBinding", "ResolveDshNeutralBinding", "VerifyDshNeutralBinding", "RemoveDshNeutralBinding", "MigrateDshNeutralBinding", "RestoreDshNeutralBinding",
    "SaveTransportCredential", "LoadTransportCredential", "RevokeTransportCredential",
    "VerifyTransportCredentialLifetimeMigration", "MigrateTransportCredentialLifetime",
    "SaveTransportSession", "LoadTransportSession", "RemoveTransportSession",
    "ReplaceTransportSession", "ResolveTransport", "VerifyTransport", "VerifyPath",
    "LoadDeviceEnrollment", "SaveDeviceEnrollment", "SaveEnrollmentTransportCredential"
  )]
  [string]$Command,

  [Parameter(Mandatory = $true)]
  [string]$StoreRoot,

  [string]$CapabilityId,
  [string]$CredentialId,
  [string]$SessionId,
  [string]$PrincipalId,
  [string]$HostInstallationId,
  [int64]$Timestamp = -1,
  [string]$PathToVerify,
  [switch]$VerifyDirectory,
  [switch]$VerifyOnly,
  [string]$ResultPipeName
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
# The Node caller writes UTF-8 to a pipe. Decode that protocol explicitly,
# independent of the inherited Windows console code page (including names).
[Console]::SetIn([IO.StreamReader]::new([Console]::OpenStandardInput(), [Text.UTF8Encoding]::new($false, $true)))
$CapabilityIdPattern = '^cap_[A-Za-z0-9_-]{32}$'
$IdentifierPattern = '^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'
$SecretPattern = '^[A-Za-z0-9_-]{43}$'
$Contract = 'hellolynk-host-protected-store-v1'
$RecordContract = 'hellolynk-host-capability-v1'
$TransportCredentialContract = 'hellolynk-host-transport-credential-v1'
$TransportSessionContract = 'hellolynk-host-transport-session-v1'
$AuthorizationHistoryContract = 'hellolynk-host-authorization-history-v1'
$CodexNeutralBindingContract = 'hellolynk-codex-neutral-binding-v1'
$OpenClawNeutralBindingContract = 'hellolynk-openclaw-neutral-binding-v1'
$TraeWorkNeutralBindingContract = 'hellolynk-trae-work-neutral-binding-v1'
$WorkBuddyNeutralBindingContract = 'hellolynk-workbuddy-neutral-binding-v1'
$ClaudeCodeNeutralBindingContract = 'hellolynk-claude-code-neutral-binding-v1'
$CursorNeutralBindingContract = 'hellolynk-cursor-neutral-binding-v1'
$DshNeutralBindingContract = 'hellolynk-dsh-neutral-binding-v1'
$CodexNeutralScopes = @(
  'app-data:authorized-messaging',
  'app-data:changes-read',
  'app-data:contact-requests-read',
  'app-data:contacts-manage',
  'app-data:contacts-read',
  'app-data:human-send-request',
  'app-data:inbox-manage',
  'app-data:inbox-read',
  'app-data:outbox-read',
  'app-data:outbox-retry',
  'attachments:manage',
  'surface:human-ui',
  'ui:launch'
)
$OpenClawNeutralScopes = @($CodexNeutralScopes)
$CodexNeutralPreviousScopes = @($CodexNeutralScopes | Where-Object { $_ -cne 'app-data:authorized-messaging' })
$OpenClawNeutralPreviousScopes = @($CodexNeutralPreviousScopes)
$TraeWorkNeutralScopes = @(
  'app-data:authorized-messaging',
  'app-data:changes-read',
  'app-data:contact-requests-read',
  'app-data:contacts-manage',
  'app-data:contacts-read',
  'app-data:human-send-request',
  'app-data:inbox-manage',
  'app-data:inbox-read',
  'app-data:outbox-read',
  'app-data:outbox-retry',
  'attachments:manage',
  'status:read',
  'surface:human-ui',
  'ui:launch'
)
$WorkBuddyNeutralScopes = @($TraeWorkNeutralScopes)
$ClaudeCodeNeutralScopes = @($WorkBuddyNeutralScopes)
$TraeWorkNeutralPreviousScopes = @($TraeWorkNeutralScopes | Where-Object { $_ -cne 'app-data:authorized-messaging' })
$WorkBuddyNeutralPreviousScopes = @($TraeWorkNeutralPreviousScopes)
$TraeWorkNeutralLegacyScopes = @(
  'app-data:human-send-request',
  'attachments:manage',
  'status:read',
  'surface:human-ui'
)
$WorkBuddyNeutralLegacyScopes = @($TraeWorkNeutralLegacyScopes)
$CursorNeutralScopes = @(
  'app-data:authorized-messaging',
  'app-data:changes-read',
  'app-data:contact-requests-read',
  'app-data:contacts-manage',
  'app-data:contacts-read',
  'app-data:human-send-request',
  'app-data:inbox-manage',
  'app-data:inbox-read',
  'app-data:outbox-read',
  'app-data:outbox-retry',
  'attachments:manage',
  'status:read',
  'surface:human-ui',
  'ui:launch'
)
$CursorNeutralPreviousScopes = @($CursorNeutralScopes | Where-Object { $_ -cne 'app-data:authorized-messaging' })
$DshNeutralScopes = @($CursorNeutralScopes)
$DshNeutralPreviousScopes = @($CursorNeutralPreviousScopes)
$TransportCredentialSecretPattern = '^hellolynk_host_transport_v1_([A-Za-z0-9_-]{3,127})\.([A-Za-z0-9_-]{32,})$'
$TransportSessionIdPattern = '^hosttransportsession_[A-Za-z0-9_-]{16,}$'
$TransportSessionSecretPattern = '^hostsession_[a-f0-9]{48}$'
$CredentialName = 'hellolynk-neutral-host-protected-store-v1'
$EnvelopeContract = 'hellolynk-host-protected-envelope-v2'
$RetiredIndexContract = 'hellolynk-retired-transport-index-v1'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class HelloLynkProtectedStoreNativePath {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern SafeFileHandle CreateFile(
    string name, uint access, uint share, IntPtr security, uint creation,
    uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern uint GetFinalPathNameByHandle(
    SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
'@

function Fail([string]$Code) {
  [Console]::Error.WriteLine($Code)
  exit 1
}

function Test-ClaudeCodeStoreRoot([string]$Value) {
  return $Value -match '(?i)[\\/]host$'
}

function Test-ExactScopeSequence($Actual, [string[]]$Expected) {
  if ($Actual -isnot [Array] -or $Actual.Count -ne $Expected.Count) { return $false }
  for ($index = 0; $index -lt $Expected.Count; $index += 1) {
    if ([string]$Actual[$index] -cne [string]$Expected[$index]) { return $false }
  }
  return $true
}

function Test-FullyQualifiedCanonicalPath([string]$Value) {
  try {
    if (-not $Value -or -not [IO.Path]::IsPathFullyQualified($Value)) { return $false }
    $null = [IO.Path]::GetFullPath($Value)
    return $true
  } catch { return $false }
}

function Assert-ExactFields($Value, [string[]]$Expected, [string]$Code) {
  if ($null -eq $Value -or $Value -is [Array]) { Fail $Code }
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $wanted = @($Expected | Sort-Object)
  if ($actual.Count -ne $wanted.Count) { Fail $Code }
  for ($index = 0; $index -lt $wanted.Count; $index += 1) {
    if ($actual[$index] -cne $wanted[$index]) { Fail $Code }
  }
}

function Assert-Record($Record) {
  Assert-ExactFields $Record @(
    'adapterId', 'capabilityId', 'contract', 'delegateId', 'hostInstallationId',
    'issuedAt', 'principalId', 'region', 'revokedAt', 'scopes', 'secret',
    'state', 'version'
  ) 'host_capability_fields_invalid'
  if (
    [string]$Record.contract -cne $RecordContract -or
    [string]$Record.capabilityId -notmatch $CapabilityIdPattern -or
    [string]$Record.region -notmatch $IdentifierPattern -or
    [string]$Record.principalId -notmatch $IdentifierPattern -or
    [string]$Record.delegateId -notmatch $IdentifierPattern -or
    [string]$Record.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Record.adapterId -notmatch $IdentifierPattern -or
    [int64]$Record.version -lt 1 -or
    @('active', 'revoked') -notcontains [string]$Record.state -or
    [int64]$Record.issuedAt -lt 0 -or
    [string]$Record.secret -notmatch $SecretPattern -or
    $Record.scopes -isnot [Array] -or
    $Record.scopes.Count -lt 1 -or
    $Record.scopes.Count -gt 64
  ) { Fail 'host_capability_invalid' }
  if (
    ([string]$Record.state -eq 'active' -and $null -ne $Record.revokedAt) -or
    ([string]$Record.state -eq 'revoked' -and [int64]$Record.revokedAt -lt [int64]$Record.issuedAt)
  ) { Fail 'host_capability_state_invalid' }
  $previous = $null
  foreach ($scope in $Record.scopes) {
    if ([string]$scope -notmatch $IdentifierPattern) { Fail 'host_capability_scope_invalid' }
    if ($null -ne $previous -and [string]::CompareOrdinal([string]$previous, [string]$scope) -ge 0) {
      Fail 'host_capability_scopes_noncanonical'
    }
    $previous = [string]$scope
  }
  return $Record
}

function Assert-CodexNeutralBinding($Binding, [bool]$ValidatePaths) {
  Assert-ExactFields $Binding @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'profileManifestPath', 'region', 'releaseManifestSha256', 'releaseRoot', 'runnerRelativePath',
    'runtimeRoot', 'scopes', 'version'
  ) 'neutral_codex_binding_invalid'
  if (
    [string]$Binding.contract -cne $CodexNeutralBindingContract -or
    [string]$Binding.region -notmatch $IdentifierPattern -or
    [string]$Binding.principalId -notmatch $IdentifierPattern -or
    [string]$Binding.delegateId -notmatch $IdentifierPattern -or
    [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Binding.profileId -notmatch $IdentifierPattern -or
    [string]$Binding.adapterId -cne 'codex' -or
    [int64]$Binding.version -ne 2 -or
    $Binding.scopes -isnot [Array] -or
    (-not (Test-ExactScopeSequence $Binding.scopes $CodexNeutralScopes) -and
      -not (Test-ExactScopeSequence $Binding.scopes $CodexNeutralPreviousScopes)) -or
    [string]$Binding.runnerRelativePath -notmatch '^(?:[A-Za-z0-9][A-Za-z0-9._-]*/)*[A-Za-z0-9][A-Za-z0-9._-]*\.mjs$' -or
    [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$'
  ) { Fail 'neutral_codex_binding_invalid' }
  if ($ValidatePaths) { Assert-CodexNeutralPaths $Binding }
  return $Binding
}

function Assert-CodexNeutralPaths($Binding) {
  $releaseRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.releaseRoot) $true 0
  $runtimeRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.runtimeRoot) $true 0
  $profileManifestPath = Assert-AbsoluteNonReparsePath ([string]$Binding.profileManifestPath) $false 65536
  $runnerPath = [IO.Path]::GetFullPath((Join-Path $releaseRoot ([string]$Binding.runnerRelativePath)))
  $releasePrefix = $releaseRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not $runnerPath.StartsWith($releasePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'neutral_codex_runner_integrity_invalid'
  }
  $null = Assert-AbsoluteNonReparsePath $runnerPath $false 1048576
  if (
    -not [string]::Equals($runtimeRoot, [IO.Path]::GetFullPath([string]$Binding.runtimeRoot), [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals($profileManifestPath, [IO.Path]::GetFullPath([string]$Binding.profileManifestPath), [StringComparison]::OrdinalIgnoreCase)
  ) { Fail 'neutral_codex_binding_invalid' }
}

function Assert-AbsoluteNonReparsePath(
  [string]$Value,
  [bool]$Directory,
  [int64]$MaxBytes,
  [string]$BindingInvalidCode = 'neutral_codex_binding_invalid',
  [string]$PathInvalidCode = 'neutral_codex_launch_manifest_invalid'
) {
  if (-not $Value -or -not [IO.Path]::IsPathFullyQualified($Value)) { Fail $BindingInvalidCode }
  $full = [IO.Path]::GetFullPath($Value)
  $rootPart = [IO.Path]::GetPathRoot($full)
  $cursor = $rootPart
  $relative = $full.Substring($rootPart.Length)
  foreach ($segment in $relative.Split([IO.Path]::DirectorySeparatorChar, [StringSplitOptions]::RemoveEmptyEntries)) {
    $cursor = Join-Path $cursor $segment
    if (-not (Test-Path -LiteralPath $cursor)) { Fail $PathInvalidCode }
    $item = Get-Item -LiteralPath $cursor -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail $PathInvalidCode
    }
  }
  $target = Get-Item -LiteralPath $full -Force
  if ($Directory) {
    if (-not $target.PSIsContainer) { Fail $BindingInvalidCode }
  } else {
    if ($target.PSIsContainer -or $target.Length -gt $MaxBytes) { Fail $PathInvalidCode }
  }
  return $full
}

function Assert-ProtectedStoreNoReparse([string]$Path) {
  $current = [IO.Path]::GetFullPath($Path)
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      $item = Get-Item -LiteralPath $current -Force
      if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'host_protected_store_root_invalid'
      }
    }
    $parent = [IO.Directory]::GetParent($current)
    if ($null -eq $parent) { break }
    $current = $parent.FullName
  }
}

function Get-ProtectedStoreCanonicalLocalRoot([string]$Path) {
  $handle = [HelloLynkProtectedStoreNativePath]::CreateFile(
    $Path, 0, 7, [IntPtr]::Zero, 3, 0x02000000, [IntPtr]::Zero
  )
  if ($handle.IsInvalid) { $handle.Dispose(); Fail 'host_protected_store_root_invalid' }
  try {
    $buffer = [Text.StringBuilder]::new(32768)
    $length = [HelloLynkProtectedStoreNativePath]::GetFinalPathNameByHandle(
      $handle, $buffer, $buffer.Capacity, 0
    )
    if ($length -eq 0 -or $length -ge $buffer.Capacity) { Fail 'host_protected_store_root_invalid' }
    $final = $buffer.ToString()
  } finally { $handle.Dispose() }
  if ($final.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'host_protected_store_root_invalid'
  }
  if ($final.StartsWith('\\?\')) { $final = $final.Substring(4) }
  $final = [IO.Path]::GetFullPath($final)
  if ($final -notmatch '^[A-Za-z]:\\' -or $final.Length -lt 4) {
    Fail 'host_protected_store_root_invalid'
  }
  return $final.TrimEnd([IO.Path]::DirectorySeparatorChar)
}

function Set-ProtectedStoreAcl([string]$Path, [string]$Sid, [bool]$Directory) {
  try {
    $identity = [Security.Principal.SecurityIdentifier]::new($Sid)
    if ($Directory) {
      $security = [Security.AccessControl.DirectorySecurity]::new()
      $security.SetOwner($identity)
      $security.SetAccessRuleProtection($true, $false)
      $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
      $trustedIdentities = @(
        $identity,
        [Security.Principal.SecurityIdentifier]::new(
          [Security.Principal.WellKnownSidType]::LocalSystemSid,
          $null
        ),
        [Security.Principal.SecurityIdentifier]::new(
          [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
          $null
        )
      )
      foreach ($trustedIdentity in $trustedIdentities) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
          $trustedIdentity,
          [Security.AccessControl.FileSystemRights]::FullControl,
          $inheritance,
          [Security.AccessControl.PropagationFlags]::None,
          [Security.AccessControl.AccessControlType]::Allow
        )
        $security.AddAccessRule($rule)
      }
      [IO.FileSystemAclExtensions]::SetAccessControl([IO.DirectoryInfo]::new($Path), $security)
    } else {
      $security = [Security.AccessControl.FileSecurity]::new()
      $security.SetOwner($identity)
      $security.SetAccessRuleProtection($true, $false)
      $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::None,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
      )
      $security.AddAccessRule($rule)
      [IO.FileSystemAclExtensions]::SetAccessControl([IO.FileInfo]::new($Path), $security)
    }
  } catch { Fail 'host_protected_store_acl_failed' }
}

function Test-ProtectedStoreAcl([string]$Path, [string]$Sid, [bool]$Directory) {
  # Returns instead of calling Fail: Fail exits the process, so callers that
  # repair an invalid ACL must be able to observe the result first.
  try {
    $security = if ($Directory) {
      [IO.FileSystemAclExtensions]::GetAccessControl(
        [IO.DirectoryInfo]::new($Path),
        [Security.AccessControl.AccessControlSections]::Access -bor
          [Security.AccessControl.AccessControlSections]::Owner
      )
    } else {
      [IO.FileSystemAclExtensions]::GetAccessControl(
        [IO.FileInfo]::new($Path),
        [Security.AccessControl.AccessControlSections]::Access -bor
          [Security.AccessControl.AccessControlSections]::Owner
      )
    }
    if (-not $security.AreAccessRulesProtected -or
        $security.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $Sid) {
      return $false
    }
    $rules = @($security.GetAccessRules(
      $true, $true, [Security.Principal.SecurityIdentifier]
    ))
    $expectedInheritance = if ($Directory) {
      [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else { [Security.AccessControl.InheritanceFlags]::None }
    $expectedSids = if ($Directory) {
      @(
        $Sid,
        [Security.Principal.SecurityIdentifier]::new(
          [Security.Principal.WellKnownSidType]::LocalSystemSid,
          $null
        ).Value,
        [Security.Principal.SecurityIdentifier]::new(
          [Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,
          $null
        ).Value
      )
    } else { @($Sid) }
    if ($rules.Count -ne $expectedSids.Count) { return $false }
    $observedSids = @()
    foreach ($rule in $rules) {
      $observedSids += $rule.IdentityReference.Value
      if ($expectedSids -notcontains $rule.IdentityReference.Value -or
          $rule.IsInherited -or
          $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
          $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
          $rule.InheritanceFlags -ne $expectedInheritance -or
          $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        return $false
      }
    }
    foreach ($expectedSid in $expectedSids) {
      if (@($observedSids | Where-Object { $_ -ceq $expectedSid }).Count -ne 1) {
        return $false
      }
    }
    return $true
  } catch { return $false }
}

function Assert-ProtectedStoreAcl([string]$Path, [string]$Sid, [bool]$Directory) {
  if (-not (Test-ProtectedStoreAcl $Path $Sid $Directory)) { Fail 'host_protected_store_acl_invalid' }
}

function Repair-ProtectedStoreAcl([string]$Path, [string]$Sid, [bool]$Directory) {
  # Rewriting an identical ACL still updates the change time, which every
  # Host's path cache treats as a change. Write only an ACL that is not exact.
  if (-not (Test-ProtectedStoreAcl $Path $Sid $Directory)) { Set-ProtectedStoreAcl $Path $Sid $Directory }
}

function Get-PublicCapabilityRecord($Record) {
  return [PSCustomObject]@{
    contract = [string]$Record.contract
    capabilityId = [string]$Record.capabilityId
    region = [string]$Record.region
    principalId = [string]$Record.principalId
    delegateId = [string]$Record.delegateId
    hostInstallationId = [string]$Record.hostInstallationId
    adapterId = [string]$Record.adapterId
    version = [int]$Record.version
    state = [string]$Record.state
    scopes = @($Record.scopes)
    issuedAt = [int64]$Record.issuedAt
    revokedAt = $Record.revokedAt
  }
}

function Test-CodexNeutralBindingEqual($Left, $Right) {
  return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress))
}

function Test-CodexCapabilityMatch($Capability, $Binding) {
  if (
    [string]$Capability.contract -cne $RecordContract -or
    [string]$Capability.state -cne 'active' -or
    [string]$Capability.region -cne [string]$Binding.region -or
    [string]$Capability.principalId -cne [string]$Binding.principalId -or
    [string]$Capability.delegateId -cne [string]$Binding.delegateId -or
    [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
    [string]$Capability.adapterId -cne 'codex' -or
    [int64]$Capability.version -ne 2 -or
    $Capability.scopes.Count -ne $Binding.scopes.Count
  ) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) {
    if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false }
  }
  return $true
}

function Assert-OpenClawNeutralBinding($Binding, [bool]$ValidatePaths, [bool]$RequireLaunch = $false) {
  if ($null -eq $Binding -or $Binding -is [Array]) { Fail 'neutral_openclaw_binding_invalid' }
  $baseFields = @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'region', 'runtimeRoot', 'scopes', 'version'
  )
  $releaseFields = @(
    'profileManifestPath', 'releaseManifestSha256', 'releaseRoot', 'runnerRelativePath'
  )
  $releaseCount = 0
  foreach ($field in $releaseFields) {
    if ($null -ne $Binding.PSObject.Properties[$field]) { $releaseCount += 1 }
  }
  $expectedFields = @($baseFields)
  if ($releaseCount -gt 0) { $expectedFields += $releaseFields }
  Assert-ExactFields $Binding $expectedFields 'neutral_openclaw_binding_invalid'
  if (($RequireLaunch -and $releaseCount -ne $releaseFields.Count) -or
      ($releaseCount -ne 0 -and $releaseCount -ne $releaseFields.Count)) {
    Fail 'neutral_openclaw_binding_invalid'
  }
  if (
    [string]$Binding.contract -cne $OpenClawNeutralBindingContract -or
    [string]$Binding.region -notmatch $IdentifierPattern -or
    [string]$Binding.principalId -notmatch $IdentifierPattern -or
    [string]$Binding.delegateId -notmatch $IdentifierPattern -or
    [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Binding.profileId -notmatch $IdentifierPattern -or
    [string]$Binding.adapterId -cne 'openclaw' -or
    [int64]$Binding.version -ne 2 -or
    $Binding.scopes -isnot [Array] -or
    (-not (Test-ExactScopeSequence $Binding.scopes $OpenClawNeutralScopes) -and
      -not (Test-ExactScopeSequence $Binding.scopes $OpenClawNeutralPreviousScopes))
  ) { Fail 'neutral_openclaw_binding_invalid' }
  if ($releaseCount -eq $releaseFields.Count -and (
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.releaseRoot)) -or
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.profileManifestPath)) -or
    [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$Binding.runnerRelativePath -cne 'runtime/neutral-host-bootstrap.mjs'
  )) { Fail 'neutral_openclaw_launch_configuration_invalid' }
  if ($ValidatePaths) {
    $runtimeRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.runtimeRoot) $true 0
    if (-not [string]::Equals(
      $runtimeRoot,
      [IO.Path]::GetFullPath([string]$Binding.runtimeRoot),
      [StringComparison]::OrdinalIgnoreCase
    )) { Fail 'neutral_openclaw_binding_invalid' }
  }
  return $Binding
}

function Test-OpenClawNeutralBindingEqual($Left, $Right) {
  return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress))
}

function Test-OpenClawCapabilityMatch($Capability, $Binding) {
  if (
    [string]$Capability.contract -cne $RecordContract -or
    [string]$Capability.state -cne 'active' -or
    [string]$Capability.region -cne [string]$Binding.region -or
    [string]$Capability.principalId -cne [string]$Binding.principalId -or
    [string]$Capability.delegateId -cne [string]$Binding.delegateId -or
    [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
    [string]$Capability.adapterId -cne 'openclaw' -or
    [int64]$Capability.version -ne 2 -or
    $Capability.scopes.Count -ne $Binding.scopes.Count
  ) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) {
    if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false }
  }
  return $true
}

function Assert-TraeWorkNeutralBinding($Binding, [bool]$ValidatePaths) {
  if ($null -eq $Binding -or $Binding -is [Array]) { Fail 'neutral_trae_work_binding_invalid' }
  $baseFields = @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'region', 'runtimeRoot', 'scopes', 'version'
  )
  $releaseFields = @(
    'profileManifestPath', 'releaseManifestSha256', 'releaseRoot', 'runnerRelativePath'
  )
  $releaseCount = 0
  foreach ($field in $releaseFields) {
    if ($null -ne $Binding.PSObject.Properties[$field]) { $releaseCount += 1 }
  }
  $expectedFields = @($baseFields)
  if ($releaseCount -gt 0) { $expectedFields += $releaseFields }
  Assert-ExactFields $Binding $expectedFields 'neutral_trae_work_binding_invalid'
  if ($releaseCount -ne 0 -and $releaseCount -ne $releaseFields.Count) {
    Fail 'neutral_trae_work_binding_invalid'
  }
  if (
    [string]$Binding.contract -cne $TraeWorkNeutralBindingContract -or
    [string]$Binding.region -notmatch $IdentifierPattern -or
    [string]$Binding.principalId -notmatch $IdentifierPattern -or
    [string]$Binding.delegateId -notmatch $IdentifierPattern -or
    [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Binding.profileId -notmatch $IdentifierPattern -or
    [string]$Binding.adapterId -cne 'trae-work' -or
    [int64]$Binding.version -ne 2 -or
    $Binding.scopes -isnot [Array]
  ) { Fail 'neutral_trae_work_binding_invalid' }
  if (-not (Test-ExactScopeSequence $Binding.scopes $TraeWorkNeutralScopes) -and
      -not (Test-ExactScopeSequence $Binding.scopes $TraeWorkNeutralPreviousScopes) -and
      -not (Test-ExactScopeSequence $Binding.scopes $TraeWorkNeutralLegacyScopes)) {
    Fail 'neutral_trae_work_capability_binding_mismatch'
  }
  if ($releaseCount -eq $releaseFields.Count -and (
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.releaseRoot)) -or
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.profileManifestPath)) -or
    [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$Binding.runnerRelativePath -cne 'runtime/neutral-host-bootstrap.mjs'
  )) { Fail 'neutral_trae_work_launch_configuration_invalid' }
  if ($ValidatePaths) {
    $runtimeRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.runtimeRoot) $true 0
    if (-not [string]::Equals(
      $runtimeRoot,
      [IO.Path]::GetFullPath([string]$Binding.runtimeRoot),
      [StringComparison]::OrdinalIgnoreCase
    )) { Fail 'neutral_trae_work_binding_invalid' }
  }
  return $Binding
}

function Test-TraeWorkNeutralBindingEqual($Left, $Right) {
  return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress))
}

function Test-TraeWorkCapabilityMatch($Capability, $Binding) {
  if (
    [string]$Capability.contract -cne $RecordContract -or
    [string]$Capability.state -cne 'active' -or
    [string]$Capability.region -cne [string]$Binding.region -or
    [string]$Capability.principalId -cne [string]$Binding.principalId -or
    [string]$Capability.delegateId -cne [string]$Binding.delegateId -or
    [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
    [string]$Capability.adapterId -cne 'trae-work' -or
    [int64]$Capability.version -ne 2 -or
    $Capability.scopes.Count -ne $Binding.scopes.Count
  ) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) {
    if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false }
  }
  return $true
}

function Assert-WorkBuddyNeutralBinding($Binding, [bool]$ValidatePaths) {
  if ($null -eq $Binding -or $Binding -is [Array]) { Fail 'neutral_workbuddy_binding_invalid' }
  $baseFields = @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'region', 'runtimeRoot', 'scopes', 'version'
  )
  $releaseFields = @(
    'profileManifestPath', 'releaseManifestSha256', 'releaseRoot', 'runnerRelativePath'
  )
  $releaseCount = 0
  foreach ($field in $releaseFields) {
    if ($null -ne $Binding.PSObject.Properties[$field]) { $releaseCount += 1 }
  }
  $expectedFields = @($baseFields)
  if ($releaseCount -gt 0) { $expectedFields += $releaseFields }
  Assert-ExactFields $Binding $expectedFields 'neutral_workbuddy_binding_invalid'
  if ($releaseCount -ne 0 -and $releaseCount -ne $releaseFields.Count) {
    Fail 'neutral_workbuddy_binding_invalid'
  }
  if (
    [string]$Binding.contract -cne $WorkBuddyNeutralBindingContract -or
    [string]$Binding.region -notmatch $IdentifierPattern -or
    [string]$Binding.principalId -notmatch $IdentifierPattern -or
    [string]$Binding.delegateId -notmatch $IdentifierPattern -or
    [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Binding.profileId -notmatch $IdentifierPattern -or
    [string]$Binding.adapterId -cne 'workbuddy' -or
    [int64]$Binding.version -ne 2 -or
    $Binding.scopes -isnot [Array]
  ) { Fail 'neutral_workbuddy_binding_invalid' }
  if (-not (Test-ExactScopeSequence $Binding.scopes $WorkBuddyNeutralScopes) -and
      -not (Test-ExactScopeSequence $Binding.scopes $WorkBuddyNeutralPreviousScopes) -and
      -not (Test-ExactScopeSequence $Binding.scopes $WorkBuddyNeutralLegacyScopes)) {
    Fail 'neutral_workbuddy_capability_binding_mismatch'
  }
  if ($releaseCount -eq $releaseFields.Count -and (
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.releaseRoot)) -or
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.profileManifestPath)) -or
    [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$Binding.runnerRelativePath -cne 'runtime/neutral-host-bootstrap.mjs'
  )) { Fail 'neutral_workbuddy_launch_configuration_invalid' }
  if ($ValidatePaths) {
    $runtimeRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.runtimeRoot) $true 0
    if (-not [string]::Equals(
      $runtimeRoot,
      [IO.Path]::GetFullPath([string]$Binding.runtimeRoot),
      [StringComparison]::OrdinalIgnoreCase
    )) { Fail 'neutral_workbuddy_binding_invalid' }
  }
  return $Binding
}

function Test-WorkBuddyNeutralBindingEqual($Left, $Right) {
  return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress))
}

function Test-WorkBuddyCapabilityMatch($Capability, $Binding) {
  if (
    [string]$Capability.contract -cne $RecordContract -or
    [string]$Capability.state -cne 'active' -or
    [string]$Capability.region -cne [string]$Binding.region -or
    [string]$Capability.principalId -cne [string]$Binding.principalId -or
    [string]$Capability.delegateId -cne [string]$Binding.delegateId -or
    [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
    [string]$Capability.adapterId -cne 'workbuddy' -or
    [int64]$Capability.version -ne 2 -or
    $Capability.scopes.Count -ne $Binding.scopes.Count
  ) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) {
    if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false }
  }
  return $true
}

function Assert-ClaudeCodeNeutralBinding($Binding, [bool]$ValidatePaths) {
  if ($null -eq $Binding -or $Binding -is [Array]) { Fail 'neutral_claude_code_binding_invalid' }
  $baseFields = @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'region', 'runtimeRoot', 'scopes', 'version'
  )
  $releaseFields = @(
    'profileManifestPath', 'releaseManifestSha256', 'releaseRoot', 'runnerRelativePath'
  )
  $releaseCount = 0
  foreach ($field in $releaseFields) {
    if ($null -ne $Binding.PSObject.Properties[$field]) { $releaseCount += 1 }
  }
  $expectedFields = @($baseFields)
  if ($releaseCount -gt 0) { $expectedFields += $releaseFields }
  Assert-ExactFields $Binding $expectedFields 'neutral_claude_code_binding_invalid'
  if ($releaseCount -ne 0 -and $releaseCount -ne $releaseFields.Count) {
    Fail 'neutral_claude_code_binding_invalid'
  }
  if (
    [string]$Binding.contract -cne $ClaudeCodeNeutralBindingContract -or
    [string]$Binding.region -notmatch $IdentifierPattern -or
    [string]$Binding.principalId -notmatch $IdentifierPattern -or
    [string]$Binding.delegateId -notmatch $IdentifierPattern -or
    [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Binding.profileId -notmatch $IdentifierPattern -or
    [string]$Binding.adapterId -cne 'claude-code' -or
    [int64]$Binding.version -ne 2 -or
    $Binding.scopes -isnot [Array]
  ) { Fail 'neutral_claude_code_binding_invalid' }
  if (-not (Test-ExactScopeSequence $Binding.scopes $ClaudeCodeNeutralScopes)) {
    Fail 'neutral_claude_code_capability_binding_mismatch'
  }
  if ($releaseCount -eq $releaseFields.Count -and (
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.releaseRoot)) -or
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.profileManifestPath)) -or
    [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$Binding.runnerRelativePath -cne 'runtime/neutral-host-bootstrap.mjs'
  )) { Fail 'neutral_claude_code_launch_configuration_invalid' }
  if ($ValidatePaths) {
    $runtimeRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.runtimeRoot) $true 0
    if (-not [string]::Equals(
      $runtimeRoot,
      [IO.Path]::GetFullPath([string]$Binding.runtimeRoot),
      [StringComparison]::OrdinalIgnoreCase
    )) { Fail 'neutral_claude_code_binding_invalid' }
  }
  return $Binding
}

function Test-ClaudeCodeNeutralBindingEqual($Left, $Right) {
  return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress))
}

function Test-ClaudeCodeCapabilityMatch($Capability, $Binding) {
  if (
    [string]$Capability.contract -cne $RecordContract -or
    [string]$Capability.state -cne 'active' -or
    [string]$Capability.region -cne [string]$Binding.region -or
    [string]$Capability.principalId -cne [string]$Binding.principalId -or
    [string]$Capability.delegateId -cne [string]$Binding.delegateId -or
    [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
    [string]$Capability.adapterId -cne 'claude-code' -or
    [int64]$Capability.version -ne 2 -or
    $Capability.scopes.Count -ne $Binding.scopes.Count
  ) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) {
    if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false }
  }
  return $true
}

function Assert-CursorNeutralBinding($Binding, [bool]$ValidatePaths, [bool]$RequireCurrentScopes = $false) {
  if ($null -eq $Binding -or $Binding -is [Array]) { Fail 'neutral_cursor_binding_invalid' }
  $baseFields = @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'region', 'runtimeRoot', 'scopes', 'version'
  )
  $releaseFields = @(
    'profileManifestPath', 'releaseManifestSha256', 'releaseRoot', 'runnerRelativePath'
  )
  $releaseCount = 0
  foreach ($field in $releaseFields) {
    if ($null -ne $Binding.PSObject.Properties[$field]) { $releaseCount += 1 }
  }
  $expectedFields = @($baseFields)
  if ($releaseCount -gt 0) { $expectedFields += $releaseFields }
  Assert-ExactFields $Binding $expectedFields 'neutral_cursor_binding_invalid'
  if ($releaseCount -ne 0 -and $releaseCount -ne $releaseFields.Count) {
    Fail 'neutral_cursor_binding_invalid'
  }
  if (
    [string]$Binding.contract -cne $CursorNeutralBindingContract -or
    [string]$Binding.region -notmatch $IdentifierPattern -or
    [string]$Binding.principalId -notmatch $IdentifierPattern -or
    [string]$Binding.delegateId -notmatch $IdentifierPattern -or
    [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Binding.profileId -notmatch $IdentifierPattern -or
    [string]$Binding.adapterId -cne 'cursor' -or
    [int64]$Binding.version -ne 2 -or
    $Binding.scopes -isnot [Array] -or
    (-not (Test-ExactScopeSequence $Binding.scopes $CursorNeutralScopes) -and
      ($RequireCurrentScopes -or -not (Test-ExactScopeSequence $Binding.scopes $CursorNeutralPreviousScopes)))
  ) { Fail 'neutral_cursor_binding_invalid' }
  if ($releaseCount -eq $releaseFields.Count -and (
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.releaseRoot)) -or
    -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.profileManifestPath)) -or
    [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$' -or
    [string]$Binding.runnerRelativePath -cne 'runtime/neutral-host-bootstrap.mjs'
  )) { Fail 'neutral_cursor_launch_configuration_invalid' }
  if ($ValidatePaths) {
    $runtimeRoot = Assert-AbsoluteNonReparsePath (
      [string]$Binding.runtimeRoot
    ) $true 0 'neutral_cursor_binding_invalid' 'neutral_cursor_launch_configuration_invalid'
    if (-not [string]::Equals(
      $runtimeRoot,
      [IO.Path]::GetFullPath([string]$Binding.runtimeRoot),
      [StringComparison]::OrdinalIgnoreCase
    )) { Fail 'neutral_cursor_binding_invalid' }
  }
  return $Binding
}

function Test-CursorNeutralBindingEqual($Left, $Right) {
  return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress))
}

function Test-CursorCapabilityMatch($Capability, $Binding) {
  if (
    [string]$Capability.contract -cne $RecordContract -or
    [string]$Capability.state -cne 'active' -or
    [string]$Capability.region -cne [string]$Binding.region -or
    [string]$Capability.principalId -cne [string]$Binding.principalId -or
    [string]$Capability.delegateId -cne [string]$Binding.delegateId -or
    [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
    [string]$Capability.adapterId -cne 'cursor' -or
    [int64]$Capability.version -ne 2 -or
    $Capability.scopes.Count -ne $Binding.scopes.Count
  ) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) {
    if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false }
  }
  return $true
}

function Assert-DshNeutralBinding($Binding, [bool]$ValidatePaths, [bool]$RequireCurrentScopes = $false) {
  if ($null -eq $Binding -or $Binding -is [Array]) { Fail 'neutral_dsh_binding_invalid' }
  Assert-ExactFields $Binding @(
    'adapterId', 'contract', 'delegateId', 'hostInstallationId', 'principalId',
    'profileId', 'profileManifestPath', 'region', 'releaseManifestSha256', 'releaseRoot',
    'runnerRelativePath', 'runtimeRoot', 'scopes', 'version'
  ) 'neutral_dsh_binding_invalid'
  if ([string]$Binding.contract -cne $DshNeutralBindingContract -or
      [string]$Binding.region -notmatch $IdentifierPattern -or
      [string]$Binding.principalId -notmatch $IdentifierPattern -or
      [string]$Binding.delegateId -notmatch $IdentifierPattern -or
      [string]$Binding.hostInstallationId -notmatch $IdentifierPattern -or
      [string]$Binding.profileId -notmatch $IdentifierPattern -or
      [string]$Binding.adapterId -cne 'dsh' -or [int64]$Binding.version -ne 2 -or
      $Binding.scopes -isnot [Array] -or
      (-not (Test-ExactScopeSequence $Binding.scopes $DshNeutralScopes) -and
        ($RequireCurrentScopes -or -not (Test-ExactScopeSequence $Binding.scopes $DshNeutralPreviousScopes)))) {
    Fail 'neutral_dsh_binding_invalid'
  }
  if (-not (Test-FullyQualifiedCanonicalPath ([string]$Binding.releaseRoot)) -or
      -not (Test-FullyQualifiedCanonicalPath ([string]$Binding.profileManifestPath)) -or
      [string]$Binding.releaseManifestSha256 -notmatch '^[a-f0-9]{64}$' -or
      [string]$Binding.runnerRelativePath -cne 'runtime/neutral-host-bootstrap.mjs') { Fail 'neutral_dsh_launch_configuration_invalid' }
  if ($ValidatePaths) {
    $runtimeRoot = Assert-AbsoluteNonReparsePath ([string]$Binding.runtimeRoot) $true 0 'neutral_dsh_binding_invalid' 'neutral_dsh_launch_configuration_invalid'
    if (-not [string]::Equals($runtimeRoot, [IO.Path]::GetFullPath([string]$Binding.runtimeRoot), [StringComparison]::OrdinalIgnoreCase)) { Fail 'neutral_dsh_binding_invalid' }
  }
  return $Binding
}

function Test-DshNeutralBindingEqual($Left, $Right) { return (($Left | ConvertTo-Json -Depth 8 -Compress) -ceq ($Right | ConvertTo-Json -Depth 8 -Compress)) }
function Test-DshCapabilityMatch($Capability, $Binding) {
  if ([string]$Capability.contract -cne $RecordContract -or [string]$Capability.state -cne 'active' -or
      [string]$Capability.region -cne [string]$Binding.region -or [string]$Capability.principalId -cne [string]$Binding.principalId -or
      [string]$Capability.delegateId -cne [string]$Binding.delegateId -or [string]$Capability.hostInstallationId -cne [string]$Binding.hostInstallationId -or
      [string]$Capability.adapterId -cne 'dsh' -or [int64]$Capability.version -ne 2 -or $Capability.scopes.Count -ne $Binding.scopes.Count) { return $false }
  for ($index = 0; $index -lt $Binding.scopes.Count; $index += 1) { if ([string]$Capability.scopes[$index] -cne [string]$Binding.scopes[$index]) { return $false } }
  return $true
}

function Test-NeutralBindingOwnerEqual($Left, $Right) {
  foreach ($field in @(
    'contract', 'region', 'principalId', 'delegateId', 'hostInstallationId',
    'profileId', 'adapterId', 'version', 'runtimeRoot'
  )) {
    if ([string]$Left.$field -cne [string]$Right.$field) { return $false }
  }
  return $true
}

function Assert-TransportCredential($Record) {
  Assert-ExactFields $Record @(
    'contract', 'credentialId', 'principalId', 'hostInstallationId', 'state',
    'secret', 'issuedAt', 'expiresAt', 'revokedAt'
  ) 'host_transport_credential_fields_invalid'
  if (
    [string]$Record.contract -cne $TransportCredentialContract -or
    [string]$Record.credentialId -notmatch $IdentifierPattern -or
    [string]$Record.principalId -notmatch $IdentifierPattern -or
    [string]$Record.hostInstallationId -notmatch $IdentifierPattern -or
    [string]$Record.secret -notmatch $TransportCredentialSecretPattern -or
    [string]$Matches[1] -cne [string]$Record.credentialId -or
    @('active', 'revoked') -notcontains [string]$Record.state -or
    [int64]$Record.issuedAt -lt 0 -or
    [int64]$Record.expiresAt -le [int64]$Record.issuedAt
  ) { Fail 'host_transport_credential_invalid' }
  if (
    ([string]$Record.state -eq 'active' -and $null -ne $Record.revokedAt) -or
    ([string]$Record.state -eq 'revoked' -and (
      $null -eq $Record.revokedAt -or [int64]$Record.revokedAt -lt [int64]$Record.issuedAt
    ))
  ) { Fail 'host_transport_credential_state_invalid' }
  return $Record
}

function Assert-TransportSession($Record) {
  Assert-ExactFields $Record @(
    'contract', 'sessionId', 'sessionSecret', 'credentialId', 'principalId',
    'hostInstallationId', 'issuedAt', 'expiresAt'
  ) 'host_transport_session_fields_invalid'
  if (
    [string]$Record.contract -cne $TransportSessionContract -or
    [string]$Record.sessionId -notmatch $TransportSessionIdPattern -or
    [string]$Record.sessionSecret -notmatch $TransportSessionSecretPattern -or
    [string]$Record.credentialId -notmatch $IdentifierPattern -or
    [string]$Record.principalId -notmatch $IdentifierPattern -or
    [string]$Record.hostInstallationId -notmatch $IdentifierPattern -or
    [int64]$Record.issuedAt -lt 0 -or
    [int64]$Record.expiresAt -le [int64]$Record.issuedAt
  ) { Fail 'host_transport_session_invalid' }
  return $Record
}

function Assert-QueryOwner {
  if (
    [string]$PrincipalId -notmatch $IdentifierPattern -or
    [string]$HostInstallationId -notmatch $IdentifierPattern
  ) { Fail 'host_transport_owner_invalid' }
}

function Test-TransportCredentialEqual($Left, $Right) {
  return (
    [string]$Left.contract -ceq [string]$Right.contract -and
    [string]$Left.credentialId -ceq [string]$Right.credentialId -and
    [string]$Left.principalId -ceq [string]$Right.principalId -and
    [string]$Left.hostInstallationId -ceq [string]$Right.hostInstallationId -and
    [string]$Left.state -ceq [string]$Right.state -and
    [string]$Left.secret -ceq [string]$Right.secret -and
    [int64]$Left.issuedAt -eq [int64]$Right.issuedAt -and
    [int64]$Left.expiresAt -eq [int64]$Right.expiresAt -and
    (($null -eq $Left.revokedAt -and $null -eq $Right.revokedAt) -or
      [int64]$Left.revokedAt -eq [int64]$Right.revokedAt)
  )
}

function Read-DeviceEnrollment([string]$EnrollmentPath, [string]$Sid) {
  $enrollment = [PSCustomObject]@{ contract = 'hellolynk-device-enrollment-v1'; revision = 0; value = $null }
  Assert-ProtectedStoreNoReparse $EnrollmentPath
  if (Test-Path -LiteralPath $EnrollmentPath) {
    Assert-ProtectedStoreAcl $EnrollmentPath $Sid $false
    $encrypted = Import-Clixml -LiteralPath $EnrollmentPath
    if ($encrypted -isnot [Management.Automation.PSCredential] -or $encrypted.UserName -cne $CredentialName) {
      Fail 'device_enrollment_store_invalid'
    }
    $plainEnrollment = $encrypted.GetNetworkCredential().Password
    if ([Text.Encoding]::UTF8.GetByteCount($plainEnrollment) -gt 65536) { Fail 'device_enrollment_store_invalid' }
    try { $enrollment = $plainEnrollment | ConvertFrom-Json } catch { Fail 'device_enrollment_store_invalid' }
    $plainEnrollment = $null
    Assert-ExactFields $enrollment @('contract', 'revision', 'value') 'device_enrollment_store_invalid'
    if ($enrollment.contract -cne 'hellolynk-device-enrollment-v1' -or
        $enrollment.revision -isnot [long] -and $enrollment.revision -isnot [int] -or
        $enrollment.revision -lt 0 -or $enrollment.revision -ge 9007199254740991) {
      Fail 'device_enrollment_store_invalid'
    }
  }
  return $enrollment
}

function Test-TransportSessionEqual($Left, $Right) {
  return (
    [string]$Left.contract -ceq [string]$Right.contract -and
    [string]$Left.sessionId -ceq [string]$Right.sessionId -and
    [string]$Left.sessionSecret -ceq [string]$Right.sessionSecret -and
    [string]$Left.credentialId -ceq [string]$Right.credentialId -and
    [string]$Left.principalId -ceq [string]$Right.principalId -and
    [string]$Left.hostInstallationId -ceq [string]$Right.hostInstallationId -and
    [int64]$Left.issuedAt -eq [int64]$Right.issuedAt -and
    [int64]$Left.expiresAt -eq [int64]$Right.expiresAt
  )
}

function Get-ActiveTransportCredential($Store, [int64]$Now) {
  Assert-QueryOwner
  $matching = @($Store.transportCredentials | Where-Object {
    [string]$_.principalId -ceq $PrincipalId -and
    [string]$_.hostInstallationId -ceq $HostInstallationId -and
    [string]$_.state -ceq 'active'
  })
  if ($matching.Count -eq 0) { Fail 'host_transport_credential_required' }
  if ($matching.Count -gt 1) { Fail 'host_transport_credential_ambiguous' }
  if ([int64]$matching[0].expiresAt -le $Now) { Fail 'host_transport_credential_expired' }
  return $matching[0]
}

# Immutable, authenticated radix pages keep retirement evidence out of the
# current-state envelope. Page limits bound individual reads, not lifetime use.
function Get-RetiredDigest([byte[]]$Bytes) {
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Assert-RetiredReference($Reference) {
  if ($null -eq $Reference) { return }
  Assert-ExactFields $Reference @('hash', 'count') 'host_retired_index_invalid'
  if ([string]$Reference.hash -cnotmatch '^[a-f0-9]{64}$' -or
      ($Reference.count -isnot [long] -and $Reference.count -isnot [int]) -or $Reference.count -le 0) {
    Fail 'host_retired_index_invalid'
  }
}

function Get-RetiredDirectory([string]$Root) {
  $directory = Join-Path $Root 'transport-retired-v1'
  Assert-ProtectedStoreNoReparse $directory
  return $directory
}

function Protect-RetiredJson($Value) {
  $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 12 -Compress))
  try {
    return ,([Security.Cryptography.ProtectedData]::Protect($bytes,
      [Text.Encoding]::UTF8.GetBytes($RetiredIndexContract), [Security.Cryptography.DataProtectionScope]::CurrentUser))
  } finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Read-RetiredJson([string]$Path, [int64]$MaxBytes, [string]$Hash = '') {
  $null = Assert-AbsoluteNonReparsePath $Path $false $MaxBytes 'host_retired_index_invalid' 'host_retired_index_unavailable'
  $cipher = [IO.File]::ReadAllBytes($Path)
  if ($Hash -and (Get-RetiredDigest $cipher) -cne $Hash) { Fail 'host_retired_index_integrity_failed' }
  $plain = $null
  try {
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($cipher,
      [Text.Encoding]::UTF8.GetBytes($RetiredIndexContract), [Security.Cryptography.DataProtectionScope]::CurrentUser)
    return ([Text.UTF8Encoding]::new($false, $true).GetString($plain) | ConvertFrom-Json)
  } catch { Fail 'host_retired_index_decryption_failed' }
  finally { if ($null -ne $plain) { [Array]::Clear($plain, 0, $plain.Length) } }
}

function Read-RetiredNode([string]$Root, $Reference, [string]$Prefix, [hashtable]$Nodes = $null) {
  Assert-RetiredReference $Reference
  if ($null -eq $Reference) { return $null }
  # Only Read-Store supplies this map, scoped to its one mutex-protected read.
  # Content-addressed nodes are immutable; retain every validation context in
  # the key so a different root, count or prefix cannot reuse another result.
  $cacheKey = "$Root`0$($Reference.hash)`0$($Reference.count)`0$Prefix"
  if ($null -ne $Nodes -and $Nodes.ContainsKey($cacheKey)) { return $Nodes[$cacheKey] }
  $node = Read-RetiredJson (Join-Path (Get-RetiredDirectory $Root) ($Reference.hash + '.dpapi')) 131072 $Reference.hash
  if ($node.kind -ceq 'leaf') {
    Assert-ExactFields $node @('contract', 'prefix', 'kind', 'hashes') 'host_retired_index_invalid'
    if ($node.hashes -isnot [Array] -or $node.hashes.Count -ne $Reference.count -or $node.hashes.Count -gt 512) {
      Fail 'host_retired_index_invalid'
    }
    $seen = @{}
    foreach ($hash in $node.hashes) {
      if ($hash -isnot [string] -or $hash -cnotmatch '^[a-f0-9]{64}$' -or -not $hash.StartsWith($Prefix) -or $seen.ContainsKey($hash)) {
        Fail 'host_retired_index_invalid'
      }
      $seen[$hash] = $true
    }
  } elseif ($node.kind -ceq 'branch') {
    Assert-ExactFields $node @('contract', 'prefix', 'kind', 'children') 'host_retired_index_invalid'
    $children = @($node.children.PSObject.Properties)
    if ($Prefix.Length -ge 64 -or $children.Count -lt 1 -or $children.Count -gt 16) { Fail 'host_retired_index_invalid' }
    [long]$count = 0
    foreach ($child in $children) {
      if ($child.Name -cnotmatch '^[a-f0-9]$' -or $null -eq $child.Value) { Fail 'host_retired_index_invalid' }
      Assert-RetiredReference $child.Value
      if ($count -gt [long]::MaxValue - $child.Value.count) { Fail 'host_retired_index_invalid' }
      $count += $child.Value.count
    }
    if ($count -ne $Reference.count) { Fail 'host_retired_index_invalid' }
  } else { Fail 'host_retired_index_invalid' }
  if ($node.contract -cne $RetiredIndexContract -or $node.prefix -cne $Prefix) { Fail 'host_retired_index_invalid' }
  if ($null -ne $Nodes) { $Nodes[$cacheKey] = $node }
  return $node
}

function Test-RetiredTransportSession($Store, [string]$Root, [string]$SessionId, [hashtable]$Nodes = $null) {
  # Preserve the conservative case-insensitive conflict check of Read-Store.
  if (@($Store.retiredTransportSessionIds | Where-Object { [string]$_ -ieq $SessionId }).Count) { return $true }
  $hash = Get-RetiredDigest ([Text.Encoding]::UTF8.GetBytes($SessionId.ToLowerInvariant()))
  return Test-RetiredHash $Store $Root $hash $Nodes
}

function Test-RetiredHash($Store, [string]$Root, [string]$Hash, [hashtable]$Nodes = $null) {
  if ($Hash -cnotmatch '^[a-f0-9]{64}$') { Fail 'host_retired_index_invalid' }
  $reference = $Store.retiredTransportSessionIndex
  $prefix = ''
  while ($null -ne $reference) {
    $node = Read-RetiredNode $Root $reference $prefix $Nodes
    if ($node.kind -ceq 'leaf') { return $node.hashes -ccontains $hash }
    $digit = $hash.Substring($prefix.Length, 1)
    $reference = $node.children.$digit
    $prefix += $digit
  }
  return $false
}

# The existing retirement tree and transaction protect both session tombstones
# and minimal authorization history. NUL-delimited domains cannot overlap a
# valid session ID. Each history ciphertext is bound to the authenticated root.
function Get-AuthorizationHistoryKey([string]$Kind, [string]$Id) {
  if ($Kind -cnotin @('capability','credential') -or
      ($Kind -ceq 'capability' -and $Id -notmatch $CapabilityIdPattern) -or
      ($Kind -ceq 'credential' -and $Id -notmatch $IdentifierPattern)) { Fail 'host_authorization_history_invalid' }
  return Get-RetiredDigest ([Text.Encoding]::UTF8.GetBytes("authorization`0$Kind`0" + $Id.ToLowerInvariant()))
}

function Get-AuthorizationHistoryProof([string]$Key, [string]$CipherHash) {
  return Get-RetiredDigest ([Text.Encoding]::UTF8.GetBytes("authorization-proof`0$Key`0$CipherHash"))
}

function New-AuthorizationHistoryRecord([string]$Kind, $Record) {
  if ($Kind -ceq 'capability') { $null = Assert-Record $Record; $idField = 'capabilityId' }
  elseif ($Kind -ceq 'credential') { $null = Assert-TransportCredential $Record; $idField = 'credentialId' }
  else { Fail 'host_authorization_history_invalid' }
  if ($Record.state -cne 'revoked') { Fail 'host_authorization_history_invalid' }
  $summary = [ordered]@{ state='revoked'; issuedAt=[long]$Record.issuedAt; revokedAt=[long]$Record.revokedAt }
  $summary[$idField] = [string]$Record.$idField
  if ($Kind -ceq 'credential') {
    $summary.principalId = [string]$Record.principalId
    $summary.hostInstallationId = [string]$Record.hostInstallationId
  }
  return [PSCustomObject]@{ contract=$AuthorizationHistoryContract; kind=$Kind; record=[PSCustomObject]$summary }
}

function Read-AuthorizationHistory($Store, [string]$Root, [string]$Kind, [string]$Id) {
  $key = Get-AuthorizationHistoryKey $Kind $Id
  if (-not (Test-RetiredHash $Store $Root $key)) { return $null }
  if ($Store.authorizationHistoryContract -cne $AuthorizationHistoryContract) { Fail 'host_authorization_history_invalid' }
  $path = Join-Path (Get-RetiredDirectory $Root) ($key + '.dpapi')
  $null = Assert-AbsoluteNonReparsePath $path $false 8192 'host_authorization_history_invalid' 'host_authorization_history_unavailable'
  $cipherHash = Get-RetiredDigest ([IO.File]::ReadAllBytes($path))
  if (-not (Test-RetiredHash $Store $Root (Get-AuthorizationHistoryProof $key $cipherHash))) { Fail 'host_authorization_history_integrity_failed' }
  $value = Read-RetiredJson $path 8192 $cipherHash
  Assert-ExactFields $value @('contract','kind','record') 'host_authorization_history_invalid'
  if ($value.contract -cne $AuthorizationHistoryContract -or $value.kind -cne $Kind) { Fail 'host_authorization_history_invalid' }
  $record = $value.record
  $fields = @('issuedAt','revokedAt','state')
  if ($Kind -ceq 'capability') { $fields += 'capabilityId'; $idField='capabilityId' }
  else { $fields += @('credentialId','principalId','hostInstallationId'); $idField='credentialId' }
  Assert-ExactFields $record $fields 'host_authorization_history_invalid'
  if ($record.$idField -cne $Id -or $record.state -cne 'revoked' -or
      ($record.issuedAt -isnot [long] -and $record.issuedAt -isnot [int]) -or
      ($record.revokedAt -isnot [long] -and $record.revokedAt -isnot [int]) -or
      $record.issuedAt -lt 0 -or $record.revokedAt -lt $record.issuedAt -or
      ($Kind -ceq 'credential' -and ($record.principalId -notmatch $IdentifierPattern -or $record.hostInstallationId -notmatch $IdentifierPattern))) {
    Fail 'host_authorization_history_invalid'
  }
  return $record
}

function Test-AuthorizationIdUsed($Store, [string]$Root, [string]$Kind, [string]$Id) {
  $key = Get-AuthorizationHistoryKey $Kind $Id
  $records = if ($Kind -ceq 'capability') { @($Store.capabilities) } else { @($Store.transportCredentials) }
  $field = if ($Kind -ceq 'capability') { 'capabilityId' } else { 'credentialId' }
  if (@($records | Where-Object { [string]$_.$field -ieq $Id }).Count) { return $true }
  return Test-RetiredHash $Store $Root $key
}

function New-RetiredNode($Context, [string]$Prefix, [string]$Kind, $Content, [long]$Count) {
  $node = [ordered]@{ contract = $RetiredIndexContract; prefix = $Prefix; kind = $Kind }
  if ($Kind -ceq 'leaf') { $node.hashes = @($Content) } else { $node.children = $Content }
  $bytes = Protect-RetiredJson $node
  $hash = Get-RetiredDigest $bytes
  $Context.pages[$hash] = $bytes
  return [PSCustomObject]@{ hash = $hash; count = $Count }
}

function Merge-RetiredNode($Context, $Reference, [string]$Prefix, [string[]]$Hashes) {
  if (-not $Hashes.Count) { return $Reference }
  $node = Read-RetiredNode $Context.root $Reference $Prefix
  if ($null -eq $node -or $node.kind -ceq 'leaf') {
    $combined = @(@($node.hashes) + $Hashes | Where-Object { $_ } | Sort-Object -Unique)
    if ($null -ne $Reference -and $combined.Count -eq $Reference.count) { return $Reference }
    if ($null -ne $Reference) { $Context.obsolete[$Reference.hash] = $true }
    if ($combined.Count -le 512) { return New-RetiredNode $Context $Prefix 'leaf' $combined $combined.Count }
    $Hashes = $combined
    $node = $null
  }
  $children = [ordered]@{}
  [long]$count = 0
  $changed = $null -eq $node
  $buckets = @{}
  foreach ($hash in $Hashes) {
    $key = $hash.Substring($Prefix.Length, 1)
    if (-not $buckets.ContainsKey($key)) { $buckets[$key] = [Collections.Generic.List[string]]::new() }
    $buckets[$key].Add($hash)
  }
  foreach ($digit in '0123456789abcdef'.ToCharArray()) {
    $key = [string]$digit
    $old = if ($null -ne $node) { $node.children.$key } else { $null }
    $subset = if ($buckets.ContainsKey($key)) { $buckets[$key].ToArray() } else { @() }
    $next = Merge-RetiredNode $Context $old ($Prefix + $key) $subset
    if ($null -ne $next) { $children[$key] = $next; $count += $next.count }
    if ($next.hash -cne $old.hash) { $changed = $true }
  }
  if (-not $changed) { return $Reference }
  if ($null -ne $node) { $Context.obsolete[$Reference.hash] = $true }
  return New-RetiredNode $Context $Prefix 'branch' $children $count
}

function Write-RetiredBytes([string]$Path, [byte[]]$Bytes, [string]$Sid) {
  Assert-ProtectedStoreNoReparse $Path
  $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  Set-ProtectedStoreAcl $Path $Sid $false
}

function Test-RetiredReferenceEqual($Left, $Right) {
  if ($null -eq $Left -or $null -eq $Right) { return $null -eq $Left -and $null -eq $Right }
  return $Left.hash -ceq $Right.hash -and $Left.count -eq $Right.count
}

function Complete-RetiredTransaction([string]$Root, $Current, $PreparedJournal = $null) {
  $directory = Get-RetiredDirectory $Root
  $path = Join-Path $directory 'pending.dpapi'
  if (-not (Test-Path -LiteralPath $path)) { return $true }
  $journal = if ($null -ne $PreparedJournal) { $PreparedJournal } else { Read-RetiredJson $path 1048576 }
  Assert-ExactFields $journal @('contract', 'before', 'after', 'added', 'obsolete') 'host_retired_journal_invalid'
  if ($journal.contract -cne ($RetiredIndexContract + '-transaction') -or $null -eq $journal.after -or
      $journal.added -isnot [Array] -or $journal.obsolete -isnot [Array]) { Fail 'host_retired_journal_invalid' }
  Assert-RetiredReference $journal.before
  Assert-RetiredReference $journal.after
  $seen = @{}
  foreach ($hash in @($journal.added) + @($journal.obsolete)) {
    if ($hash -isnot [string] -or $hash -cnotmatch '^[a-f0-9]{64}$' -or $seen.ContainsKey($hash)) { Fail 'host_retired_journal_invalid' }
    $seen[$hash] = $true
  }
  if (Test-RetiredReferenceEqual $Current $journal.after) { $remove = @($journal.obsolete) }
  elseif (Test-RetiredReferenceEqual $Current $journal.before) { $remove = @($journal.added) }
  else { Fail 'host_retired_journal_conflict' }
  # Cleanup is retryable after commit. Never turn a committed replacement into
  # an apparent failed operation, or delete any page from an unknown revision.
  try {
    foreach ($hash in $remove) {
      $target = Join-Path $directory ($hash + '.dpapi')
      Assert-ProtectedStoreNoReparse $target
      if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    }
    Remove-Item -LiteralPath $path -Force
    return $true
  } catch { return $false }
}

function Read-Store([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    return [PSCustomObject]@{
      contract = $Contract
      capabilities = @()
      transportCredentials = @()
      transportSessions = @()
      retiredTransportSessionIds = @()
      codexNeutralBindings = @()
      openClawNeutralBindings = @()
      traeWorkNeutralBindings = @()
      workBuddyNeutralBindings = @()
      claudeCodeNeutralBindings = @()
      cursorNeutralBindings = @()
      dshNeutralBindings = @()
    }
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 2097152) {
    Fail 'host_protected_store_path_invalid'
  }
  $credential = Import-Clixml -LiteralPath $Path
  if ($credential -is [Management.Automation.PSCredential]) {
    if ($credential.UserName -cne $CredentialName) { Fail 'host_protected_store_binding_invalid' }
    $plain = $credential.GetNetworkCredential().Password
  } elseif ([string]$credential.contract -ceq $EnvelopeContract) {
    Assert-ExactFields $credential @('contract', 'ciphertext') 'host_protected_store_binding_invalid'
    $plainBytes = $null
    try {
      $ciphertext = [Convert]::FromBase64String([string]$credential.ciphertext)
      $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
        $ciphertext, [Text.Encoding]::UTF8.GetBytes($EnvelopeContract),
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
      if ($plainBytes.Length -gt 1048576) { Fail 'host_protected_store_too_large' }
      $plain = [Text.UTF8Encoding]::new($false, $true).GetString($plainBytes)
    } catch { Fail 'host_protected_store_decryption_failed' }
    finally { if ($null -ne $plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) } }
  } else {
    Fail 'host_protected_store_binding_invalid'
  }
  if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 1048576) { Fail 'host_protected_store_too_large' }
  try { $store = $plain | ConvertFrom-Json } catch { Fail 'host_protected_store_invalid' }
  $plain = $null
  $authorizationHistory = $store.authorizationHistoryContract
  if ($null -ne $store.PSObject.Properties['authorizationHistoryContract']) {
    if ($authorizationHistory -cne $AuthorizationHistoryContract) { Fail 'host_authorization_history_invalid' }
    $store.PSObject.Properties.Remove('authorizationHistoryContract')
  }
  $retiredIndex = $store.retiredTransportSessionIndex
  if ($null -ne $store.PSObject.Properties['retiredTransportSessionIndex']) {
    if ($null -eq $retiredIndex) { Fail 'host_retired_index_invalid' }
    Assert-RetiredReference $retiredIndex
    $store.PSObject.Properties.Remove('retiredTransportSessionIndex')
  }
  $fields = @($store.PSObject.Properties.Name | Sort-Object)
  if ($fields.Count -eq 2) {
    Assert-ExactFields $store @('capabilities', 'contract') 'host_protected_store_fields_invalid'
    $store | Add-Member -NotePropertyName transportCredentials -NotePropertyValue @()
    $store | Add-Member -NotePropertyName transportSessions -NotePropertyValue @()
    $store | Add-Member -NotePropertyName retiredTransportSessionIds -NotePropertyValue @()
    $store | Add-Member -NotePropertyName codexNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName openClawNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName traeWorkNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName workBuddyNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
  } elseif ($fields.Count -eq 5) {
    Assert-ExactFields $store @(
      'capabilities', 'contract', 'retiredTransportSessionIds',
      'transportCredentials', 'transportSessions'
    ) 'host_protected_store_fields_invalid'
    $store | Add-Member -NotePropertyName codexNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName openClawNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName traeWorkNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName workBuddyNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
  } elseif ($fields.Count -eq 6) {
    Assert-ExactFields $store @(
      'capabilities', 'codexNeutralBindings', 'contract', 'retiredTransportSessionIds',
      'transportCredentials', 'transportSessions'
    ) 'host_protected_store_fields_invalid'
    $store | Add-Member -NotePropertyName openClawNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName traeWorkNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName workBuddyNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
  } elseif ($fields.Count -eq 7) {
    Assert-ExactFields $store @(
      'capabilities', 'codexNeutralBindings', 'contract', 'openClawNeutralBindings', 'retiredTransportSessionIds',
      'transportCredentials', 'transportSessions'
    ) 'host_protected_store_fields_invalid'
    $store | Add-Member -NotePropertyName traeWorkNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName workBuddyNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
  } elseif ($fields.Count -eq 8) {
    Assert-ExactFields $store @(
      'capabilities', 'codexNeutralBindings', 'contract', 'openClawNeutralBindings', 'retiredTransportSessionIds',
      'traeWorkNeutralBindings', 'transportCredentials', 'transportSessions'
    ) 'host_protected_store_fields_invalid'
    $store | Add-Member -NotePropertyName workBuddyNeutralBindings -NotePropertyValue @()
    $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
  } elseif ($fields.Count -eq 9) {
    Assert-ExactFields $store @(
      'capabilities', 'codexNeutralBindings', 'contract', 'openClawNeutralBindings', 'retiredTransportSessionIds',
      'traeWorkNeutralBindings', 'transportCredentials', 'transportSessions', 'workBuddyNeutralBindings'
    ) 'host_protected_store_fields_invalid'
    $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
  } elseif ($fields.Count -eq 10) {
    if ($null -ne $store.PSObject.Properties['dshNeutralBindings']) {
      Assert-ExactFields $store @(
        'capabilities', 'codexNeutralBindings', 'contract', 'dshNeutralBindings', 'openClawNeutralBindings',
        'retiredTransportSessionIds', 'traeWorkNeutralBindings', 'transportCredentials', 'transportSessions',
        'workBuddyNeutralBindings'
      ) 'host_protected_store_fields_invalid'
      $store | Add-Member -NotePropertyName cursorNeutralBindings -NotePropertyValue @()
    } else {
      Assert-ExactFields $store @(
        'capabilities', 'codexNeutralBindings', 'contract', 'cursorNeutralBindings', 'openClawNeutralBindings',
        'retiredTransportSessionIds', 'traeWorkNeutralBindings', 'transportCredentials', 'transportSessions',
        'workBuddyNeutralBindings'
      ) 'host_protected_store_fields_invalid'
    }
  } elseif ($fields.Count -eq 11) {
    Assert-ExactFields $store @(
      'capabilities', 'codexNeutralBindings', 'contract', 'cursorNeutralBindings', 'dshNeutralBindings',
      'openClawNeutralBindings', 'retiredTransportSessionIds', 'traeWorkNeutralBindings',
      'transportCredentials', 'transportSessions', 'workBuddyNeutralBindings'
    ) 'host_protected_store_fields_invalid'
  } else {
    Assert-ExactFields $store @(
      'capabilities', 'claudeCodeNeutralBindings', 'codexNeutralBindings', 'contract', 'cursorNeutralBindings',
      'dshNeutralBindings', 'openClawNeutralBindings', 'retiredTransportSessionIds',
      'traeWorkNeutralBindings', 'transportCredentials', 'transportSessions', 'workBuddyNeutralBindings'
    ) 'host_protected_store_fields_invalid'
  }
  if ($null -eq $store.PSObject.Properties['dshNeutralBindings']) {
    $store | Add-Member -NotePropertyName dshNeutralBindings -NotePropertyValue @()
  }
  if ($null -eq $store.PSObject.Properties['claudeCodeNeutralBindings']) {
    $store | Add-Member -NotePropertyName claudeCodeNeutralBindings -NotePropertyValue @()
  }
  if (
    [string]$store.contract -cne $Contract -or
    $store.capabilities -isnot [Array] -or
    $store.codexNeutralBindings -isnot [Array] -or $store.codexNeutralBindings.Count -gt 64 -or
    $store.openClawNeutralBindings -isnot [Array] -or $store.openClawNeutralBindings.Count -gt 64 -or
    $store.traeWorkNeutralBindings -isnot [Array] -or $store.traeWorkNeutralBindings.Count -gt 64 -or
    $store.workBuddyNeutralBindings -isnot [Array] -or $store.workBuddyNeutralBindings.Count -gt 64 -or
    $store.claudeCodeNeutralBindings -isnot [Array] -or $store.claudeCodeNeutralBindings.Count -gt 64 -or
    $store.cursorNeutralBindings -isnot [Array] -or $store.cursorNeutralBindings.Count -gt 64 -or
    $store.dshNeutralBindings -isnot [Array] -or $store.dshNeutralBindings.Count -gt 64 -or
    $store.transportCredentials -isnot [Array] -or
    $store.transportSessions -isnot [Array] -or $store.transportSessions.Count -gt 1024 -or
    $store.retiredTransportSessionIds -isnot [Array]
  ) {
    Fail 'host_protected_store_invalid'
  }
  $seen = @{}
  foreach ($record in $store.capabilities) {
    $null = Assert-Record $record
    if ($seen.ContainsKey([string]$record.capabilityId)) { Fail 'host_capability_duplicate' }
    $seen[[string]$record.capabilityId] = $true
  }
  foreach ($binding in $store.codexNeutralBindings) {
    $null = Assert-CodexNeutralBinding $binding $false
  }
  foreach ($binding in $store.openClawNeutralBindings) {
    $null = Assert-OpenClawNeutralBinding $binding $false
  }
  foreach ($binding in $store.traeWorkNeutralBindings) {
    $null = Assert-TraeWorkNeutralBinding $binding $false
  }
  foreach ($binding in $store.workBuddyNeutralBindings) {
    $null = Assert-WorkBuddyNeutralBinding $binding $false
  }
  foreach ($binding in $store.claudeCodeNeutralBindings) {
    $null = Assert-ClaudeCodeNeutralBinding $binding $false
  }
  foreach ($binding in $store.cursorNeutralBindings) {
    $null = Assert-CursorNeutralBinding $binding $false
  }
  foreach ($binding in $store.dshNeutralBindings) {
    $null = Assert-DshNeutralBinding $binding $false
  }
  $credentialSeen = @{}
  foreach ($record in $store.transportCredentials) {
    $null = Assert-TransportCredential $record
    if ($credentialSeen.ContainsKey([string]$record.credentialId)) { Fail 'host_transport_credential_duplicate' }
    $credentialSeen[[string]$record.credentialId] = $record
  }
  $retiredSeen = @{}
  foreach ($retiredId in $store.retiredTransportSessionIds) {
    if ([string]$retiredId -notmatch $TransportSessionIdPattern) { Fail 'host_transport_session_tombstone_invalid' }
    if ($retiredSeen.ContainsKey([string]$retiredId)) { Fail 'host_transport_session_tombstone_duplicate' }
    $retiredSeen[[string]$retiredId] = $true
  }
  $retiredNodes = @{}
  if ($null -ne $retiredIndex) {
    $store | Add-Member -NotePropertyName retiredTransportSessionIndex -NotePropertyValue $retiredIndex
    $null = Read-RetiredNode ([IO.Path]::GetDirectoryName($Path)) $retiredIndex '' $retiredNodes
  }
  if ($null -ne $authorizationHistory) {
    if ($null -eq $retiredIndex) { Fail 'host_authorization_history_invalid' }
    $store | Add-Member -NotePropertyName authorizationHistoryContract -NotePropertyValue $authorizationHistory
    foreach ($pair in @(@('capability','capabilities','capabilityId'),@('credential','transportCredentials','credentialId'))) {
      foreach ($record in $store.($pair[1])) {
        if ($record.state -ceq 'active' -and (Test-RetiredHash $store ([IO.Path]::GetDirectoryName($Path)) (Get-AuthorizationHistoryKey $pair[0] $record.($pair[2])) $retiredNodes)) {
          Fail 'host_authorization_history_active_conflict'
        }
      }
    }
  }
  $sessionSeen = @{}
  foreach ($record in $store.transportSessions) {
    $null = Assert-TransportSession $record
    if ($sessionSeen.ContainsKey([string]$record.sessionId)) { Fail 'host_transport_session_duplicate' }
    if (Test-RetiredTransportSession $store ([IO.Path]::GetDirectoryName($Path)) ([string]$record.sessionId) $retiredNodes) { Fail 'host_transport_session_retired_conflict' }
    $sessionSeen[[string]$record.sessionId] = $true
    $credential = $credentialSeen[[string]$record.credentialId]
    if (
      $null -eq $credential -or [string]$credential.state -cne 'active' -or
      [string]$credential.principalId -cne [string]$record.principalId -or
      [string]$credential.hostInstallationId -cne [string]$record.hostInstallationId -or
      [int64]$record.expiresAt -gt [int64]$credential.expiresAt
    ) { Fail 'host_transport_session_credential_mismatch' }
  }
  return $store
}

function Write-Store([string]$Path, $Store, [string]$Root, [string]$Sid) {
  $retired = $null
  $preparedJournal = $null
  $nextIndex = $Store.retiredTransportSessionIndex
  $hasAuthorizationHistory = $Store.authorizationHistoryContract -ceq $AuthorizationHistoryContract
  if ([string]$Store.contract -ceq $Contract) {
    if (-not (Complete-RetiredTransaction $Root $nextIndex)) { Fail 'host_retired_cleanup_pending' }
    if ([Text.Encoding]::UTF8.GetByteCount((ConvertTo-Json -InputObject @($Store.retiredTransportSessionIds) -Compress)) -gt 1048576) {
      Fail 'host_protected_store_too_large'
    }
    $hashes = @($Store.retiredTransportSessionIds | ForEach-Object {
      if ($_ -isnot [string] -or $_ -notmatch $TransportSessionIdPattern) { Fail 'host_transport_session_tombstone_invalid' }
      Get-RetiredDigest ([Text.Encoding]::UTF8.GetBytes($_.ToLowerInvariant()))
    } | Sort-Object -Unique)
    $retired = @{ root = $Root; pages = @{}; obsolete = @{} }
    foreach ($pair in @(@('capability','capabilities','capabilityId'),@('credential','transportCredentials','credentialId'))) {
      foreach ($record in @($Store.($pair[1]) | Where-Object state -CEQ 'revoked')) {
        $history = New-AuthorizationHistoryRecord $pair[0] $record
        $key = Get-AuthorizationHistoryKey $pair[0] $record.($pair[2])
        if (Test-RetiredHash $Store $Root $key) {
          $saved = Read-AuthorizationHistory $Store $Root $pair[0] $record.($pair[2])
          if (($saved | ConvertTo-Json -Compress) -cne ($history.record | ConvertTo-Json -Compress)) { Fail 'host_authorization_history_conflict' }
        } else {
          if ($retired.pages.ContainsKey($key) -or (Test-Path -LiteralPath (Join-Path (Get-RetiredDirectory $Root) ($key + '.dpapi')))) { Fail 'host_authorization_history_conflict' }
          $bytes = Protect-RetiredJson $history
          $retired.pages[$key] = $bytes
          $hashes += @($key, (Get-AuthorizationHistoryProof $key (Get-RetiredDigest $bytes)))
        }
        $hasAuthorizationHistory = $true
      }
    }
    $nextIndex = Merge-RetiredNode $retired $nextIndex '' $hashes
  }
  # All six adapters share this store. A write for another client must retain
  # Claude's binding, just as it retains the other adapters' bindings.
  $serializedStore = $Store | Select-Object -Property *
  if ($null -ne $nextIndex) {
    $serializedStore.retiredTransportSessionIds = @()
    $serializedStore | Add-Member -NotePropertyName retiredTransportSessionIndex -NotePropertyValue $nextIndex -Force
  }
  if ($hasAuthorizationHistory) {
    $serializedStore.capabilities = @($Store.capabilities | Where-Object state -CNE 'revoked')
    $serializedStore.transportCredentials = @($Store.transportCredentials | Where-Object state -CNE 'revoked')
    # Earlier development writers must reject this state, not reuse a revoked
    # capability ID after silently ignoring its indexed history.
    $serializedStore | Add-Member -NotePropertyName authorizationHistoryContract -NotePropertyValue $AuthorizationHistoryContract -Force
  }
  $plain = $serializedStore | ConvertTo-Json -Depth 8 -Compress
  if ([Text.Encoding]::UTF8.GetByteCount($plain) -gt 1048576) { Fail 'host_protected_store_too_large' }
  if ([string]$Store.contract -ceq $Contract) {
    # Protect bytes directly: SecureString's 65536-character ceiling must not
    # turn accumulated anti-replay evidence into a connection failure. Keep
    # every record. This envelope deliberately fails closed in old writers.
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($plain)
    try {
      $ciphertext = [Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, [Text.Encoding]::UTF8.GetBytes($EnvelopeContract),
        [Security.Cryptography.DataProtectionScope]::CurrentUser)
      $credential = [PSCustomObject]@{
        contract = $EnvelopeContract
        ciphertext = [Convert]::ToBase64String($ciphertext)
      }
    } finally { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
  } else {
    # Device enrollment uses its separate, small PSCredential contract.
    $secure = ConvertTo-SecureString -String $plain -AsPlainText -Force
    $credential = [Management.Automation.PSCredential]::new($CredentialName, $secure)
  }
  $temp = Join-Path $Root ('.capabilities.{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
  try {
    $credential | Export-Clixml -LiteralPath $temp -Force
    Set-ProtectedStoreAcl $temp $Sid $false
    $durable = [IO.File]::Open($temp, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
    try { $durable.Flush($true) } finally { $durable.Dispose() }
    if ($null -ne $retired -and $retired.pages.Count) {
      $directory = Get-RetiredDirectory $Root
      if (-not (Test-Path -LiteralPath $directory)) { $null = New-Item -ItemType Directory -Path $directory }
      Set-ProtectedStoreAcl $directory $Sid $true
      $preparedJournal = [PSCustomObject]@{ contract = $RetiredIndexContract + '-transaction'; before = $Store.retiredTransportSessionIndex;
        after = $nextIndex; added = @($retired.pages.Keys); obsolete = @($retired.obsolete.Keys) }
      # Publish the complete write set before creating pages. A terminated write
      # can then clean either the unpublished pages or the superseded pages.
      $journalTemp = Join-Path $directory 'pending.tmp'
      if (Test-Path -LiteralPath $journalTemp) { Remove-Item -LiteralPath $journalTemp -Force }
      Write-RetiredBytes $journalTemp (Protect-RetiredJson $preparedJournal) $Sid
      Move-Item -LiteralPath $journalTemp -Destination (Join-Path $directory 'pending.dpapi')
      foreach ($hash in $retired.pages.Keys) { Write-RetiredBytes (Join-Path $directory ($hash + '.dpapi')) $retired.pages[$hash] $Sid }
    }
    for ($attempt = 0; ; $attempt += 1) {
      try {
        Move-Item -LiteralPath $temp -Destination $Path -Force
        break
      } catch [System.IO.IOException] {
        if ($attempt -ge 20) { throw }
        Start-Sleep -Milliseconds (5 * ($attempt + 1))
      } catch [System.UnauthorizedAccessException] {
        if ($attempt -ge 20) { throw }
        Start-Sleep -Milliseconds (5 * ($attempt + 1))
      }
    }
    if ($null -ne $nextIndex) {
      $Store.retiredTransportSessionIds = @()
      $Store | Add-Member -NotePropertyName retiredTransportSessionIndex -NotePropertyValue $nextIndex -Force
      if ($hasAuthorizationHistory) {
        $Store.capabilities = $serializedStore.capabilities
        $Store.transportCredentials = $serializedStore.transportCredentials
        $Store | Add-Member -NotePropertyName authorizationHistoryContract -NotePropertyValue $AuthorizationHistoryContract -Force
      }
      # The just-published journal is already in memory. A transient read or
      # cleanup I/O failure must not misreport the committed state as failed.
      try { $null = Complete-RetiredTransaction $Root $nextIndex $preparedJournal } catch { }
    }
  } finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    $plain = $null
    $secure = $null
    $credential = $null
  }
}

function Write-Result($Value) {
  if (-not $ResultPipeName -or $ResultPipeName -notmatch '^HelloLynkHostProtected-[A-Za-z0-9_-]{16,96}$') {
    Fail 'host_protected_result_pipe_invalid'
  }
  $json = $Value | ConvertTo-Json -Depth 8 -Compress
  $pipeOptions = [IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::CurrentUserOnly
  $pipe = [IO.Pipes.NamedPipeServerStream]::new(
    $ResultPipeName,
    [IO.Pipes.PipeDirection]::Out,
    1,
    [IO.Pipes.PipeTransmissionMode]::Byte,
    $pipeOptions
  )
  try {
    $pipe.WaitForConnection()
    $writer = [IO.StreamWriter]::new($pipe, [Text.UTF8Encoding]::new($false), 1024, $true)
    try { $writer.Write($json); $writer.Flush() } finally { $writer.Dispose() }
  } finally {
    $pipe.Dispose()
    $json = $null
  }
}

try {
  if (-not $StoreRoot) { Fail 'host_protected_store_root_unavailable' }
  $verificationCommands = @(
    'LoadDeviceEnrollment',
    'Status',
    'VerifyCodexNeutralBinding', 'VerifyOpenClawNeutralBinding',
    'VerifyTraeWorkNeutralBinding', 'VerifyWorkBuddyNeutralBinding', 'VerifyClaudeCodeNeutralBinding',
    'VerifyCursorNeutralBinding', 'VerifyDshNeutralBinding',
    'VerifyTransport', 'VerifyPath', 'VerifyTransportCredentialLifetimeMigration',
    'ResolveCodexNeutralBinding', 'ResolveOpenClawNeutralBinding', 'ResolveTraeWorkNeutralBinding',
    'ResolveWorkBuddyNeutralBinding', 'ResolveClaudeCodeNeutralBinding', 'ResolveCursorNeutralBinding', 'ResolveDshNeutralBinding'
  )
  $readOnlyBindingResolution = $VerifyOnly -and [string]$Command -match '^Resolve(?:Codex|OpenClaw|TraeWork|WorkBuddy|ClaudeCode|Cursor|Dsh)NeutralBinding$'
  $verificationMode = [string]$Command -match '^Verify' -or
    ($VerifyOnly -and [string]$Command -in @('Status', 'LoadDeviceEnrollment')) -or $readOnlyBindingResolution
  if ($VerifyOnly -and -not ($verificationCommands -contains [string]$Command)) {
    Fail 'host_protected_store_verify_only_command_invalid'
  }
  if (
    $StoreRoot -notmatch '^[A-Za-z]:[\\/]' -or
    $StoreRoot.StartsWith('\\') -or
    $StoreRoot.Contains([char]0)
  ) { Fail 'host_protected_store_root_invalid' }
  $root = [IO.Path]::GetFullPath($StoreRoot)
  if ([string]$Command -match 'ClaudeCodeNeutralBinding$' -and -not (Test-ClaudeCodeStoreRoot $root)) {
    Fail 'neutral_claude_code_store_root_invalid'
  }
  if ($root -notmatch '^[A-Za-z]:\\' -or $root.Length -lt 4) {
    Fail 'host_protected_store_root_invalid'
  }
  try { $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)) } catch {
    Fail 'host_protected_store_root_invalid'
  }
  if ($drive.DriveType -ne [IO.DriveType]::Fixed) { Fail 'host_protected_store_root_invalid' }
  Assert-ProtectedStoreNoReparse $root
  if ($verificationMode) {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
      Fail 'host_protected_store_root_invalid'
    }
  } else {
    $null = New-Item -ItemType Directory -Path $root -Force
  }
  Assert-ProtectedStoreNoReparse $root
  $root = Get-ProtectedStoreCanonicalLocalRoot $root
  Assert-ProtectedStoreNoReparse $root
  $rootItem = Get-Item -LiteralPath $root -Force
  if (-not $rootItem.PSIsContainer -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail 'host_protected_store_root_invalid'
  }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $path = Join-Path $root 'capabilities-v1.dpapi.clixml'
  if ($Command -in @('LoadDeviceEnrollment', 'SaveDeviceEnrollment')) {
    # Separate from the capability format so existing installed readers can
    # continue opening their store during the explicit enrollment transition.
    $path = Join-Path $root 'device-enrollment-v1.dpapi.clixml'
  }
  $rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not [IO.Path]::GetFullPath($path).StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail 'host_protected_store_path_invalid'
  }

  # The directory is not atomically replaced, so its idempotent ACL hardening
  # can happen before the per-root data mutex. The main file is hardened again
  # under the mutex immediately before it is read.
  if ($verificationMode) {
    Assert-ProtectedStoreAcl $root $sid $true
  } else {
    Repair-ProtectedStoreAcl $root $sid $true
  }

  if ([string]$Command -eq 'VerifyPath') {
    if (-not $PathToVerify -or -not [IO.Path]::IsPathFullyQualified($PathToVerify)) {
      Fail 'host_protected_store_path_invalid'
    }
    $verifiedPath = [IO.Path]::GetFullPath($PathToVerify)
    if (-not [string]::Equals($verifiedPath, $root, [StringComparison]::OrdinalIgnoreCase) -and
        -not $verifiedPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
      Fail 'host_protected_store_path_invalid'
    }
    Assert-ProtectedStoreNoReparse $verifiedPath
    if ($VerifyDirectory) {
      if (-not (Test-Path -LiteralPath $verifiedPath -PathType Container)) {
        Fail 'host_protected_store_path_invalid'
      }
    } elseif (-not (Test-Path -LiteralPath $verifiedPath -PathType Leaf)) {
      Fail 'host_protected_store_path_invalid'
    }
    $verifiedItem = Get-Item -LiteralPath $verifiedPath -Force
    if (($verifiedItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      Fail 'host_protected_store_path_invalid'
    }
    Assert-ProtectedStoreAcl $verifiedPath $sid ([bool]$VerifyDirectory)
    Write-Result ([PSCustomObject]@{ verified = $true })
    exit 0
  }

  $mutexScope = ('{0}`0{1}' -f $sid, $root.ToUpperInvariant())
  $scopeHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes($mutexScope)
  )).Substring(0, 32)
  $mutex = [Threading.Mutex]::new($false, "Local\HelloLynkNeutralHostProtected-$scopeHash")
  $acquired = $false
  try {
    try { $acquired = $mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { Fail 'host_protected_store_lock_timeout' }
    if (Test-Path -LiteralPath $path -PathType Leaf) {
      $existingItem = Get-Item -LiteralPath $path -Force
      if (($existingItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'host_protected_store_path_invalid'
      }
      if ($verificationMode) { Assert-ProtectedStoreAcl $path $sid $false }
      else { Repair-ProtectedStoreAcl $path $sid $false }
    } elseif ($verificationMode) {
      Fail 'host_protected_store_path_invalid'
    }
    if ([string]$Command -eq 'Status') {
      Write-Result ([PSCustomObject]@{ contract = $Contract; protected = $true })
      exit 0
    }
    if ($Command -in @('LoadDeviceEnrollment', 'SaveDeviceEnrollment')) {
      $enrollment = Read-DeviceEnrollment $path $sid
      if ($Command -eq 'SaveDeviceEnrollment') {
        $plainInput = [Console]::In.ReadToEnd()
        if ([Text.Encoding]::UTF8.GetByteCount($plainInput) -gt 65536) { Fail 'device_enrollment_store_invalid' }
        try { $inputRecord = $plainInput | ConvertFrom-Json } catch { Fail 'device_enrollment_store_invalid' }
        $plainInput = $null
        Assert-ExactFields $inputRecord @('expectedRevision', 'value') 'device_enrollment_store_invalid'
        if ($inputRecord.expectedRevision -isnot [long] -and $inputRecord.expectedRevision -isnot [int]) {
          Fail 'device_enrollment_store_invalid'
        }
        if ($inputRecord.expectedRevision -cne $enrollment.revision) { Fail 'device_enrollment_revision_conflict' }
        if ($null -eq $inputRecord.value -or $inputRecord.value -isnot [PSCustomObject]) { Fail 'device_enrollment_store_invalid' }
        $enrollment.revision = [long]$enrollment.revision + 1
        $enrollment.value = $inputRecord.value
        Write-Store $path $enrollment $root $sid
      }
      Write-Result $enrollment
      exit 0
    }
    $store = Read-Store $path
    $inputRecord = $null
    if (@(
      'DisconnectLocalClient', 'Issue', 'Rotate', 'SaveCodexNeutralBinding', 'RemoveCodexNeutralBinding', 'ReplaceCodexNeutralBinding', 'MigrateCodexNeutralBinding', 'SaveTransportCredential',
      'SaveOpenClawNeutralBinding', 'RemoveOpenClawNeutralBinding', 'MigrateOpenClawNeutralBinding',
      'SaveTraeWorkNeutralBinding', 'RemoveTraeWorkNeutralBinding', 'MigrateTraeWorkNeutralBinding',
      'SaveWorkBuddyNeutralBinding', 'RemoveWorkBuddyNeutralBinding', 'MigrateWorkBuddyNeutralBinding',
      'SaveClaudeCodeNeutralBinding', 'RemoveClaudeCodeNeutralBinding', 'MigrateClaudeCodeNeutralBinding',
      'SaveCursorNeutralBinding', 'RemoveCursorNeutralBinding', 'MigrateCursorNeutralBinding',
      'SaveDshNeutralBinding', 'RemoveDshNeutralBinding', 'MigrateDshNeutralBinding', 'RestoreDshNeutralBinding',
      'SaveTransportSession', 'ReplaceTransportSession', 'SaveEnrollmentTransportCredential', 'MigrateTransportCredentialLifetime'
    ) -contains $Command) {
      $plainInput = [Console]::In.ReadToEnd()
      if ([Text.Encoding]::UTF8.GetByteCount($plainInput) -gt 65536) { Fail 'host_capability_input_too_large' }
      try { $inputRecord = $plainInput | ConvertFrom-Json } catch { Fail 'host_capability_input_invalid' }
      $plainInput = $null
      if ($Command -eq 'DisconnectLocalClient') {
        Assert-ExactFields $inputRecord @('client') 'workbench_disconnect_input_invalid'
      } elseif (@('Issue', 'Rotate') -contains $Command) {
        $null = Assert-Record $inputRecord
        if ([string]$inputRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveCodexNeutralBinding') {
        $null = Assert-CodexNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'RemoveCodexNeutralBinding') {
        $null = Assert-CodexNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'ReplaceCodexNeutralBinding') {
        Assert-ExactFields $inputRecord @('previousBinding', 'replacementBinding') 'neutral_codex_binding_invalid'
        $null = Assert-CodexNeutralBinding $inputRecord.previousBinding $true
        $null = Assert-CodexNeutralBinding $inputRecord.replacementBinding $true
      } elseif ([string]$Command -eq 'MigrateCodexNeutralBinding') {
        Assert-ExactFields $inputRecord @(
          'previousBinding', 'replacementBinding', 'replacementRecord'
        ) 'neutral_codex_binding_invalid'
        $null = Assert-CodexNeutralBinding $inputRecord.previousBinding $true
        $null = Assert-CodexNeutralBinding $inputRecord.replacementBinding $true
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveOpenClawNeutralBinding') {
        $null = Assert-OpenClawNeutralBinding $inputRecord $true $true
      } elseif ([string]$Command -eq 'RemoveOpenClawNeutralBinding') {
        $null = Assert-OpenClawNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'MigrateOpenClawNeutralBinding') {
        Assert-ExactFields $inputRecord @(
          'previousBinding', 'replacementBinding', 'replacementRecord'
        ) 'neutral_openclaw_binding_invalid'
        $null = Assert-OpenClawNeutralBinding $inputRecord.previousBinding $true $false
        $null = Assert-OpenClawNeutralBinding $inputRecord.replacementBinding $true $true
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveTraeWorkNeutralBinding') {
        $null = Assert-TraeWorkNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'RemoveTraeWorkNeutralBinding') {
        $null = Assert-TraeWorkNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'MigrateTraeWorkNeutralBinding') {
        Assert-ExactFields $inputRecord @(
          'previousBinding', 'replacementBinding', 'replacementRecord'
        ) 'neutral_trae_work_binding_invalid'
        $null = Assert-TraeWorkNeutralBinding $inputRecord.previousBinding $true
        $null = Assert-TraeWorkNeutralBinding $inputRecord.replacementBinding $true
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveWorkBuddyNeutralBinding') {
        $null = Assert-WorkBuddyNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'RemoveWorkBuddyNeutralBinding') {
        $null = Assert-WorkBuddyNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'MigrateWorkBuddyNeutralBinding') {
        Assert-ExactFields $inputRecord @(
          'previousBinding', 'replacementBinding', 'replacementRecord'
        ) 'neutral_workbuddy_binding_invalid'
        $null = Assert-WorkBuddyNeutralBinding $inputRecord.previousBinding $true
        $null = Assert-WorkBuddyNeutralBinding $inputRecord.replacementBinding $true
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveClaudeCodeNeutralBinding') {
        $null = Assert-ClaudeCodeNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'RemoveClaudeCodeNeutralBinding') {
        $null = Assert-ClaudeCodeNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'MigrateClaudeCodeNeutralBinding') {
        Assert-ExactFields $inputRecord @(
          'previousBinding', 'replacementBinding', 'replacementRecord'
        ) 'neutral_claude_code_binding_invalid'
        $null = Assert-ClaudeCodeNeutralBinding $inputRecord.previousBinding $true
        $null = Assert-ClaudeCodeNeutralBinding $inputRecord.replacementBinding $true
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveCursorNeutralBinding') {
        $null = Assert-CursorNeutralBinding $inputRecord $true $true
      } elseif ([string]$Command -eq 'RemoveCursorNeutralBinding') {
        $null = Assert-CursorNeutralBinding $inputRecord $true
      } elseif ([string]$Command -eq 'MigrateCursorNeutralBinding') {
        Assert-ExactFields $inputRecord @(
          'previousBinding', 'replacementBinding', 'replacementRecord'
        ) 'neutral_cursor_binding_invalid'
        $null = Assert-CursorNeutralBinding $inputRecord.previousBinding $true
        $null = Assert-CursorNeutralBinding $inputRecord.replacementBinding $true $true
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ([string]$Command -eq 'SaveDshNeutralBinding') {
        $null = Assert-DshNeutralBinding $inputRecord $true $true
      } elseif ([string]$Command -eq 'RemoveDshNeutralBinding') {
        $null = Assert-DshNeutralBinding $inputRecord $true
      } elseif ([string]$Command -in @('MigrateDshNeutralBinding', 'RestoreDshNeutralBinding')) {
        Assert-ExactFields $inputRecord @('previousBinding', 'replacementBinding', 'replacementRecord') 'neutral_dsh_binding_invalid'
        $null = Assert-DshNeutralBinding $inputRecord.previousBinding $true
        $restoringPrevious = [string]$Command -eq 'RestoreDshNeutralBinding'
        $null = Assert-DshNeutralBinding $inputRecord.replacementBinding $true (-not $restoringPrevious)
        if ($restoringPrevious -and -not (Test-ExactScopeSequence $inputRecord.replacementBinding.scopes $DshNeutralPreviousScopes)) {
          Fail 'neutral_dsh_capability_binding_mismatch'
        }
        $null = Assert-Record $inputRecord.replacementRecord
        if ([string]$inputRecord.replacementRecord.state -ne 'active') { Fail 'host_capability_input_invalid' }
      } elseif ($Command -eq 'MigrateTransportCredentialLifetime') {
        Assert-ExactFields $inputRecord @('previous', 'proof') 'host_transport_migration_input_invalid'
        $null = Assert-TransportCredential $inputRecord.previous
        Assert-ExactFields $inputRecord.proof @('credentialId', 'principalId', 'hostId', 'credentialCreatedAt', 'credentialExpiresAt') 'host_transport_migration_proof_invalid'
      } elseif ($Command -in @('SaveTransportCredential', 'SaveEnrollmentTransportCredential')) {
        $null = Assert-TransportCredential $inputRecord
        if ([string]$inputRecord.state -ne 'active') { Fail 'host_transport_credential_input_invalid' }
      } else {
        $null = Assert-TransportSession $inputRecord
      }
    }

    $bindingVerification = [string]$Command -match '^Verify(?:Codex|OpenClaw|TraeWork|WorkBuddy|ClaudeCode|Cursor|Dsh)NeutralBinding$'
    $operationCommand = switch ([string]$Command) {
      'VerifyCodexNeutralBinding' { 'ResolveCodexNeutralBinding' }
      'VerifyOpenClawNeutralBinding' { 'ResolveOpenClawNeutralBinding' }
      'VerifyTraeWorkNeutralBinding' { 'ResolveTraeWorkNeutralBinding' }
      'VerifyWorkBuddyNeutralBinding' { 'ResolveWorkBuddyNeutralBinding' }
      'VerifyClaudeCodeNeutralBinding' { 'ResolveClaudeCodeNeutralBinding' }
      'VerifyCursorNeutralBinding' { 'ResolveCursorNeutralBinding' }
      'VerifyDshNeutralBinding' { 'ResolveDshNeutralBinding' }
      'RestoreDshNeutralBinding' { 'MigrateDshNeutralBinding' }
      default { [string]$Command }
    }
    switch ($operationCommand) {
      'DisconnectLocalClient' {
        Assert-ExactFields $inputRecord @('client') 'workbench_disconnect_input_invalid'
        $fields = @{
          'codex' = 'codexNeutralBindings'; 'openclaw' = 'openClawNeutralBindings'
          'trae-work' = 'traeWorkNeutralBindings'; 'workbuddy' = 'workBuddyNeutralBindings'
          'claude-code' = 'claudeCodeNeutralBindings'
          'cursor' = 'cursorNeutralBindings'; 'dsh' = 'dshNeutralBindings'
        }
        $client = [string]$inputRecord.client
        if (-not $fields.ContainsKey($client)) { Fail 'workbench_account_client_invalid' }
        if ($client -ceq 'claude-code' -and -not (Test-ClaudeCodeStoreRoot $root)) {
          Fail 'neutral_claude_code_store_root_invalid'
        }
        foreach ($record in @($store.capabilities)) {
          if ([string]$record.adapterId -ceq $client -and [string]$record.state -ceq 'active') {
            $record.state = 'revoked'
            $record.revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
          }
        }
        $field = $fields[$client]
        $store.$field = @()
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ disconnected = $true; client = $client })
      }
      'Issue' {
        if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.capabilityId) {
          Fail 'host_capability_id_conflict'
        }
        $store.capabilities = @($store.capabilities) + @($inputRecord)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ record = $inputRecord })
      }
      'Load' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $records = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($records.Count -ne 1 -or [string]$records[0].state -ne 'active') { Fail 'host_capability_inactive' }
        Write-Result ([PSCustomObject]@{ record = $records[0] })
      }
      'Revoke' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $records = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($records.Count -eq 0) {
          $archived = Read-AuthorizationHistory $store $root 'capability' $CapabilityId
          if ($null -ne $archived) { $records = @($archived) }
        }
        if ($records.Count -ne 1) { Fail 'host_capability_missing' }
        if ([string]$records[0].state -eq 'active') {
          $records[0].state = 'revoked'
          $records[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ capabilityId = $CapabilityId; state = 'revoked'; revokedAt = $records[0].revokedAt })
      }
      'Rotate' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -ne 'active') { Fail 'host_capability_inactive' }
        if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.capabilityId) {
          Fail 'host_capability_id_conflict'
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.capabilities = @($store.capabilities) + @($inputRecord)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ record = $inputRecord; replacedCapabilityId = $CapabilityId })
      }
      'Status' {
        Fail 'host_protected_store_status_invalid'
      }
      'SaveCodexNeutralBinding' {
        $existing = @($store.codexNeutralBindings | Where-Object adapterId -CEQ 'codex')
        if ($existing.Count -gt 1) { Fail 'neutral_codex_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-CodexNeutralBindingEqual $existing[0] $inputRecord)) {
            Fail 'neutral_codex_binding_invalid'
          }
        } else {
          $store.codexNeutralBindings = @($store.codexNeutralBindings) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveCodexNeutralBinding' {
        $bindings = @($store.codexNeutralBindings | Where-Object adapterId -CEQ 'codex')
        if ($bindings.Count -eq 0) { Fail 'neutral_codex_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_codex_binding_invalid' }
        $binding = Assert-CodexNeutralBinding $bindings[0] $true
        $activeCodex = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'codex'
        })
        $matching = @($activeCodex | Where-Object { Test-CodexCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) {
          if ($activeCodex.Count -eq 0) { Fail 'neutral_codex_capability_missing' }
          Fail 'neutral_codex_capability_binding_mismatch'
        }
        if ($matching.Count -gt 1) { Fail 'neutral_codex_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveCodexNeutralBinding' {
        $matching = @($store.codexNeutralBindings | Where-Object {
          Test-CodexNeutralBindingEqual $_ $inputRecord
        })
        if ($matching.Count -eq 0) { Fail 'neutral_codex_binding_invalid' }
        if ($matching.Count -gt 1) { Fail 'neutral_codex_binding_invalid' }
        $store.codexNeutralBindings = @($store.codexNeutralBindings | Where-Object {
          -not (Test-CodexNeutralBindingEqual $_ $matching[0])
        })
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'ReplaceCodexNeutralBinding' {
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement) -or
            -not (Test-ExactScopeSequence $previous.scopes $replacement.scopes)) {
          Fail 'neutral_codex_capability_binding_mismatch'
        }
        $bindings = @($store.codexNeutralBindings | Where-Object adapterId -CEQ 'codex')
        if ($bindings.Count -ne 1 -or
            -not (Test-CodexNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_codex_binding_invalid'
        }
        $matching = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and (Test-CodexCapabilityMatch $_ $replacement)
        })
        if ($matching.Count -ne 1) { Fail 'neutral_codex_capability_ambiguous' }
        $store.codexNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ binding = $replacement })
      }
      'MigrateCodexNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) {
          Fail 'neutral_codex_capability_binding_mismatch'
        }
        $bindings = @($store.codexNeutralBindings | Where-Object adapterId -CEQ 'codex')
        if ($bindings.Count -ne 1 -or
            -not (Test-CodexNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_codex_binding_invalid'
        }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or
            -not (Test-CodexCapabilityMatch $old[0] $previous)) {
          Fail 'neutral_codex_capability_binding_mismatch'
        }
        if (-not (Test-CodexCapabilityMatch $inputRecord.replacementRecord $replacement)) {
          Fail 'neutral_codex_capability_binding_mismatch'
        }
        $candidates = @($store.capabilities | Where-Object {
          [string]$_.capabilityId -cne $CapabilityId -and
          [string]$_.state -ceq 'active' -and
          (Test-CodexCapabilityMatch $_ $replacement)
        })
        if ($candidates.Count -gt 1) { Fail 'neutral_codex_capability_ambiguous' }
        if ($candidates.Count -eq 1) {
          $selected = $candidates[0]
        } else {
          if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) {
            Fail 'host_capability_id_conflict'
          }
          $selected = $inputRecord.replacementRecord
          $store.capabilities = @($store.capabilities) + @($selected)
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.codexNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{
          binding = $replacement; record = $selected; replacedCapabilityId = $CapabilityId
        })
      }
      'SaveOpenClawNeutralBinding' {
        $existing = @($store.openClawNeutralBindings | Where-Object adapterId -CEQ 'openclaw')
        if ($existing.Count -gt 1) { Fail 'neutral_openclaw_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-OpenClawNeutralBindingEqual $existing[0] $inputRecord)) {
            Fail 'neutral_openclaw_binding_invalid'
          }
        } else {
          $store.openClawNeutralBindings = @($store.openClawNeutralBindings) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveOpenClawNeutralBinding' {
        $bindings = @($store.openClawNeutralBindings | Where-Object adapterId -CEQ 'openclaw')
        if ($bindings.Count -eq 0) { Fail 'neutral_openclaw_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_openclaw_binding_invalid' }
        $binding = Assert-OpenClawNeutralBinding $bindings[0] $true
        $activeOpenClaw = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'openclaw'
        })
        $matching = @($activeOpenClaw | Where-Object { Test-OpenClawCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) {
          if ($activeOpenClaw.Count -eq 0) { Fail 'neutral_openclaw_capability_missing' }
          Fail 'neutral_openclaw_capability_binding_mismatch'
        }
        if ($matching.Count -gt 1) { Fail 'neutral_openclaw_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveOpenClawNeutralBinding' {
        $matching = @($store.openClawNeutralBindings | Where-Object {
          Test-OpenClawNeutralBindingEqual $_ $inputRecord
        })
        if ($matching.Count -ne 1) { Fail 'neutral_openclaw_binding_invalid' }
        $store.openClawNeutralBindings = @($store.openClawNeutralBindings | Where-Object {
          -not (Test-OpenClawNeutralBindingEqual $_ $matching[0])
        })
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'MigrateOpenClawNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) {
          Fail 'neutral_openclaw_capability_binding_mismatch'
        }
        $bindings = @($store.openClawNeutralBindings | Where-Object adapterId -CEQ 'openclaw')
        if ($bindings.Count -ne 1 -or
            -not (Test-OpenClawNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_openclaw_binding_invalid'
        }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or
            -not (Test-OpenClawCapabilityMatch $old[0] $previous)) {
          Fail 'neutral_openclaw_capability_binding_mismatch'
        }
        if (-not (Test-OpenClawCapabilityMatch $inputRecord.replacementRecord $replacement)) {
          Fail 'neutral_openclaw_capability_binding_mismatch'
        }
        $candidates = @($store.capabilities | Where-Object {
          [string]$_.capabilityId -cne $CapabilityId -and
          [string]$_.state -ceq 'active' -and
          (Test-OpenClawCapabilityMatch $_ $replacement)
        })
        if ($candidates.Count -gt 1) { Fail 'neutral_openclaw_capability_ambiguous' }
        if ($candidates.Count -eq 1) {
          $selected = $candidates[0]
        } else {
          if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) {
            Fail 'host_capability_id_conflict'
          }
          $selected = $inputRecord.replacementRecord
          $store.capabilities = @($store.capabilities) + @($selected)
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.openClawNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{
          binding = $replacement; record = $selected; replacedCapabilityId = $CapabilityId
        })
      }
      'SaveTraeWorkNeutralBinding' {
        $existing = @($store.traeWorkNeutralBindings | Where-Object adapterId -CEQ 'trae-work')
        if ($existing.Count -gt 1) { Fail 'neutral_trae_work_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-TraeWorkNeutralBindingEqual $existing[0] $inputRecord)) {
            Fail 'neutral_trae_work_binding_invalid'
          }
        } else {
          $store.traeWorkNeutralBindings = @($store.traeWorkNeutralBindings) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveTraeWorkNeutralBinding' {
        $bindings = @($store.traeWorkNeutralBindings | Where-Object adapterId -CEQ 'trae-work')
        if ($bindings.Count -eq 0) { Fail 'neutral_trae_work_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_trae_work_binding_invalid' }
        $binding = Assert-TraeWorkNeutralBinding $bindings[0] $true
        $activeTraeWork = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'trae-work'
        })
        $matching = @($activeTraeWork | Where-Object { Test-TraeWorkCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) {
          if ($activeTraeWork.Count -eq 0) { Fail 'neutral_trae_work_capability_missing' }
          Fail 'neutral_trae_work_capability_binding_mismatch'
        }
        if ($matching.Count -gt 1) { Fail 'neutral_trae_work_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveTraeWorkNeutralBinding' {
        $matching = @($store.traeWorkNeutralBindings | Where-Object {
          Test-TraeWorkNeutralBindingEqual $_ $inputRecord
        })
        if ($matching.Count -ne 1) { Fail 'neutral_trae_work_binding_invalid' }
        $store.traeWorkNeutralBindings = @($store.traeWorkNeutralBindings | Where-Object {
          -not (Test-TraeWorkNeutralBindingEqual $_ $matching[0])
        })
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'MigrateTraeWorkNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) {
          Fail 'neutral_trae_work_capability_binding_mismatch'
        }
        $bindings = @($store.traeWorkNeutralBindings | Where-Object adapterId -CEQ 'trae-work')
        if ($bindings.Count -ne 1 -or
            -not (Test-TraeWorkNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_trae_work_binding_invalid'
        }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or
            -not (Test-TraeWorkCapabilityMatch $old[0] $previous)) {
          Fail 'neutral_trae_work_capability_binding_mismatch'
        }
        if (-not (Test-TraeWorkCapabilityMatch $inputRecord.replacementRecord $replacement)) {
          Fail 'neutral_trae_work_capability_binding_mismatch'
        }
        $candidates = @($store.capabilities | Where-Object {
          [string]$_.capabilityId -cne $CapabilityId -and
          [string]$_.state -ceq 'active' -and
          (Test-TraeWorkCapabilityMatch $_ $replacement)
        })
        if ($candidates.Count -gt 1) { Fail 'neutral_trae_work_capability_ambiguous' }
        if ($candidates.Count -eq 1) {
          $selected = $candidates[0]
        } else {
          if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) {
            Fail 'host_capability_id_conflict'
          }
          $selected = $inputRecord.replacementRecord
          $store.capabilities = @($store.capabilities) + @($selected)
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.traeWorkNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{
          binding = $replacement; record = $selected; replacedCapabilityId = $CapabilityId
        })
      }
      'SaveWorkBuddyNeutralBinding' {
        $existing = @($store.workBuddyNeutralBindings | Where-Object adapterId -CEQ 'workbuddy')
        if ($existing.Count -gt 1) { Fail 'neutral_workbuddy_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-WorkBuddyNeutralBindingEqual $existing[0] $inputRecord)) {
            Fail 'neutral_workbuddy_binding_invalid'
          }
        } else {
          $store.workBuddyNeutralBindings = @($store.workBuddyNeutralBindings) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveWorkBuddyNeutralBinding' {
        $bindings = @($store.workBuddyNeutralBindings | Where-Object adapterId -CEQ 'workbuddy')
        if ($bindings.Count -eq 0) { Fail 'neutral_workbuddy_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_workbuddy_binding_invalid' }
        $binding = Assert-WorkBuddyNeutralBinding $bindings[0] $true
        $activeWorkBuddy = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'workbuddy'
        })
        $matching = @($activeWorkBuddy | Where-Object { Test-WorkBuddyCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) {
          if ($activeWorkBuddy.Count -eq 0) { Fail 'neutral_workbuddy_capability_missing' }
          Fail 'neutral_workbuddy_capability_binding_mismatch'
        }
        if ($matching.Count -gt 1) { Fail 'neutral_workbuddy_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveWorkBuddyNeutralBinding' {
        $matching = @($store.workBuddyNeutralBindings | Where-Object {
          Test-WorkBuddyNeutralBindingEqual $_ $inputRecord
        })
        if ($matching.Count -ne 1) { Fail 'neutral_workbuddy_binding_invalid' }
        $store.workBuddyNeutralBindings = @($store.workBuddyNeutralBindings | Where-Object {
          -not (Test-WorkBuddyNeutralBindingEqual $_ $matching[0])
        })
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'MigrateWorkBuddyNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) {
          Fail 'neutral_workbuddy_capability_binding_mismatch'
        }
        $bindings = @($store.workBuddyNeutralBindings | Where-Object adapterId -CEQ 'workbuddy')
        if ($bindings.Count -ne 1 -or
            -not (Test-WorkBuddyNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_workbuddy_binding_invalid'
        }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or
            -not (Test-WorkBuddyCapabilityMatch $old[0] $previous)) {
          Fail 'neutral_workbuddy_capability_binding_mismatch'
        }
        if (-not (Test-WorkBuddyCapabilityMatch $inputRecord.replacementRecord $replacement)) {
          Fail 'neutral_workbuddy_capability_binding_mismatch'
        }
        $candidates = @($store.capabilities | Where-Object {
          [string]$_.capabilityId -cne $CapabilityId -and
          [string]$_.state -ceq 'active' -and
          (Test-WorkBuddyCapabilityMatch $_ $replacement)
        })
        if ($candidates.Count -gt 1) { Fail 'neutral_workbuddy_capability_ambiguous' }
        if ($candidates.Count -eq 1) {
          $selected = $candidates[0]
        } else {
          if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) {
            Fail 'host_capability_id_conflict'
          }
          $selected = $inputRecord.replacementRecord
          $store.capabilities = @($store.capabilities) + @($selected)
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.workBuddyNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{
          binding = $replacement; record = $selected; replacedCapabilityId = $CapabilityId
        })
      }
      'SaveClaudeCodeNeutralBinding' {
        $existing = @($store.claudeCodeNeutralBindings | Where-Object adapterId -CEQ 'claude-code')
        if ($existing.Count -gt 1) { Fail 'neutral_claude_code_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-ClaudeCodeNeutralBindingEqual $existing[0] $inputRecord)) {
            Fail 'neutral_claude_code_binding_invalid'
          }
        } else {
          $store.claudeCodeNeutralBindings = @($store.claudeCodeNeutralBindings) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveClaudeCodeNeutralBinding' {
        $bindings = @($store.claudeCodeNeutralBindings | Where-Object adapterId -CEQ 'claude-code')
        if ($bindings.Count -eq 0) { Fail 'neutral_claude_code_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_claude_code_binding_invalid' }
        $binding = Assert-ClaudeCodeNeutralBinding $bindings[0] $true
        $activeClaudeCode = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'claude-code'
        })
        $matching = @($activeClaudeCode | Where-Object { Test-ClaudeCodeCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) {
          if ($activeClaudeCode.Count -eq 0) { Fail 'neutral_claude_code_capability_missing' }
          Fail 'neutral_claude_code_capability_binding_mismatch'
        }
        if ($matching.Count -gt 1) { Fail 'neutral_claude_code_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveClaudeCodeNeutralBinding' {
        $matching = @($store.claudeCodeNeutralBindings | Where-Object {
          Test-ClaudeCodeNeutralBindingEqual $_ $inputRecord
        })
        if ($matching.Count -ne 1) { Fail 'neutral_claude_code_binding_invalid' }
        $store.claudeCodeNeutralBindings = @($store.claudeCodeNeutralBindings | Where-Object {
          -not (Test-ClaudeCodeNeutralBindingEqual $_ $matching[0])
        })
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'MigrateClaudeCodeNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) {
          Fail 'neutral_claude_code_capability_binding_mismatch'
        }
        $bindings = @($store.claudeCodeNeutralBindings | Where-Object adapterId -CEQ 'claude-code')
        if ($bindings.Count -ne 1 -or
            -not (Test-ClaudeCodeNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_claude_code_binding_invalid'
        }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or
            -not (Test-ClaudeCodeCapabilityMatch $old[0] $previous)) {
          Fail 'neutral_claude_code_capability_binding_mismatch'
        }
        if (-not (Test-ClaudeCodeCapabilityMatch $inputRecord.replacementRecord $replacement)) {
          Fail 'neutral_claude_code_capability_binding_mismatch'
        }
        $candidates = @($store.capabilities | Where-Object {
          [string]$_.capabilityId -cne $CapabilityId -and
          [string]$_.state -ceq 'active' -and
          (Test-ClaudeCodeCapabilityMatch $_ $replacement)
        })
        if ($candidates.Count -gt 1) { Fail 'neutral_claude_code_capability_ambiguous' }
        if ($candidates.Count -eq 1) {
          $selected = $candidates[0]
        } else {
          if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) {
            Fail 'host_capability_id_conflict'
          }
          $selected = $inputRecord.replacementRecord
          $store.capabilities = @($store.capabilities) + @($selected)
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.claudeCodeNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{
          binding = $replacement; record = $selected; replacedCapabilityId = $CapabilityId
        })
      }
      'SaveCursorNeutralBinding' {
        $existing = @($store.cursorNeutralBindings | Where-Object adapterId -CEQ 'cursor')
        if ($existing.Count -gt 1) { Fail 'neutral_cursor_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-CursorNeutralBindingEqual $existing[0] $inputRecord)) {
            Fail 'neutral_cursor_binding_invalid'
          }
        } else {
          $store.cursorNeutralBindings = @($store.cursorNeutralBindings) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveCursorNeutralBinding' {
        $bindings = @($store.cursorNeutralBindings | Where-Object adapterId -CEQ 'cursor')
        if ($bindings.Count -eq 0) { Fail 'neutral_cursor_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_cursor_binding_invalid' }
        $binding = Assert-CursorNeutralBinding $bindings[0] $true
        $activeCursor = @($store.capabilities | Where-Object {
          [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'cursor'
        })
        $matching = @($activeCursor | Where-Object { Test-CursorCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) {
          if ($activeCursor.Count -eq 0) { Fail 'neutral_cursor_capability_missing' }
          Fail 'neutral_cursor_capability_binding_mismatch'
        }
        if ($matching.Count -gt 1) { Fail 'neutral_cursor_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveCursorNeutralBinding' {
        $matching = @($store.cursorNeutralBindings | Where-Object {
          Test-CursorNeutralBindingEqual $_ $inputRecord
        })
        if ($matching.Count -ne 1) { Fail 'neutral_cursor_binding_invalid' }
        $store.cursorNeutralBindings = @($store.cursorNeutralBindings | Where-Object {
          -not (Test-CursorNeutralBindingEqual $_ $matching[0])
        })
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'MigrateCursorNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding
        $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) {
          Fail 'neutral_cursor_capability_binding_mismatch'
        }
        $bindings = @($store.cursorNeutralBindings | Where-Object adapterId -CEQ 'cursor')
        if ($bindings.Count -ne 1 -or
            -not (Test-CursorNeutralBindingEqual $bindings[0] $previous)) {
          Fail 'neutral_cursor_binding_invalid'
        }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or
            -not (Test-CursorCapabilityMatch $old[0] $previous)) {
          Fail 'neutral_cursor_capability_binding_mismatch'
        }
        if (-not (Test-CursorCapabilityMatch $inputRecord.replacementRecord $replacement)) {
          Fail 'neutral_cursor_capability_binding_mismatch'
        }
        $candidates = @($store.capabilities | Where-Object {
          [string]$_.capabilityId -cne $CapabilityId -and
          [string]$_.state -ceq 'active' -and
          (Test-CursorCapabilityMatch $_ $replacement)
        })
        if ($candidates.Count -gt 1) { Fail 'neutral_cursor_capability_ambiguous' }
        if ($candidates.Count -eq 1) {
          $selected = $candidates[0]
        } else {
          if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) {
            Fail 'host_capability_id_conflict'
          }
          $selected = $inputRecord.replacementRecord
          $store.capabilities = @($store.capabilities) + @($selected)
        }
        $old[0].state = 'revoked'
        $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $store.cursorNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid
        Write-Result ([PSCustomObject]@{
          binding = $replacement; record = $selected; replacedCapabilityId = $CapabilityId
        })
      }
      'SaveDshNeutralBinding' {
        $existing = @($store.dshNeutralBindings | Where-Object adapterId -CEQ 'dsh')
        if ($existing.Count -gt 1) { Fail 'neutral_dsh_binding_invalid' }
        if ($existing.Count -eq 1) {
          if (-not (Test-DshNeutralBindingEqual $existing[0] $inputRecord)) { Fail 'neutral_dsh_binding_invalid' }
        } else { $store.dshNeutralBindings = @($store.dshNeutralBindings) + @($inputRecord); Write-Store $path $store $root $sid }
        Write-Result ([PSCustomObject]@{ binding = $inputRecord })
      }
      'ResolveDshNeutralBinding' {
        $bindings = @($store.dshNeutralBindings | Where-Object adapterId -CEQ 'dsh')
        if ($bindings.Count -eq 0) { Fail 'neutral_dsh_binding_configuration_required' }
        if ($bindings.Count -gt 1) { Fail 'neutral_dsh_binding_invalid' }
        $binding = Assert-DshNeutralBinding $bindings[0] $true
        $activeDsh = @($store.capabilities | Where-Object { [string]$_.state -ceq 'active' -and [string]$_.adapterId -ceq 'dsh' })
        $matching = @($activeDsh | Where-Object { Test-DshCapabilityMatch $_ $binding })
        if ($matching.Count -eq 0) { if ($activeDsh.Count -eq 0) { Fail 'neutral_dsh_capability_missing' }; Fail 'neutral_dsh_capability_binding_mismatch' }
        if ($matching.Count -gt 1) { Fail 'neutral_dsh_capability_ambiguous' }
        $record = if ($bindingVerification) { Get-PublicCapabilityRecord $matching[0] } else { $matching[0] }
        Write-Result ([PSCustomObject]@{ binding = $binding; record = $record })
      }
      'RemoveDshNeutralBinding' {
        $matching = @($store.dshNeutralBindings | Where-Object { Test-DshNeutralBindingEqual $_ $inputRecord })
        if ($matching.Count -ne 1) { Fail 'neutral_dsh_binding_invalid' }
        $store.dshNeutralBindings = @($store.dshNeutralBindings | Where-Object { -not (Test-DshNeutralBindingEqual $_ $matching[0]) })
        Write-Store $path $store $root $sid; Write-Result ([PSCustomObject]@{ removed = $true })
      }
      'MigrateDshNeutralBinding' {
        if ($CapabilityId -notmatch $CapabilityIdPattern) { Fail 'host_capability_id_invalid' }
        $previous = $inputRecord.previousBinding; $replacement = $inputRecord.replacementBinding
        if (-not (Test-NeutralBindingOwnerEqual $previous $replacement)) { Fail 'neutral_dsh_capability_binding_mismatch' }
        $bindings = @($store.dshNeutralBindings | Where-Object adapterId -CEQ 'dsh')
        if ($bindings.Count -ne 1 -or -not (Test-DshNeutralBindingEqual $bindings[0] $previous)) { Fail 'neutral_dsh_binding_invalid' }
        $old = @($store.capabilities | Where-Object capabilityId -CEQ $CapabilityId)
        if ($old.Count -ne 1 -or [string]$old[0].state -cne 'active' -or -not (Test-DshCapabilityMatch $old[0] $previous) -or -not (Test-DshCapabilityMatch $inputRecord.replacementRecord $replacement)) { Fail 'neutral_dsh_capability_binding_mismatch' }
        if (@($store.capabilities | Where-Object { [string]$_.capabilityId -cne $CapabilityId -and [string]$_.state -ceq 'active' -and (Test-DshCapabilityMatch $_ $replacement) }).Count -ne 0) { Fail 'neutral_dsh_capability_ambiguous' }
        if (Test-AuthorizationIdUsed $store $root 'capability' $inputRecord.replacementRecord.capabilityId) { Fail 'host_capability_id_conflict' }
        $store.capabilities = @($store.capabilities) + @($inputRecord.replacementRecord); $old[0].state = 'revoked'; $old[0].revokedAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); $store.dshNeutralBindings = @($replacement)
        Write-Store $path $store $root $sid; Write-Result ([PSCustomObject]@{ binding = $replacement; record = $inputRecord.replacementRecord; replacedCapabilityId = $CapabilityId })
      }
      { $_ -in @('SaveTransportCredential', 'SaveEnrollmentTransportCredential') } {
        $enrollmentUpgrade = $Command -eq 'SaveEnrollmentTransportCredential'
        if ($enrollmentUpgrade) {
          # This is the same per-root mutex used by enrollment CAS. Approval
          # and replacement cannot race with another local setup operation.
          $enrollment = Read-DeviceEnrollment (Join-Path $root 'device-enrollment-v1.dpapi.clixml') $sid
          Assert-ExactFields $enrollment.value @('baseUrl', 'hellolynkId', 'hostId', 'deviceLabel', 'requestId', 'proof', 'approval', 'intents') 'device_enrollment_transport_approval_mismatch'
          $approval = $enrollment.value.approval
          Assert-ExactFields $approval @('status', 'principalId', 'hellolynkId', 'region', 'hostId', 'hostTransportCredential') 'device_enrollment_transport_approval_mismatch'
          Assert-ExactFields $approval.hostTransportCredential @('credentialId', 'credential', 'createdAt', 'expiresAt') 'device_enrollment_transport_approval_mismatch'
          if ($null -eq $approval -or [string]$approval.status -cne 'approved' -or
              [string]$approval.principalId -cne [string]$inputRecord.principalId -or
              [string]$approval.hostId -cne [string]$inputRecord.hostInstallationId -or
              [string]$enrollment.value.hostId -cne [string]$inputRecord.hostInstallationId -or
              [string]$approval.hellolynkId -cne [string]$enrollment.value.hellolynkId -or
              [string]$approval.hostTransportCredential.credentialId -cne [string]$inputRecord.credentialId -or
              [string]$approval.hostTransportCredential.credential -cne [string]$inputRecord.secret) {
            Fail 'device_enrollment_transport_approval_mismatch'
          }
          try {
            $approvedCreatedAt = ([DateTimeOffset]$approval.hostTransportCredential.createdAt).ToUnixTimeMilliseconds()
            $approvedExpiresAt = ([DateTimeOffset]$approval.hostTransportCredential.expiresAt).ToUnixTimeMilliseconds()
          } catch { Fail 'device_enrollment_transport_approval_mismatch' }
          if ($approvedCreatedAt -ne [int64]$inputRecord.issuedAt -or $approvedExpiresAt -ne [int64]$inputRecord.expiresAt) {
            Fail 'device_enrollment_transport_approval_mismatch'
          }
          if ([int64]$inputRecord.expiresAt -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) {
            Fail 'host_transport_credential_expired'
          }
        }
        $existing = @($store.transportCredentials | Where-Object credentialId -CEQ $inputRecord.credentialId)
        if ($existing.Count -eq 0 -and (Test-AuthorizationIdUsed $store $root 'credential' $inputRecord.credentialId)) {
          Fail 'host_transport_credential_immutable_conflict'
        }
        if ($existing.Count -gt 1) { Fail 'host_transport_credential_duplicate' }
        if ($existing.Count -eq 1) {
          if (-not (Test-TransportCredentialEqual $existing[0] $inputRecord)) {
            Fail 'host_transport_credential_immutable_conflict'
          }
        } else {
          $sameOwner = @($store.transportCredentials | Where-Object {
            [string]$_.principalId -ceq [string]$inputRecord.principalId -and
            [string]$_.hostInstallationId -ceq [string]$inputRecord.hostInstallationId -and
            [string]$_.state -ceq 'active'
          })
          if ($sameOwner.Count -gt 1 -or ($sameOwner.Count -gt 0 -and -not $enrollmentUpgrade)) {
            Fail 'host_transport_credential_ambiguous'
          }
          if ($sameOwner.Count -eq 1) {
            $old = $sameOwner[0]
            $replacementTime = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
            if ($replacementTime -lt [int64]$old.issuedAt) { Fail 'host_transport_credential_revoke_timestamp_invalid' }
            $sessions = @($store.transportSessions | Where-Object credentialId -CEQ $old.credentialId)
            $store.retiredTransportSessionIds = @(
              @($store.retiredTransportSessionIds) + @($sessions | ForEach-Object sessionId) | Sort-Object -Unique
            )
            $store.transportSessions = @($store.transportSessions | Where-Object credentialId -CNE $old.credentialId)
            $old.state = 'revoked'; $old.revokedAt = $replacementTime
          }
          $store.transportCredentials = @($store.transportCredentials) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ record = $inputRecord })
      }
      { $_ -in @('VerifyTransportCredentialLifetimeMigration', 'MigrateTransportCredentialLifetime') } {
        Assert-QueryOwner
        $records = @($store.transportCredentials | Where-Object {
          [string]$_.principalId -ceq $PrincipalId -and
          [string]$_.hostInstallationId -ceq $HostInstallationId -and
          [string]$_.state -ceq 'active' -and $null -eq $_.revokedAt
        })
        if ($records.Count -ne 1) { Fail 'host_transport_migration_credential_inactive_or_ambiguous' }
        $record = $records[0]
        $permanent = [int64]253402300799999
        if ([int64]$record.expiresAt -ne $permanent -and
            ([int64]$record.expiresAt - [int64]$record.issuedAt) -ne [int64]2592000000) {
          Fail 'host_transport_migration_lifetime_invalid'
        }
        if ($Command -eq 'VerifyTransportCredentialLifetimeMigration') {
          Write-Result ([PSCustomObject]@{ record = $record })
        } else {
          $previous = $inputRecord.previous
          if ([string]$previous.state -cne 'active' -or $null -ne $previous.revokedAt -or
              ([int64]$previous.expiresAt - [int64]$previous.issuedAt) -ne [int64]2592000000 -or
              -not (Test-TransportCredentialEqual $record $previous)) {
            Fail 'host_transport_migration_compare_failed'
          }
          $proof = $inputRecord.proof
          try {
            $createdAt = ([DateTimeOffset]$proof.credentialCreatedAt).ToUnixTimeMilliseconds()
            $expiresAt = ([DateTimeOffset]$proof.credentialExpiresAt).ToUnixTimeMilliseconds()
          } catch { Fail 'host_transport_migration_proof_invalid' }
          if ([string]$proof.credentialId -cne [string]$record.credentialId -or
              [string]$proof.principalId -cne $PrincipalId -or [string]$proof.hostId -cne $HostInstallationId -or
              $createdAt -ne [int64]$record.issuedAt -or $expiresAt -ne $permanent) {
            Fail 'host_transport_migration_proof_invalid'
          }
          $record.expiresAt = $permanent
          Write-Store $path $store $root $sid
          Write-Result ([PSCustomObject]@{ credentialId = $record.credentialId; expiresAt = $permanent; status = 'migrated' })
        }
      }
      'LoadTransportCredential' {
        Assert-QueryOwner
        if ($CredentialId -notmatch $IdentifierPattern) { Fail 'host_transport_credential_id_invalid' }
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $records = @($store.transportCredentials | Where-Object credentialId -CEQ $CredentialId)
        if ($records.Count -ne 1 -or [string]$records[0].state -ne 'active') {
          Fail 'host_transport_credential_inactive'
        }
        if (
          [string]$records[0].principalId -cne $PrincipalId -or
          [string]$records[0].hostInstallationId -cne $HostInstallationId
        ) { Fail 'host_transport_credential_owner_mismatch' }
        if ([int64]$records[0].expiresAt -le $Timestamp) { Fail 'host_transport_credential_expired' }
        Write-Result ([PSCustomObject]@{ record = $records[0] })
      }
      'RevokeTransportCredential' {
        Assert-QueryOwner
        if ($CredentialId -notmatch $IdentifierPattern) { Fail 'host_transport_credential_id_invalid' }
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $records = @($store.transportCredentials | Where-Object credentialId -CEQ $CredentialId)
        if ($records.Count -eq 0) {
          $archived = Read-AuthorizationHistory $store $root 'credential' $CredentialId
          if ($null -ne $archived) { $records = @($archived) }
        }
        if ($records.Count -ne 1) { Fail 'host_transport_credential_missing' }
        if (
          [string]$records[0].principalId -cne $PrincipalId -or
          [string]$records[0].hostInstallationId -cne $HostInstallationId
        ) { Fail 'host_transport_credential_owner_mismatch' }
        if ($Timestamp -lt [int64]$records[0].issuedAt) {
          Fail 'host_transport_credential_revoke_timestamp_invalid'
        }
        $sessions = @($store.transportSessions | Where-Object credentialId -CEQ $CredentialId)
        if ([string]$records[0].state -eq 'active') {
          $records[0].state = 'revoked'
          $records[0].revokedAt = $Timestamp
          $store.retiredTransportSessionIds = @(
            @($store.retiredTransportSessionIds) + @($sessions | ForEach-Object sessionId) |
              Sort-Object -Unique
          )
          $store.transportSessions = @($store.transportSessions | Where-Object credentialId -CNE $CredentialId)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{
          credentialId = $CredentialId
          state = 'revoked'
          revokedAt = $records[0].revokedAt
          cascadedSessionCount = $sessions.Count
        })
      }
      'SaveTransportSession' {
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $credential = @($store.transportCredentials | Where-Object credentialId -CEQ $inputRecord.credentialId)
        if ($credential.Count -ne 1 -or [string]$credential[0].state -ne 'active') {
          Fail 'host_transport_credential_inactive'
        }
        if (
          [string]$credential[0].principalId -cne [string]$inputRecord.principalId -or
          [string]$credential[0].hostInstallationId -cne [string]$inputRecord.hostInstallationId -or
          [int64]$credential[0].expiresAt -le $Timestamp -or
          [int64]$inputRecord.expiresAt -gt [int64]$credential[0].expiresAt
        ) { Fail 'host_transport_session_credential_mismatch' }
        if (Test-RetiredTransportSession $store $root ([string]$inputRecord.sessionId)) {
          Fail 'host_transport_session_retired'
        }
        $existing = @($store.transportSessions | Where-Object sessionId -CEQ $inputRecord.sessionId)
        if ($existing.Count -gt 1) { Fail 'host_transport_session_duplicate' }
        if ($existing.Count -eq 1) {
          if (-not (Test-TransportSessionEqual $existing[0] $inputRecord)) {
            Fail 'host_transport_session_immutable_conflict'
          }
        } else {
          $sameOwner = @($store.transportSessions | Where-Object {
            [string]$_.principalId -ceq [string]$inputRecord.principalId -and
            [string]$_.hostInstallationId -ceq [string]$inputRecord.hostInstallationId
          })
          if ($sameOwner.Count -gt 0) { Fail 'host_transport_session_ambiguous' }
          $store.transportSessions = @($store.transportSessions) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ record = $inputRecord })
      }
      'ReplaceTransportSession' {
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $credential = @($store.transportCredentials | Where-Object credentialId -CEQ $inputRecord.credentialId)
        if ($credential.Count -ne 1 -or [string]$credential[0].state -ne 'active') {
          Fail 'host_transport_credential_inactive'
        }
        if (
          [string]$credential[0].principalId -cne [string]$inputRecord.principalId -or
          [string]$credential[0].hostInstallationId -cne [string]$inputRecord.hostInstallationId -or
          [int64]$credential[0].expiresAt -le $Timestamp -or
          [int64]$inputRecord.expiresAt -gt [int64]$credential[0].expiresAt
        ) { Fail 'host_transport_session_credential_mismatch' }
        if (Test-RetiredTransportSession $store $root ([string]$inputRecord.sessionId)) {
          Fail 'host_transport_session_retired'
        }
        $sameId = @($store.transportSessions | Where-Object sessionId -CEQ $inputRecord.sessionId)
        if ($sameId.Count -gt 0 -and -not (Test-TransportSessionEqual $sameId[0] $inputRecord)) {
          Fail 'host_transport_session_immutable_conflict'
        }
        if ($sameId.Count -eq 0) {
          $old = @($store.transportSessions | Where-Object {
            [string]$_.principalId -ceq [string]$inputRecord.principalId -and
            [string]$_.hostInstallationId -ceq [string]$inputRecord.hostInstallationId
          })
          $store.retiredTransportSessionIds = @(
            @($store.retiredTransportSessionIds) + @($old | ForEach-Object sessionId) |
              Sort-Object -Unique
          )
          $store.transportSessions = @($store.transportSessions | Where-Object {
            -not (
              [string]$_.principalId -ceq [string]$inputRecord.principalId -and
              [string]$_.hostInstallationId -ceq [string]$inputRecord.hostInstallationId
            )
          }) + @($inputRecord)
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ record = $inputRecord })
      }
      'LoadTransportSession' {
        Assert-QueryOwner
        if ($SessionId -notmatch $TransportSessionIdPattern) { Fail 'host_transport_session_id_invalid' }
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $records = @($store.transportSessions | Where-Object sessionId -CEQ $SessionId)
        if ($records.Count -ne 1) { Fail 'host_transport_session_invalid' }
        $record = $records[0]
        if (
          [string]$record.principalId -cne $PrincipalId -or
          [string]$record.hostInstallationId -cne $HostInstallationId
        ) { Fail 'host_transport_session_owner_mismatch' }
        $credential = @($store.transportCredentials | Where-Object credentialId -CEQ $record.credentialId)
        if (
          $credential.Count -ne 1 -or [string]$credential[0].state -ne 'active' -or
          [int64]$credential[0].expiresAt -le $Timestamp
        ) { Fail 'host_transport_credential_inactive' }
        if ([int64]$record.expiresAt -le $Timestamp) { Fail 'host_transport_session_expired' }
        Write-Result ([PSCustomObject]@{ record = $record })
      }
      'RemoveTransportSession' {
        Assert-QueryOwner
        if ($SessionId -notmatch $TransportSessionIdPattern) { Fail 'host_transport_session_id_invalid' }
        $records = @($store.transportSessions | Where-Object sessionId -CEQ $SessionId)
        if ($records.Count -gt 0 -and (
          [string]$records[0].principalId -cne $PrincipalId -or
          [string]$records[0].hostInstallationId -cne $HostInstallationId
        )) { Fail 'host_transport_session_owner_mismatch' }
        $removed = $records.Count -eq 1
        if ($removed) {
          $store.transportSessions = @($store.transportSessions | Where-Object sessionId -CNE $SessionId)
          $store.retiredTransportSessionIds = @(
            @($store.retiredTransportSessionIds) + @($SessionId) | Sort-Object -Unique
          )
          Write-Store $path $store $root $sid
        }
        Write-Result ([PSCustomObject]@{ sessionId = $SessionId; removed = $removed })
      }
      'ResolveTransport' {
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $credential = Get-ActiveTransportCredential $store $Timestamp
        $sessions = @($store.transportSessions | Where-Object {
          [string]$_.credentialId -ceq [string]$credential.credentialId -and
          [string]$_.principalId -ceq $PrincipalId -and
          [string]$_.hostInstallationId -ceq $HostInstallationId
        })
        if ($sessions.Count -gt 1) { Fail 'host_transport_session_ambiguous' }
        $session = $null
        if ($sessions.Count -eq 1) {
          if ([int64]$sessions[0].expiresAt -le $Timestamp) {
            $store.transportSessions = @($store.transportSessions | Where-Object sessionId -CNE $sessions[0].sessionId)
            $store.retiredTransportSessionIds = @(
              @($store.retiredTransportSessionIds) + @($sessions[0].sessionId) | Sort-Object -Unique
            )
            Write-Store $path $store $root $sid
          } else {
            $session = $sessions[0]
          }
        }
        Write-Result ([PSCustomObject]@{ credential = $credential; session = $session })
      }
      'VerifyTransport' {
        if ($Timestamp -lt 0) { Fail 'host_timestamp_invalid' }
        $credential = Get-ActiveTransportCredential $store $Timestamp
        $sessions = @($store.transportSessions | Where-Object {
          [string]$_.credentialId -ceq [string]$credential.credentialId -and
          [string]$_.principalId -ceq $PrincipalId -and
          [string]$_.hostInstallationId -ceq $HostInstallationId
        })
        if ($sessions.Count -gt 1) { Fail 'host_transport_session_ambiguous' }
        $session = $null
        if ($sessions.Count -eq 1) {
          if ([int64]$sessions[0].expiresAt -gt $Timestamp) {
            $session = [PSCustomObject]@{
              sessionId = [string]$sessions[0].sessionId
              credentialId = [string]$sessions[0].credentialId
              principalId = [string]$sessions[0].principalId
              hostInstallationId = [string]$sessions[0].hostInstallationId
              expiresAt = [int64]$sessions[0].expiresAt
            }
          }
        }
        Write-Result ([PSCustomObject]@{
          credential = [PSCustomObject]@{
            credentialId = [string]$credential.credentialId
            principalId = [string]$credential.principalId
            hostInstallationId = [string]$credential.hostInstallationId
            expiresAt = [int64]$credential.expiresAt
          }
          session = $session
        })
      }
    }
    $inputRecord = $null
    $store = $null
  } finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
  }
} catch {
  $candidate = [string]$_.Exception.Message
  if ($candidate -match '^[a-z][a-z0-9_]{2,127}$') { Fail $candidate }
  if ($_.Exception -is [System.UnauthorizedAccessException]) { Fail 'host_protected_store_access_failed' }
  if ($_.Exception -is [System.IO.IOException]) { Fail 'host_protected_store_io_failed' }
  if ($_.Exception -is [System.Management.Automation.RuntimeException]) { Fail 'host_protected_store_runtime_failed' }
  Fail 'host_protected_store_operation_failed'
}
