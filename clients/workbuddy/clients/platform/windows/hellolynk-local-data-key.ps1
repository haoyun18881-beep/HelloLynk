param(
  [Parameter(Mandatory = $true)]
  [ValidateSet("CreateOrLoad", "Load")]
  [string]$Command,

  [Parameter(Mandatory = $true)]
  [string]$StoreRoot,

  [Parameter(Mandatory = $true)]
  [string]$ResultPipeName
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Set-StrictMode -Version Latest

$StoreContract = "hellolynk-local-data-key-store-v1"
$RecordContract = "hellolynk-local-data-key-v1"
$KeyIdPattern = '^ldk_[A-Za-z0-9_-]{22}$'
$Entropy = [Text.Encoding]::UTF8.GetBytes("HelloLynk local data key v1")

function Fail([string]$Code) {
  [Console]::Error.WriteLine($Code)
  exit 1
}

function Assert-ExactFields($Value, [string[]]$Expected, [string]$Code) {
  if ($null -eq $Value -or $Value -is [Array]) { Fail $Code }
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $wanted = @($Expected | Sort-Object)
  if ($actual.Count -ne $wanted.Count) { Fail $Code }
  for ($index = 0; $index -lt $wanted.Count; $index += 1) {
    if ([string]$actual[$index] -cne [string]$wanted[$index]) { Fail $Code }
  }
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
  return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Set-CurrentUserOnlyAcl([string]$Path, [string]$Sid, [bool]$Container) {
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRuleAll($rule) }
  $inheritance = if ($Container) {
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    [Security.AccessControl.InheritanceFlags]::None
  }
  $propagation = [Security.AccessControl.PropagationFlags]::None
  $allow = [Security.AccessControl.AccessControlType]::Allow
  $rights = [Security.AccessControl.FileSystemRights]::FullControl
  $currentIdentity = [Security.Principal.SecurityIdentifier]::new($Sid)
  $systemIdentity = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $currentIdentity, $rights, $inheritance, $propagation, $allow
  ))
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $systemIdentity, $rights, $inheritance, $propagation, $allow
  ))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-CurrentUserOnlyAcl([string]$Path, [string]$Sid, [bool]$Container, [string]$Code) {
  try { $acl = Get-Acl -LiteralPath $Path }
  catch { Fail $Code }
  if (-not $acl.AreAccessRulesProtected) { Fail $Code }
  $expectedInheritance = if ($Container) {
    [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    [Security.AccessControl.InheritanceFlags]::None
  }
  $expected = @($Sid, "S-1-5-18" | Sort-Object)
  $observed = @()
  foreach ($rule in @($acl.Access)) {
    if ($rule.IsInherited -or
      $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
      $rule.InheritanceFlags -ne $expectedInheritance -or
      $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None -or
      (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
        [Security.AccessControl.FileSystemRights]::FullControl)) {
      Fail $Code
    }
    try {
      $ruleSid = $rule.IdentityReference.Translate(
        [Security.Principal.SecurityIdentifier]
      ).Value
    } catch { Fail $Code }
    $observed += [string]$ruleSid
  }
  $observed = @($observed | Sort-Object)
  if ($observed.Count -ne $expected.Count) { Fail $Code }
  for ($index = 0; $index -lt $expected.Count; $index += 1) {
    if ([string]$observed[$index] -cne [string]$expected[$index]) { Fail $Code }
  }
}

function Assert-RegularLocalPath([string]$Path, [bool]$Container, [string]$Code) {
  $item = Get-Item -LiteralPath $Path -Force
  if ($Container -and -not $item.PSIsContainer) { Fail $Code }
  if (-not $Container -and $item.PSIsContainer) { Fail $Code }
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail $Code }
}

function New-KeyRecord {
  $key = [byte[]]::new(32)
  $identifier = [byte[]]::new(16)
  [Security.Cryptography.RandomNumberGenerator]::Fill($key)
  [Security.Cryptography.RandomNumberGenerator]::Fill($identifier)
  $record = [PSCustomObject]@{
    contract = $RecordContract
    keyId = "ldk_$(ConvertTo-Base64Url $identifier)"
    key = ConvertTo-Base64Url $key
  }
  [Array]::Clear($key, 0, $key.Length)
  [Array]::Clear($identifier, 0, $identifier.Length)
  return $record
}

function Assert-KeyRecord($Record) {
  Assert-ExactFields $Record @("contract", "key", "keyId") "local_data_key_record_invalid"
  if ([string]$Record.contract -cne $RecordContract) { Fail "local_data_key_record_invalid" }
  if ([string]$Record.keyId -notmatch $KeyIdPattern) { Fail "local_data_key_record_invalid" }
  $encoded = ([string]$Record.key).Replace('-', '+').Replace('_', '/')
  while (($encoded.Length % 4) -ne 0) { $encoded += '=' }
  try { $key = [Convert]::FromBase64String($encoded) }
  catch { Fail "local_data_key_record_invalid" }
  if ($key.Length -ne 32 -or (ConvertTo-Base64Url $key) -cne [string]$Record.key) {
    Fail "local_data_key_record_invalid"
  }
  [Array]::Clear($key, 0, $key.Length)
  $key = $null
  $encoded = $null
  return $Record
}

function Write-KeyStore([string]$Path, [string]$Root, [string]$Sid, $Record) {
  $plainBytes = $null
  $protected = $null
  $json = $null
  $temp = $null
  $plain = $Record | ConvertTo-Json -Depth 3 -Compress
  $plainBytes = [Text.Encoding]::UTF8.GetBytes($plain)
  try {
    $protected = [Security.Cryptography.ProtectedData]::Protect(
      $plainBytes,
      $Entropy,
      [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $store = [PSCustomObject]@{
      contract = $StoreContract
      schemaVersion = 1
      protectedPayload = [Convert]::ToBase64String($protected)
    }
    $json = $store | ConvertTo-Json -Depth 3 -Compress
    $temp = Join-Path $Root (".local-data-key.{0}.tmp" -f [Guid]::NewGuid().ToString("N"))
    try {
      [IO.File]::WriteAllText($temp, $json, [Text.UTF8Encoding]::new($false))
      Set-CurrentUserOnlyAcl $temp $Sid $false
      $stream = [IO.File]::Open($temp, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read)
      try { $stream.Flush($true) } finally { $stream.Dispose() }
      Move-Item -LiteralPath $temp -Destination $Path -Force
      Set-CurrentUserOnlyAcl $Path $Sid $false
    } finally {
      if ($temp -and (Test-Path -LiteralPath $temp)) { Remove-Item -LiteralPath $temp -Force }
    }
  } finally {
    if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
    $plain = $null
    $plainBytes = $null
    $protected = $null
    $json = $null
  }
}

function Read-KeyStore([string]$Path, [string]$Sid) {
  $protected = $null
  $plainBytes = $null
  $plain = $null
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "local_data_key_missing" }
  Assert-RegularLocalPath $Path $false "local_data_key_store_invalid"
  try { $store = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8) | ConvertFrom-Json }
  catch { Fail "local_data_key_store_invalid" }
  Assert-ExactFields $store @("contract", "protectedPayload", "schemaVersion") "local_data_key_store_invalid"
  if ([int]$store.schemaVersion -ne 1) {
    Fail "local_data_key_store_invalid"
  }
  if ([string]$store.contract -cne $StoreContract) { Fail "local_data_key_store_invalid" }
  Assert-CurrentUserOnlyAcl $Path $Sid $false "local_data_key_access_failed"
  try {
    $protected = [Convert]::FromBase64String([string]$store.protectedPayload)
    $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect(
      $protected,
      $Entropy,
      [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $plain = [Text.Encoding]::UTF8.GetString($plainBytes)
    return Assert-KeyRecord ($plain | ConvertFrom-Json)
  } catch {
    $candidate = [string]$_.Exception.Message
    if ($candidate -match '^local_data_[a-z0-9_]{2,127}$') { Fail $candidate }
    Fail "local_data_key_unprotect_failed"
  } finally {
    if ($protected) { [Array]::Clear($protected, 0, $protected.Length) }
    if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    $protected = $null
    $plainBytes = $null
    $plain = $null
  }
}

function Write-Result($Record) {
  if ($ResultPipeName -notmatch '^HelloLynkLocalDataKey-[A-Za-z0-9_-]{16,96}$') {
    Fail "local_data_key_result_pipe_invalid"
  }
  $json = $Record | ConvertTo-Json -Depth 3 -Compress
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
  if (-not $StoreRoot -or $StoreRoot.Contains([char]0) -or $StoreRoot.StartsWith('\\')) {
    Fail "local_data_key_root_invalid"
  }
  try { $root = [IO.Path]::GetFullPath($StoreRoot) } catch { Fail "local_data_key_root_invalid" }
  if ($root -notmatch '^[A-Za-z]:\\' -or $root.Length -lt 4) { Fail "local_data_key_root_invalid" }
  try { $drive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($root)) }
  catch { Fail "local_data_key_root_invalid" }
  if ($drive.DriveType -ne [IO.DriveType]::Fixed) { Fail "local_data_key_root_invalid" }

  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($Command -ceq "CreateOrLoad") {
    $null = New-Item -ItemType Directory -Path $root -Force
    Assert-RegularLocalPath $root $true "local_data_key_root_invalid"
    Set-CurrentUserOnlyAcl $root $sid $true
  } else {
    if (-not (Test-Path -LiteralPath $root -PathType Container)) { Fail "local_data_key_missing" }
    Assert-RegularLocalPath $root $true "local_data_key_root_invalid"
  }
  $path = Join-Path $root "local-data-key-v1.dpapi.json"
  $rootPrefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
  if (-not [IO.Path]::GetFullPath($path).StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    Fail "local_data_key_store_invalid"
  }

  $mutexInput = "${sid}`0$($root.ToUpperInvariant())"
  $mutexHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
    [Text.Encoding]::UTF8.GetBytes($mutexInput)
  )).Substring(0, 32)
  $mutex = [Threading.Mutex]::new($false, "Local\HelloLynkLocalDataKey-$mutexHash")
  $acquired = $false
  try {
    try { $acquired = $mutex.WaitOne(10000) }
    catch [Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { Fail "local_data_key_lock_timeout" }
    if (Test-Path -LiteralPath $path) {
      $record = Read-KeyStore $path $sid
      if ($Command -ceq "Load") {
        Assert-CurrentUserOnlyAcl $root $sid $true "local_data_key_access_failed"
      }
    } elseif ($Command -ceq "CreateOrLoad") {
      $record = New-KeyRecord
      $null = Assert-KeyRecord $record
      Write-KeyStore $path $root $sid $record
    } else {
      Fail "local_data_key_missing"
    }
    Write-Result $record
  } finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
    $record = $null
  }
} catch {
  $candidate = [string]$_.Exception.Message
  if ($candidate -match '^[a-z][a-z0-9_]{2,127}$') { Fail $candidate }
  if ($_.Exception -is [UnauthorizedAccessException]) { Fail "local_data_key_access_failed" }
  if ($_.Exception -is [IO.IOException]) { Fail "local_data_key_io_failed" }
  Fail "local_data_key_helper_failed"
} finally {
  if ($Entropy) { [Array]::Clear($Entropy, 0, $Entropy.Length) }
  $Entropy = $null
}
