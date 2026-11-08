param(
  [Parameter(Mandatory=$true)][ValidateSet('Install','Verify','Start','Run','Uninstall')][string]$Command,
  [Parameter(Mandatory=$true)][string]$Root,
  [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$Manifest,
  [Parameter(Mandatory=$true)][string]$NodePath,
  [Parameter(Mandatory=$true)][string]$StoreRoot,
  [string]$DriverRoot = '',
  [ValidateSet('workbench-service','native-task-service')][string]$Mode = 'workbench-service',
  [string]$DebugEndpoint = ''
)
$ErrorActionPreference = 'Stop'
try {
  $nativeService = $Mode -eq 'native-task-service'
  if (-not $DriverRoot) { $DriverRoot = $Root }
  # A new, verified installer may check an older immutable release with its
  # current task driver. It may not mutate that release through this path.
  if ($DriverRoot -ne $Root -and $Command -ne 'Verify') { throw 'workbuddy_page_task_path_invalid' }
  if ($nativeService -and ($DebugEndpoint -notmatch '^http://127\.0\.0\.1:[0-9]{1,5}$' -or ([uri]$DebugEndpoint).Port -lt 1)) { throw 'workbuddy_native_debug_endpoint_invalid' }
  if (-not $nativeService -and $DebugEndpoint) { throw 'workbuddy_native_debug_endpoint_invalid' }
  if (-not [IO.Path]::IsPathRooted($Root) -or $Root -match '["\r\n]' -or
    -not [IO.Path]::IsPathRooted($NodePath) -or $NodePath -match '["\r\n]' -or
    -not [IO.Path]::IsPathRooted($StoreRoot) -or $StoreRoot -match '["\r\n]' -or
    [IO.Path]::GetFileName($StoreRoot) -ne 'host') { throw 'workbuddy_page_task_path_invalid' }
  $entry = Join-Path $Root 'integrations\workbuddy\server\package-bootstrap.mjs'
  $script = Join-Path $DriverRoot 'integrations\workbuddy\server\workbench-task.ps1'
  $launcher = Join-Path $Root 'integrations\workbuddy\server\workbench-hidden-launcher.vbs'
  $wscript = Join-Path $env:SystemRoot 'System32\wscript.exe'
  if (-not (Test-Path -LiteralPath $entry -PathType Leaf) -or -not (Test-Path -LiteralPath $launcher -PathType Leaf) -or
    -not (Test-Path -LiteralPath $wscript -PathType Leaf) -or -not (Test-Path -LiteralPath $NodePath -PathType Leaf) -or
    [IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($script)) { throw 'workbuddy_page_task_entry_invalid' }
  if ($Command -eq 'Run') {
    $arguments = '//B //NoLogo "{0}" "{1}" "{2}" "{3}" {4} "{5}"' -f $launcher,$NodePath,$entry,$Root,$Manifest,$StoreRoot
    if ($nativeService) { $arguments += ' native-task-service "{0}"' -f $DebugEndpoint }
    $worker = Start-Process -FilePath $wscript -ArgumentList $arguments -WindowStyle Hidden -PassThru -Wait
    exit $worker.ExitCode
  }
  $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $namespaceRoot = [IO.Path]::GetDirectoryName($Root)
  if ([IO.Path]::GetFileName($namespaceRoot) -ne 'releases') { $namespaceRoot = $Root }
  $namespace = $sid + '|' + [IO.Path]::GetFullPath($namespaceRoot).ToLowerInvariant()
  $hash = [Security.Cryptography.SHA256]::Create()
  try {
    $suffix = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($namespace)))).Replace('-','').Substring(0,20)
    $releaseIdentity = [IO.Path]::GetFullPath($Root).ToLowerInvariant() + '|' + $Manifest
    $releaseSuffix = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($releaseIdentity)))).Replace('-','').Substring(0,16)
  }
  finally { $hash.Dispose() }
  $taskBase = "HelloLynk WorkBuddy - $suffix"
  if ($nativeService) { $taskBase = "HelloLynk WorkBuddy Native - $suffix" }
  $taskName = "$taskBase - $releaseSuffix"
  $description = 'HelloLynk WorkBuddy page service; starts on demand and stops when browser sessions expire.'
  if ($nativeService) { $description = 'HelloLynk WorkBuddy native inbox listener; explicit loopback desktop bridge; no model polling.' }
  $executable = $wscript
  $arguments = '//B //NoLogo "{0}" "{1}" "{2}" "{3}" {4} "{5}"' -f $launcher,$NodePath,$entry,$Root,$Manifest,$StoreRoot
  if ($nativeService) { $arguments += ' native-task-service "{0}"' -f $DebugEndpoint }
  # The native listener also resumes at this user's logon with normal rights,
  # so an update's trust request survives a restart before WorkBuddy opens.
  # One instance per release. The page task stays on demand.
  $instances = 0; $installedTrigger = 'none'
  if ($nativeService) { $instances = 2; $installedTrigger = 'logon' }
  # Use the Scheduler API directly; its CIM wrapper can time out while the
  # registered task and on-demand service are both healthy.
  $scheduler = New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
  $folder = $scheduler.GetFolder('\')
  function Read-Task($registered) {
    $d = $registered.Definition
    [pscustomobject]@{ TaskName=$registered.Name; Description=$d.RegistrationInfo.Description; Principal=$d.Principal; Settings=$d.Settings
      Triggers=@($d.Triggers); Actions=@($d.Actions | ForEach-Object { [pscustomobject]@{Execute=$_.Path; Arguments=$_.Arguments; WorkingDirectory=$_.WorkingDirectory; Type=$_.Type} })
      State=$registered.State; Registered=$registered }
  }
  # 'none', 'logon' (this user's logon trigger), 'logon_disabled' or 'other'.
  function Get-TriggerState($triggers) {
    $list = @($triggers | Where-Object { $null -ne $_ })
    if ($list.Count -eq 0) { return 'none' }
    if (-not $nativeService -or $list.Count -ne 1 -or $list[0].Type -ne 9) { return 'other' }
    $user = [string]$list[0].UserId
    if ($user -notmatch '^S-1-') { $user = (New-Object Security.Principal.NTAccount($user)).Translate([Security.Principal.SecurityIdentifier]).Value }
    if ($user -ne $sid) { return 'other' }
    if ($list[0].Enabled) { return 'logon' }
    return 'logon_disabled'
  }
  $task = $null
  try { $task = Read-Task ($folder.GetTask($taskName)) }
  catch { if ($_.Exception.HResult -ne -2147024894) { throw } }
  if ($task) {
    $taskSid = [string]$task.Principal.UserId
    if ($taskSid -notmatch '^S-1-') { $taskSid = (New-Object Security.Principal.NTAccount($taskSid)).Translate([Security.Principal.SecurityIdentifier]).Value }
    if ($task.Description -ne $description -or $taskSid -ne $sid) { throw 'workbuddy_page_task_conflict' }
  }
  $namespaceTasks = @($folder.GetTasks(1) | Where-Object { $_.Name -eq $taskBase -or $_.Name.StartsWith($taskBase + ' - ') } | ForEach-Object { Read-Task $_ })
  foreach ($candidate in $namespaceTasks) {
    $candidateSid = [string]$candidate.Principal.UserId
    if ($candidateSid -notmatch '^S-1-') { $candidateSid = (New-Object Security.Principal.NTAccount($candidateSid)).Translate([Security.Principal.SecurityIdentifier]).Value }
    if ($candidate.Description -ne $description -or $candidateSid -ne $sid) { throw 'workbuddy_page_task_conflict' }
  }
  function Stop-VerifiedNativeTaskProcesses($candidate) {
    # Task Scheduler can stop wscript while leaving its shell.Run child alive.
    # Match the entire verified native command, never a generic node process.
    if (@($candidate.Actions).Count -ne 1 -or $candidate.Actions[0].Execute -ne $wscript) { throw 'workbuddy_native_service_identity_invalid' }
    $pattern = '^//B //NoLogo "([^"\r\n]+)" "([^"\r\n]+)" "([^"\r\n]+)" "([^"\r\n]+)" ([a-f0-9]{64}) "([^"\r\n]+)" native-task-service "(http://127\.0\.0\.1:[0-9]{1,5})"$'
    $match = [regex]::Match([string]$candidate.Actions[0].Arguments, $pattern)
    if (-not $match.Success) { throw 'workbuddy_native_service_identity_invalid' }
    $oldLauncher = $match.Groups[1].Value; $oldNode = $match.Groups[2].Value
    $oldEntry = $match.Groups[3].Value; $oldRoot = $match.Groups[4].Value
    $oldManifest = $match.Groups[5].Value; $oldStore = $match.Groups[6].Value
    if (-not [IO.Path]::IsPathRooted($oldRoot) -or $oldNode -ne $NodePath -or $oldStore -ne $StoreRoot -or
      $oldLauncher -ne (Join-Path $oldRoot 'integrations\workbuddy\server\workbench-hidden-launcher.vbs') -or
      $oldEntry -ne (Join-Path $oldRoot 'integrations\workbuddy\server\package-bootstrap.mjs')) { throw 'workbuddy_native_service_identity_invalid' }
    $oldNamespace = [IO.Path]::GetDirectoryName($oldRoot)
    if ([IO.Path]::GetFileName($oldNamespace) -ne 'releases') { $oldNamespace = $oldRoot }
    if ([IO.Path]::GetFullPath($oldNamespace) -ne [IO.Path]::GetFullPath($namespaceRoot)) { throw 'workbuddy_native_service_identity_invalid' }
    $identityHash = [Security.Cryptography.SHA256]::Create()
    try { $oldSuffix = ([BitConverter]::ToString($identityHash.ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($oldRoot).ToLowerInvariant() + '|' + $oldManifest)))).Replace('-','').Substring(0,16) }
    finally { $identityHash.Dispose() }
    if ($candidate.TaskName -ne "$taskBase - $oldSuffix") { throw 'workbuddy_native_service_identity_invalid' }
    $nodeTail = '"{0}" native-task-service --root "{1}" --expected-manifest-sha256 {2}' -f $oldEntry,$oldRoot,$oldManifest
    # WScript.Shell.Run can add a second space after the executable. Only
    # that argv separator varies; all paths, mode and manifest remain exact.
    $nodeCommandPattern = '^(?:"' + [regex]::Escape($oldNode) + '"|' + [regex]::Escape($oldNode) + ')[ \t]+' + [regex]::Escape($nodeTail) + '$'
    $helperCommandPattern = '^(?:"' + [regex]::Escape($wscript) + '"|' + [regex]::Escape($wscript) + ')[ \t]+' + [regex]::Escape([string]$candidate.Actions[0].Arguments) + '$'
    foreach ($observed in @(Get-CimInstance Win32_Process -Filter "Name = 'node.exe' OR Name = 'wscript.exe'")) {
      $observedCommand = ([string]$observed.CommandLine).Trim()
      if (-not (($observed.ExecutablePath -eq $oldNode -and $observedCommand -match $nodeCommandPattern) -or
        ($observed.ExecutablePath -eq $wscript -and $observedCommand -match $helperCommandPattern))) { continue }
      if ((Invoke-CimMethod -InputObject $observed -MethodName GetOwnerSid).Sid -ne $sid) { continue }
      $process = $null
      try {
        $process = Get-Process -Id $observed.ProcessId -ErrorAction SilentlyContinue
        if (-not $process) { continue }
        $openedHandle = $process.Handle
        $current = Get-CimInstance Win32_Process -Filter "ProcessId = $($observed.ProcessId)"
        if (-not $current -or $current.CreationDate -ne $observed.CreationDate -or $current.CommandLine -ne $observed.CommandLine -or $current.ExecutablePath -ne $observed.ExecutablePath) { continue }
        $process.Kill()
        if (-not $process.WaitForExit(5000)) { throw 'workbuddy_native_service_stop_timeout' }
      } finally { if ($process) { $process.Dispose() } }
    }
  }
  if ($Command -eq 'Uninstall') {
    foreach ($candidate in $namespaceTasks) {
      # An obsolete release may be uninstalled after its replacement is active.
      # Its manifest/root identity only owns this exact task, not the namespace.
      if ($candidate.TaskName -ne $taskName) { continue }
      if ($nativeService) { Stop-VerifiedNativeTaskProcesses $candidate }
      $candidate.Registered.Stop(0)
      $folder.DeleteTask($candidate.TaskName, 0)
    }
  } elseif ($Command -eq 'Install') {
    if ($task -and @($task.Actions).Count -eq 1 -and $task.Actions[0].Type -eq 0 -and $task.Actions[0].Execute -eq $executable -and $task.Actions[0].Arguments -eq $arguments -and $task.Actions[0].WorkingDirectory -eq $Root -and
      (Get-TriggerState $task.Triggers) -eq $installedTrigger -and $task.Principal.RunLevel -eq 0 -and $task.Principal.LogonType -eq 3 -and
      $task.Settings.MultipleInstances -eq $instances -and $task.Settings.ExecutionTimeLimit -eq 'PT0S' -and $task.Settings.AllowDemandStart) {
      # The exact current package is already registered; leave its page alone.
    } else {
      # Registering a new immutable release must not terminate a page that a
      # user already has open. Different releases use different control pipes;
      # Parallel lets the new release start while the old page drains. Calls
      # for the same release still reuse its existing pipe before task start.
      $definition = $scheduler.NewTask(0); $definition.RegistrationInfo.Description = $description
      $definition.Principal.UserId = $sid; $definition.Principal.LogonType = 3; $definition.Principal.RunLevel = 0
      $definition.Settings.MultipleInstances = $instances; $definition.Settings.ExecutionTimeLimit = 'PT0S'; $definition.Settings.AllowDemandStart = $true
      $definition.Settings.DisallowStartIfOnBatteries = $false; $definition.Settings.StopIfGoingOnBatteries = $false
      if ($nativeService) { $logon = $definition.Triggers.Create(9); $logon.UserId = $sid }
      $action = $definition.Actions.Create(0); $action.Path = $executable; $action.Arguments = $arguments; $action.WorkingDirectory = $Root
      $null = $folder.RegisterTaskDefinition($taskName, $definition, 6, $sid, $null, 3)
    }
    foreach ($candidate in $namespaceTasks) {
      if ($nativeService -and $candidate.TaskName -ne $taskName) {
        Stop-VerifiedNativeTaskProcesses $candidate
        $candidate.Registered.Stop(0)
      }
      if ($candidate.TaskName -ne $taskName -and ($nativeService -or $candidate.State -ne 4)) {
        $folder.DeleteTask($candidate.TaskName, 0)
      }
    }
  } else {
    if (-not $task) { throw 'workbuddy_page_task_missing' }
    # A logon trigger the user removed or disabled still leaves on-demand start.
    if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Type -ne 0 -or $task.Actions[0].Execute -ne $executable -or $task.Actions[0].Arguments -ne $arguments -or $task.Actions[0].WorkingDirectory -ne $Root -or
      (Get-TriggerState $task.Triggers) -eq 'other' -or $task.Principal.RunLevel -ne 0 -or $task.Principal.LogonType -ne 3 -or
      $task.Settings.MultipleInstances -ne $instances -or $task.Settings.ExecutionTimeLimit -ne 'PT0S' -or -not $task.Settings.AllowDemandStart) { throw 'workbuddy_page_task_configuration_invalid' }
    if ($Command -eq 'Start' -and $task.State -ne 4) {
      for ($attempt = 0; $attempt -lt 3; $attempt += 1) {
        try { $null = $task.Registered.Run($null); break }
        catch {
          if ($attempt -eq 2) { throw }
          Start-Sleep -Milliseconds (100 * ($attempt + 1))
        }
      }
    }
  }
  [pscustomobject]@{ok=$true;operation=$Command;taskName=$taskName} | ConvertTo-Json -Compress
} catch {
  $code = [string]$_.Exception.Message
  if ($code -notmatch '^workbuddy_[a-z_]+$') { $code = 'workbuddy_page_task_failed' }
  [Console]::Error.WriteLine($code)
  exit 1
}
