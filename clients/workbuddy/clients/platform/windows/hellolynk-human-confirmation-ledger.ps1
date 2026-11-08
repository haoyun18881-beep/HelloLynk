param(
  [Parameter(Mandatory = $true)][ValidateSet('Admit','Record','Lookup')][string]$Command,
  [Parameter(Mandatory = $true)][string]$StoreRoot,
  [Parameter(Mandatory = $true)][string]$ResultPipeName
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$LedgerContract = 'hellolynk-native-human-confirmation-ledger-v1'
$StoreContract = 'hellolynk-human-confirmation-ledger-store-v1'
$CredentialName = 'hellolynk-human-confirmation-ledger-v1'
$MaxRecords = 4096
$RetentionMs = 86400000

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class HelloLynkLedgerNativePath {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern SafeFileHandle CreateFile(
    string name, uint access, uint share, IntPtr security, uint creation,
    uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern uint GetFinalPathNameByHandle(
    SafeFileHandle handle, StringBuilder path, uint length, uint flags);
}
'@

function Fail([string]$Code) { [Console]::Error.WriteLine($Code); exit 1 }
function Exact($Value, [string[]]$Fields, [string]$Code) {
  if ($null -eq $Value -or $Value -is [Array]) { Fail $Code }
  $actual = @($Value.PSObject.Properties.Name | Sort-Object); $wanted = @($Fields | Sort-Object)
  if ($actual.Count -ne $wanted.Count) { Fail $Code }
  for ($i=0; $i -lt $wanted.Count; $i++) { if ($actual[$i] -cne $wanted[$i]) { Fail $Code } }
}
function Valid-Action([string]$Value) { return $Value -match '^human_[A-Za-z0-9_-]{16,96}$' }
function Valid-Digest([string]$Value) { return $Value -match '^[a-f0-9]{64}$' }
function Valid-Time($Value) { try { $n=[int64]$Value; return $n -ge 0 } catch { return $false } }
function Assert-Admission($v) {
  Exact $v @('contract','actionId','partitionDigest','createdAtMs','expiresAtMs','rateWindowMs','rateLimit','restartTombstoneState','restartTombstoneCode') 'human_confirmation_ledger_input_invalid'
  if ([string]$v.contract -cne $LedgerContract -or -not (Valid-Action $v.actionId) -or -not (Valid-Digest $v.partitionDigest) -or
    -not (Valid-Time $v.createdAtMs) -or -not (Valid-Time $v.expiresAtMs) -or [int64]$v.expiresAtMs -le [int64]$v.createdAtMs -or
    [int64]$v.rateWindowMs -ne 60000 -or [int64]$v.rateLimit -ne 3 -or [string]$v.restartTombstoneState -cne 'invalidated' -or
    [string]$v.restartTombstoneCode -cne 'human_confirmation_restart_invalidated') { Fail 'human_confirmation_ledger_input_invalid' }
}
function Assert-Record($v) {
  Exact $v @('contract','actionId','partitionDigest','state','code','createdAtMs','expiresAtMs','recordedAtMs') 'human_confirmation_ledger_input_invalid'
  if ([string]$v.contract -cne $LedgerContract -or -not (Valid-Action $v.actionId) -or -not (Valid-Digest $v.partitionDigest) -or
    @('approved','cancelled','consuming','expired','failed','invalidated') -cnotcontains [string]$v.state -or
    ($null -ne $v.code -and [string]$v.code -notmatch '^human_confirmation_[a-z0-9_]{1,100}$') -or
    ([string]$v.state -ceq 'consuming' -and $null -ne $v.code) -or -not (Valid-Time $v.createdAtMs) -or
    -not (Valid-Time $v.expiresAtMs) -or -not (Valid-Time $v.recordedAtMs) -or [int64]$v.expiresAtMs -le [int64]$v.createdAtMs -or
    [int64]$v.recordedAtMs -lt [int64]$v.createdAtMs) { Fail 'human_confirmation_ledger_input_invalid' }
}
function Assert-Lookup($v) {
  Exact $v @('contract','actionId','partitionDigest') 'human_confirmation_ledger_input_invalid'
  if ([string]$v.contract -cne $LedgerContract -or -not (Valid-Action $v.actionId) -or -not (Valid-Digest $v.partitionDigest)) { Fail 'human_confirmation_ledger_input_invalid' }
}
function Assert-Entry($v) {
  Exact $v @('actionId','partitionDigest','createdAtMs','expiresAtMs','admittedAtMs','pending','state','code','recordedAtMs') 'human_confirmation_ledger_corrupt'
  if (-not (Valid-Action $v.actionId) -or -not (Valid-Digest $v.partitionDigest) -or -not (Valid-Time $v.createdAtMs) -or
    -not (Valid-Time $v.expiresAtMs) -or -not (Valid-Time $v.admittedAtMs) -or [int64]$v.expiresAtMs -le [int64]$v.createdAtMs -or $v.pending -isnot [bool] -or
    @('approved','cancelled','consuming','expired','failed','invalidated') -cnotcontains [string]$v.state -or
    ($null -ne $v.code -and [string]$v.code -notmatch '^human_confirmation_[a-z0-9_]{1,100}$') -or -not (Valid-Time $v.recordedAtMs)) { Fail 'human_confirmation_ledger_corrupt' }
}
function Read-Store([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return [PSCustomObject]@{ contract=$StoreContract; records=@() } }
  $item=Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 1048576) { Fail 'human_confirmation_ledger_path_invalid' }
  try { $cred=Import-Clixml -LiteralPath $Path; $plain=$cred.GetNetworkCredential().Password; $s=$plain|ConvertFrom-Json } catch { Fail 'human_confirmation_ledger_corrupt' }
  Exact $s @('contract','records') 'human_confirmation_ledger_corrupt'
  if ([string]$s.contract -cne $StoreContract -or $s.records -isnot [Array] -or $s.records.Count -gt $MaxRecords) { Fail 'human_confirmation_ledger_corrupt' }
  $seen=@{}; foreach($r in $s.records) { Assert-Entry $r; if($seen.ContainsKey([string]$r.actionId)){Fail 'human_confirmation_ledger_corrupt'}; $seen[[string]$r.actionId]=$true }
  $plain=$null; return $s
}
function Write-Store([string]$Path,$Store,[string]$Root,[string]$Sid) {
  $plain=$Store|ConvertTo-Json -Depth 6 -Compress
  if([Text.Encoding]::UTF8.GetByteCount($plain)-gt 1048576){Fail 'human_confirmation_ledger_too_large'}
  $secure=ConvertTo-SecureString -String $plain -AsPlainText -Force; $cred=[Management.Automation.PSCredential]::new($CredentialName,$secure)
  $temp=Join-Path $Root ('.ledger.{0}.tmp' -f [Guid]::NewGuid().ToString('N'))
  try {
    $cred|Export-Clixml -LiteralPath $temp -Force
    & icacls.exe $temp '/inheritance:r' '/grant:r' "*$Sid`:F" | Out-Null; if($LASTEXITCODE-ne 0){Fail 'human_confirmation_ledger_acl_failed'}
    $f=[IO.File]::Open($temp,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read); try{$f.Flush($true)}finally{$f.Dispose()}
    for($a=0;;$a++){try{Move-Item -LiteralPath $temp -Destination $Path -Force;break}catch [IO.IOException]{if($a-ge 20){throw};Start-Sleep -Milliseconds (5*($a+1))}catch [UnauthorizedAccessException]{if($a-ge 20){throw};Start-Sleep -Milliseconds (5*($a+1))}}
  } finally { if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}; $plain=$null;$secure=$null;$cred=$null }
}
function Write-Result($v) {
  if($ResultPipeName -notmatch '^HelloLynkHumanLedger-[A-Za-z0-9_-]{16,96}$'){Fail 'human_confirmation_ledger_pipe_invalid'}
  $json=$v|ConvertTo-Json -Depth 6 -Compress
  $opts=[IO.Pipes.PipeOptions]::Asynchronous -bor [IO.Pipes.PipeOptions]::CurrentUserOnly
  $pipe=[IO.Pipes.NamedPipeServerStream]::new($ResultPipeName,[IO.Pipes.PipeDirection]::Out,1,[IO.Pipes.PipeTransmissionMode]::Byte,$opts)
  try{$pipe.WaitForConnection();$w=[IO.StreamWriter]::new($pipe,[Text.UTF8Encoding]::new($false),1024,$true);try{$w.Write($json);$w.Flush()}finally{$w.Dispose()}}finally{$pipe.Dispose();$json=$null}
}
function Assert-NoReparse([string]$Path) {
  $cur=[IO.Path]::GetFullPath($Path)
  while($cur){if(Test-Path -LiteralPath $cur){$it=Get-Item -LiteralPath $cur -Force;if(($it.Attributes-band [IO.FileAttributes]::ReparsePoint)-ne 0){Fail 'human_confirmation_ledger_path_invalid'}};$parent=[IO.Directory]::GetParent($cur);if($null-eq $parent){break};$cur=$parent.FullName}
}
function Get-CanonicalLocalRoot([string]$Path) {
  $handle=[HelloLynkLedgerNativePath]::CreateFile($Path,0,7,[IntPtr]::Zero,3,0x02000000,[IntPtr]::Zero)
  if($handle.IsInvalid){$handle.Dispose();Fail 'human_confirmation_ledger_root_invalid'}
  try {
    $buffer=[Text.StringBuilder]::new(32768)
    $length=[HelloLynkLedgerNativePath]::GetFinalPathNameByHandle($handle,$buffer,$buffer.Capacity,0)
    if($length-eq 0 -or $length-ge $buffer.Capacity){Fail 'human_confirmation_ledger_root_invalid'}
    $final=$buffer.ToString()
  } finally {$handle.Dispose()}
  if($final.StartsWith('\\?\UNC\',[StringComparison]::OrdinalIgnoreCase)){Fail 'human_confirmation_ledger_root_invalid'}
  if($final.StartsWith('\\?\')){$final=$final.Substring(4)}
  $final=[IO.Path]::GetFullPath($final)
  if($final -notmatch '^[A-Za-z]:\\' -or $final.Length-lt 4){Fail 'human_confirmation_ledger_root_invalid'}
  return $final.TrimEnd([IO.Path]::DirectorySeparatorChar)
}
try {
  if($StoreRoot -notmatch '^[A-Za-z]:[\\/]' -or $StoreRoot.StartsWith('\\') -or $StoreRoot.Contains([char]0)){Fail 'human_confirmation_ledger_root_invalid'}
  $root=[IO.Path]::GetFullPath($StoreRoot);if($root -notmatch '^[A-Za-z]:\\' -or $root.Length-lt 4){Fail 'human_confirmation_ledger_root_invalid'}
  try{$drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($root))}catch{Fail 'human_confirmation_ledger_root_invalid'}
  if($drive.DriveType-ne [IO.DriveType]::Fixed){Fail 'human_confirmation_ledger_root_invalid'}
  Assert-NoReparse $root; New-Item -ItemType Directory -Path $root -Force|Out-Null; Assert-NoReparse $root
  $root=Get-CanonicalLocalRoot $root; Assert-NoReparse $root
  $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  & icacls.exe $root '/inheritance:r' '/grant:r' "*$Sid`:(OI)(CI)F" | Out-Null; if($LASTEXITCODE-ne 0){Fail 'human_confirmation_ledger_acl_failed'}
  $path=Join-Path $root 'human-confirmation-ledger-v1.dpapi.clixml'; Assert-NoReparse $path
  $mutexScope=('{0}`0{1}' -f $sid,$root.TrimEnd([IO.Path]::DirectorySeparatorChar).ToUpperInvariant())
  $scopeHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($mutexScope))).Substring(0,32)
  $mutex=[Threading.Mutex]::new($false,"Local\HelloLynkHumanConfirmationLedger-$scopeHash");$held=$false
  try { try{$held=$mutex.WaitOne(30000)}catch [Threading.AbandonedMutexException]{$held=$true};if(-not $held){Fail 'human_confirmation_ledger_lock_timeout'}
    Assert-NoReparse $root; Assert-NoReparse $path
    if(Test-Path -LiteralPath $path -PathType Leaf){& icacls.exe $path '/inheritance:r' '/grant:r' "*$Sid`:F" | Out-Null;if($LASTEXITCODE-ne 0){Fail 'human_confirmation_ledger_acl_failed'}}
    $store=Read-Store $path
    $raw=[Console]::In.ReadToEnd();if([Text.Encoding]::UTF8.GetByteCount($raw)-gt 16384){Fail 'human_confirmation_ledger_input_too_large'};try{$request=$raw|ConvertFrom-Json}catch{Fail 'human_confirmation_ledger_input_invalid'};$raw=$null
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $store.records=@($store.records|Where-Object{[int64]$_.admittedAtMs-ge ($now-$RetentionMs) -or ([bool]$_.pending -and [int64]$_.expiresAtMs-gt $now)})
    switch($Command){
      'Admit' { Assert-Admission $request; $same=@($store.records|Where-Object actionId -CEQ $request.actionId)
        if($same.Count){$r=$same[0];if([string]$r.partitionDigest-cne [string]$request.partitionDigest -or [int64]$r.createdAtMs-ne [int64]$request.createdAtMs -or [int64]$r.expiresAtMs-ne [int64]$request.expiresAtMs){Fail 'human_confirmation_ledger_action_conflict'};Write-Result ([PSCustomObject]@{accepted=$true});break}
        $pending=@($store.records|Where-Object{[string]$_.partitionDigest-ceq [string]$request.partitionDigest -and [bool]$_.pending -and [int64]$_.expiresAtMs-gt [int64]$request.createdAtMs})
        if($pending.Count){Write-Result ([PSCustomObject]@{accepted=$false;reason='partition_pending'});break}
        $recent=@($store.records|Where-Object{[string]$_.partitionDigest-ceq [string]$request.partitionDigest -and [int64]$_.admittedAtMs-gt ($now-[int64]$request.rateWindowMs)}|Sort-Object admittedAtMs)
        if($recent.Count-ge [int64]$request.rateLimit){$retry=[Math]::Max(0,[int64]$recent[0].admittedAtMs+[int64]$request.rateWindowMs-$now);Write-Result ([PSCustomObject]@{accepted=$false;reason='rate_limited';retryAfterMs=$retry});break}
        if($store.records.Count-ge $MaxRecords){Fail 'human_confirmation_ledger_capacity_exceeded'}
        $entry=[PSCustomObject]@{actionId=[string]$request.actionId;partitionDigest=[string]$request.partitionDigest;createdAtMs=[int64]$request.createdAtMs;expiresAtMs=[int64]$request.expiresAtMs;admittedAtMs=$now;pending=$true;state='invalidated';code='human_confirmation_restart_invalidated';recordedAtMs=[int64]$request.createdAtMs}
        $store.records=@($store.records)+@($entry);Write-Store $path $store $root $sid;Write-Result ([PSCustomObject]@{accepted=$true})
      }
      'Record' { Assert-Record $request;$same=@($store.records|Where-Object actionId -CEQ $request.actionId);if($same.Count-ne 1){Fail 'human_confirmation_ledger_action_missing'};$r=$same[0]
        if([string]$r.partitionDigest-cne [string]$request.partitionDigest -or [int64]$r.createdAtMs-ne [int64]$request.createdAtMs -or [int64]$r.expiresAtMs-ne [int64]$request.expiresAtMs){Fail 'human_confirmation_ledger_action_conflict'}
        $identical=([string]$r.state-ceq [string]$request.state -and (($null-eq $r.code -and $null-eq $request.code)-or [string]$r.code-ceq [string]$request.code) -and [int64]$r.recordedAtMs-eq [int64]$request.recordedAtMs)
        if(-not $identical){$allowed=((([bool]$r.pending -and [string]$r.state-ceq 'invalidated' -and @('consuming','cancelled','expired','failed','invalidated') -ccontains [string]$request.state)) -or ([string]$r.state-ceq 'consuming' -and @('approved','failed') -ccontains [string]$request.state)) -and [int64]$request.recordedAtMs-ge [int64]$r.recordedAtMs;if(-not $allowed){Fail 'human_confirmation_ledger_state_regression'};$r.state=[string]$request.state;$r.code=$request.code;$r.recordedAtMs=[int64]$request.recordedAtMs;$r.pending=$false;Write-Store $path $store $root $sid}
        Write-Result ([PSCustomObject]@{recorded=$true})
      }
      'Lookup' { Assert-Lookup $request;$same=@($store.records|Where-Object{[string]$_.actionId-ceq [string]$request.actionId -and [string]$_.partitionDigest-ceq [string]$request.partitionDigest});if(-not $same.Count){Write-Result ([PSCustomObject]@{record=$null})}else{$r=$same[0];Write-Result ([PSCustomObject]@{record=[PSCustomObject]@{actionId=$r.actionId;state=$r.state;code=$r.code;createdAtMs=$r.createdAtMs;expiresAtMs=$r.expiresAtMs}})}}
    }
  } finally {if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
} catch { $c=[string]$_.Exception.Message;if($c-match '^human_confirmation_ledger_[a-z0-9_]{1,90}$'){Fail $c};if($_.Exception-is [IO.IOException]){Fail 'human_confirmation_ledger_io_failed'};if($_.Exception-is [UnauthorizedAccessException]){Fail 'human_confirmation_ledger_access_failed'};Fail 'human_confirmation_ledger_operation_failed' }
