param(
  [Parameter(Mandatory=$true)][ValidateSet('Read','CompareExchange')][string]$Operation,
  [ValidatePattern('^(absent|[0-9]{1,5})$')][string]$Expected = 'absent',
  [ValidatePattern('^(absent|[0-9]{1,5})$')][string]$Value = 'absent'
)
$ErrorActionPreference = 'Stop'
try {
  $variable = 'WORKBUDDY_REMOTE_DEBUGGING_PORT'
  $current = [Environment]::GetEnvironmentVariable($variable, 'User')
  if ($Operation -eq 'Read') {
    [pscustomobject]@{ok=$true;value=$current} | ConvertTo-Json -Compress
    exit 0
  }
  $expectedValue = $null
  if ($Expected -ne 'absent') { $expectedValue = $Expected }
  if ($current -cne $expectedValue) {
    [pscustomobject]@{ok=$true;exchanged=$false} | ConvertTo-Json -Compress
    exit 0
  }
  $nextValue = $null
  if ($Value -ne 'absent') {
    if ([int]$Value -lt 1 -or [int]$Value -gt 65535) { throw 'invalid_port' }
    $nextValue = $Value
  }
  [Environment]::SetEnvironmentVariable($variable, $nextValue, 'User')
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HelloLynkWorkBuddyEnvironmentBroadcast {
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr wParam, string lParam, uint flags, uint timeout, out UIntPtr result);
}
'@
  $result = [UIntPtr]::Zero
  $delivered = [HelloLynkWorkBuddyEnvironmentBroadcast]::SendMessageTimeout([IntPtr]0xffff, 0x001a, [IntPtr]::Zero, 'Environment', 2, 3000, [ref]$result) -ne [IntPtr]::Zero
  [pscustomobject]@{ok=$true;exchanged=$true;broadcastDelivered=$delivered} | ConvertTo-Json -Compress
} catch {
  [Console]::Error.WriteLine('workbuddy_native_debug_startup_failed')
  exit 1
}
