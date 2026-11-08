$ErrorActionPreference = "Stop"

# Host-owned native decision surface. The request arrives only on anonymous
# child stdin. This script accepts no command-line decision or secret inputs, does
# not read environment variables, and does not write files or logs.

function ConvertFrom-Base64Url {
  param([Parameter(Mandatory = $true)][string]$Value)
  if ($Value -notmatch '^[A-Za-z0-9_-]{43}$') { throw "invalid input" }
  $padded = $Value.Replace('-', '+').Replace('_', '/')
  switch ($padded.Length % 4) {
    2 { $padded += '==' }
    3 { $padded += '=' }
  }
  return [Convert]::FromBase64String($padded)
}

function Get-DecisionMessage {
  param(
    [Parameter(Mandatory = $true)]$InputRecord,
    [Parameter(Mandatory = $true)][string]$Decision
  )
  $fields = @(
    [string]$InputRecord.contract,
    [string]$InputRecord.actionId,
    $Decision,
    [string]$InputRecord.principalId,
    [string]$InputRecord.delegateId,
    [string]$InputRecord.hostInstallationId,
    [string]$InputRecord.adapterId,
    [string]$InputRecord.adapterInstanceId,
    [string]$InputRecord.hostGeneration,
    [string]$InputRecord.recipientHelloLynkId
  )
  if ($InputRecord.PSObject.Properties.Name -contains 'recipientDelegateId') {
    $fields += @([string]$InputRecord.recipientDelegateId, [string]$InputRecord.recipientInstanceDisplayName)
  }
  $fields += @(
    [string]$InputRecord.clientMessageId,
    [string]$InputRecord.textDigest,
    [string]$InputRecord.createdAtMs,
    [string]$InputRecord.expiresAtMs,
    [string]$InputRecord.challenge
  )
  return $fields -join "`n"
}

try {
  # Node sends UTF-8 bytes; the user's console code page must not change them.
  [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
  $inputReader = [IO.StreamReader]::new([Console]::OpenStandardInput(), [Text.Encoding]::UTF8)
  $raw = $inputReader.ReadToEnd()
  if ([string]::IsNullOrWhiteSpace($raw) -or [Text.Encoding]::UTF8.GetByteCount($raw) -gt (20480 * 6 + 8192)) {
    throw "invalid input"
  }
  $inputRecord = $raw | ConvertFrom-Json
  $expected = @(
    'actionId', 'adapterId', 'adapterInstanceId', 'challenge', 'clientMessageId',
    'contract', 'createdAtMs', 'delegateId', 'displayText', 'expiresAtMs',
    'hmacKey', 'hostGeneration', 'hostInstallationId', 'principalId',
    'recipientHelloLynkId', 'textDigest'
  )
  $hasRecipientInstance = ($inputRecord.PSObject.Properties.Name -contains 'recipientDelegateId') -or
    ($inputRecord.PSObject.Properties.Name -contains 'recipientInstanceDisplayName')
  if ($hasRecipientInstance) { $expected += @('recipientDelegateId', 'recipientInstanceDisplayName') }
  $expected = $expected | Sort-Object
  $actual = @($inputRecord.PSObject.Properties.Name | Sort-Object)
  if ($actual.Count -ne $expected.Count -or (Compare-Object $actual $expected)) {
    throw "invalid input"
  }
  if ($inputRecord.contract -ne 'hellolynk-native-human-confirmation-v1') { throw "invalid input" }
  if ($hasRecipientInstance) {
    if ($inputRecord.recipientDelegateId -isnot [string] -or
      $inputRecord.recipientDelegateId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{2,198}$') { throw "invalid input" }
    $instanceName = $inputRecord.recipientInstanceDisplayName
    if ($instanceName -isnot [string] -or [string]::IsNullOrWhiteSpace($instanceName) -or
      $instanceName.Trim() -cne $instanceName -or [Text.Encoding]::UTF8.GetByteCount($instanceName) -gt 512 -or
      $instanceName -match '[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]') { throw "invalid input" }
  }
  if ([string]::IsNullOrEmpty([string]$inputRecord.displayText)) { throw "invalid input" }
  if ([Text.Encoding]::UTF8.GetByteCount([string]$inputRecord.displayText) -gt 20480) {
    throw "invalid input"
  }
  $hmacKey = ConvertFrom-Base64Url -Value ([string]$inputRecord.hmacKey)
  if ($hmacKey.Length -ne 32) { throw "invalid input" }

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HelloLynkNativeConfirmationWindow {
  [DllImport("user32.dll")]
  public static extern bool ShowWindow(IntPtr window, int command);
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool SetWindowPos(IntPtr window, IntPtr insertAfter, int x, int y, int width, int height, uint flags);
}
'@
  [System.Windows.Forms.Application]::EnableVisualStyles()

  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'HelloLynk 人类确认'
  $form.StartPosition = 'CenterScreen'
  $form.Size = New-Object System.Drawing.Size(620, 430)
  $form.MinimizeBox = $false
  $form.MaximizeBox = $false
  $form.ShowInTaskbar = $true
  $form.TopMost = $true
  # HELLOLYNK_VISIBLE_CONFIRMATION_START
  # Node keeps the PowerShell console hidden with STARTF_USESHOWWINDOW/SW_HIDE.
  # The first ShowDialog inherits that hidden state, so explicitly show the
  # already-created native form without exposing the console window.
  $form.Add_Shown({
    [void][HelloLynkNativeConfirmationWindow]::ShowWindow($form.Handle, 1)
    [void][HelloLynkNativeConfirmationWindow]::SetWindowPos(
      $form.Handle, [IntPtr](-1), 0, 0, 0, 0, (0x0001 -bor 0x0002 -bor 0x0040)
    )
  })
  # HELLOLYNK_VISIBLE_CONFIRMATION_END

  $heading = New-Object System.Windows.Forms.Label
  $heading.Text = '是否允许 HelloLynk 发送以下文本？'
  $heading.AutoSize = $true
  $heading.Location = New-Object System.Drawing.Point(20, 18)
  $heading.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
  $form.Controls.Add($heading)

  $recipient = New-Object System.Windows.Forms.Label
  $recipient.Text = ('收件人：' + [string]$inputRecord.recipientHelloLynkId)
  $recipient.AutoSize = $true
  $recipient.Location = New-Object System.Drawing.Point(20, 54)
  $form.Controls.Add($recipient)

  $textTop = 82
  if ($hasRecipientInstance) {
    $recipientAI = New-Object System.Windows.Forms.Label
    $recipientAI.Text = ('目标 AI：' + [string]$inputRecord.recipientInstanceDisplayName)
    $recipientAI.UseMnemonic = $false
    $recipientAI.AutoSize = $true
    $recipientAI.MaximumSize = New-Object System.Drawing.Size(565, 0)
    $recipientAI.Location = New-Object System.Drawing.Point(20, 80)
    $form.Controls.Add($recipientAI)
    $textTop = $recipientAI.Bottom + 16
  }
  $extraHeight = $textTop - 82
  $form.Size = New-Object System.Drawing.Size(620, (430 + $extraHeight))

  $textBox = New-Object System.Windows.Forms.TextBox
  $textBox.Multiline = $true
  $textBox.ReadOnly = $true
  $textBox.ScrollBars = 'Vertical'
  $textBox.WordWrap = $true
  $textBox.Text = [string]$inputRecord.displayText
  $textBox.Location = New-Object System.Drawing.Point(20, $textTop)
  $textBox.Size = New-Object System.Drawing.Size(565, 245)
  $form.Controls.Add($textBox)

  $approve = New-Object System.Windows.Forms.Button
  $approve.Text = '批准发送'
  $approve.Location = New-Object System.Drawing.Point(385, (344 + $extraHeight))
  $approve.Size = New-Object System.Drawing.Size(95, 32)
  $approve.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.Controls.Add($approve)
  $form.AcceptButton = $approve

  $cancel = New-Object System.Windows.Forms.Button
  $cancel.Text = '取消'
  $cancel.Location = New-Object System.Drawing.Point(490, (344 + $extraHeight))
  $cancel.Size = New-Object System.Drawing.Size(95, 32)
  $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $form.Controls.Add($cancel)
  $form.CancelButton = $cancel

  # Closing the window produces Cancel; there is no third decision path.
  $result = $form.ShowDialog()
  $form.Dispose()
  $decision = if ($result -eq [System.Windows.Forms.DialogResult]::OK) { 'approve' } else { 'cancel' }
  $message = Get-DecisionMessage -InputRecord $inputRecord -Decision $decision
  $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (, $hmacKey)
  try {
    $proofBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
    $proof = ([BitConverter]::ToString($proofBytes)).Replace('-', '').ToLowerInvariant()
  }
  finally {
    $hmac.Dispose()
    [Array]::Clear($hmacKey, 0, $hmacKey.Length)
  }

  $response = [ordered]@{
    contract = [string]$inputRecord.contract
    actionId = [string]$inputRecord.actionId
    decision = $decision
    principalId = [string]$inputRecord.principalId
    delegateId = [string]$inputRecord.delegateId
    hostInstallationId = [string]$inputRecord.hostInstallationId
    adapterId = [string]$inputRecord.adapterId
    adapterInstanceId = [string]$inputRecord.adapterInstanceId
    hostGeneration = [string]$inputRecord.hostGeneration
    recipientHelloLynkId = [string]$inputRecord.recipientHelloLynkId
    clientMessageId = [string]$inputRecord.clientMessageId
    textDigest = [string]$inputRecord.textDigest
    createdAtMs = [long]$inputRecord.createdAtMs
    expiresAtMs = [long]$inputRecord.expiresAtMs
    proof = $proof
  }
  if ($hasRecipientInstance) {
    $response.recipientDelegateId = [string]$inputRecord.recipientDelegateId
    $response.recipientInstanceDisplayName = [string]$inputRecord.recipientInstanceDisplayName
  }
  [Console]::Out.WriteLine(($response | ConvertTo-Json -Compress))
  exit 0
}
catch {
  # Never reflect input or exception details onto stderr/stdout.
  exit 1
}
