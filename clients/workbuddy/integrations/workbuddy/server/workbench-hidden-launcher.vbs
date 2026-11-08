Option Explicit

If WScript.Arguments.Count <> 5 And WScript.Arguments.Count <> 7 Then WScript.Quit 2

Dim shell, fso, command, exitCode, nodePath, entryPath, rootPath, manifest, storeRoot, expectedLauncher, expectedEntry, serviceMode, debugEndpoint, endpointPattern
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

Function QuoteArgument(value)
  QuoteArgument = Chr(34) & Replace(value, Chr(34), Chr(34) & Chr(34)) & Chr(34)
End Function

Function IsSha256(value)
  Dim index, valueChar
  IsSha256 = Len(value) = 64
  For index = 1 To Len(value)
    valueChar = Mid(value, index, 1)
    If InStr("0123456789abcdef", valueChar) = 0 Then IsSha256 = False
  Next
End Function

nodePath = WScript.Arguments(0)
entryPath = WScript.Arguments(1)
rootPath = WScript.Arguments(2)
manifest = WScript.Arguments(3)
storeRoot = WScript.Arguments(4)
If StrComp(fso.GetAbsolutePathName(rootPath), rootPath, 1) <> 0 Then WScript.Quit 3
If StrComp(fso.GetAbsolutePathName(storeRoot), storeRoot, 1) <> 0 Or LCase(fso.GetFileName(storeRoot)) <> "host" Then WScript.Quit 3
expectedLauncher = fso.BuildPath(rootPath, "integrations\workbuddy\server\workbench-hidden-launcher.vbs")
expectedEntry = fso.BuildPath(rootPath, "integrations\workbuddy\server\package-bootstrap.mjs")
If StrComp(fso.GetAbsolutePathName(WScript.ScriptFullName), expectedLauncher, 1) <> 0 Then WScript.Quit 3
If StrComp(fso.GetAbsolutePathName(nodePath), nodePath, 1) <> 0 Or StrComp(fso.GetAbsolutePathName(entryPath), expectedEntry, 1) <> 0 Or Not fso.FileExists(entryPath) Or Not fso.FileExists(nodePath) Or Not IsSha256(manifest) Then WScript.Quit 3
shell.Environment("Process")("HELLOLYNK_NEUTRAL_STORE_ROOT") = storeRoot
serviceMode = "workbench-service"
If WScript.Arguments.Count = 7 Then
  serviceMode = WScript.Arguments(5)
  debugEndpoint = WScript.Arguments(6)
  Set endpointPattern = New RegExp
  endpointPattern.Pattern = "^http://127\.0\.0\.1:[0-9]{1,5}$"
  If serviceMode <> "native-task-service" Or Not endpointPattern.Test(debugEndpoint) Then WScript.Quit 3
  shell.Environment("Process")("HELLOLYNK_WORKBUDDY_DEBUG_ENDPOINT") = debugEndpoint
End If
command = QuoteArgument(nodePath) & " " & QuoteArgument(entryPath) & " " & serviceMode & " --root " & QuoteArgument(rootPath) & _
  " --expected-manifest-sha256 " & manifest
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode
