#requires -Version 5.1
<#
.SYNOPSIS
    Read-only Active Directory Certificate Services (AD CS) security audit.

.DESCRIPTION
    Uses native LDAP/DirectoryServices, security-descriptor parsing, read-only CA
    registry/certutil queries, and unauthenticated web-enrolment probes to identify
    Certipy/Certify-style ESC configuration issues.

    No certificate is requested. No authentication is relayed or coerced. No CA,
    template, account, registry, or service setting is changed.

    By default, enrolment and ACL findings are evaluated for the current user and
    that user's token groups. Use -AllPrincipals for a broader, noisier review of
    non-administrative principals.

    This is not a claim of complete Certipy parity. ESC8 HTTPS channel binding is
    not established by an unauthenticated probe; ESC10 requires optional DC registry
    checks; ESC12 is hardware-specific; ESC14 is an explicit-mapping review.

.PARAMETER DomainController
    Optional DC FQDN or IP used for all LDAP paths.

.PARAMETER Credential
    Optional credential for LDAP. CA registry, certutil, web, and optional remote
    DC registry queries still use the process security context.

.PARAMETER OutputDirectory
    Parent directory for a timestamped CSV output folder.

.PARAMETER AllPrincipals
    Assess all non-administrative ACL principals instead of only the current user.

.PARAMETER IncludeDisabledTemplates
    Include enrolment-based findings for templates not enabled on an enterprise CA.
    Dangerous template ACLs are always assessed.

.PARAMETER SkipCAConfiguration
    Skip remote registry and certutil CA configuration queries. ESC6/7/11/16 will
    be reported as unknown rather than safe.

.PARAMETER SkipWebEnrollment
    Skip unauthenticated HTTP(S) GET requests to /certsrv/.

.PARAMETER CheckDomainControllers
    Attempt read-only remote registry checks of KDC/Schannel settings on DCs.
    This commonly requires administrative rights and Remote Registry access.

.EXAMPLE
    .\Invoke-ADCSAudit.ps1

.EXAMPLE
    .\Invoke-ADCSAudit.ps1 -DomainController dc01.corp.local -AllPrincipals

.EXAMPLE
    $cred = Get-Credential
    .\Invoke-ADCSAudit.ps1 -Credential $cred -CheckDomainControllers

.OUTPUTS
    Timestamped folder containing Findings, Templates, CAs, IssuancePolicies,
    CertificateMappings, DomainControllers, and Coverage CSV files as applicable.
#>
[CmdletBinding()]
param(
    [string]$DomainController,
    [pscredential]$Credential,
    [string]$OutputDirectory = 'C:\Users\Public\Music\ADCS-Audit',
    [switch]$AllPrincipals,
    [switch]$IncludeDisabledTemplates,
    [switch]$SkipCAConfiguration,
    [switch]$SkipWebEnrollment,
    [switch]$CheckDomainControllers,
    [ValidateRange(2,30)][int]$WebTimeoutSeconds = 5
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:AllPrincipals = [bool]$AllPrincipals
$script:SidNameCache = @{}
$script:Findings = New-Object System.Collections.ArrayList
$script:TemplateInventory = New-Object System.Collections.ArrayList
$script:CAInventory = New-Object System.Collections.ArrayList
$script:OidInventory = New-Object System.Collections.ArrayList
$script:MappingInventory = New-Object System.Collections.ArrayList
$script:DCInventory = New-Object System.Collections.ArrayList

$EnrollmentRightGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$ClientAuthOids = @(
    '1.3.6.1.5.5.7.3.2',       # Client Authentication
    '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
    '1.3.6.1.5.2.3.4'         # PKINIT Client Authentication
)
$ServerAuthOid = '1.3.6.1.5.5.7.3.1'
$AnyPurposeOid = '2.5.29.37.0'
$EnrollmentAgentOid = '1.3.6.1.4.1.311.20.2.1'
$SecurityExtensionOid = '1.3.6.1.4.1.311.25.2'

$OidNames = @{
    '1.3.6.1.5.5.7.3.1' = 'Server Authentication'
    '1.3.6.1.5.5.7.3.2' = 'Client Authentication'
    '1.3.6.1.5.5.7.3.3' = 'Code Signing'
    '1.3.6.1.5.5.7.3.4' = 'Secure Email'
    '1.3.6.1.5.5.7.3.8' = 'Time Stamping'
    '1.3.6.1.5.5.7.3.9' = 'OCSP Signing'
    '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'
    '1.3.6.1.4.1.311.20.2.1' = 'Certificate Request Agent'
    '1.3.6.1.5.2.3.4' = 'PKINIT Client Authentication'
    '1.3.6.1.5.2.3.5' = 'KDC Authentication'
    '1.3.6.1.4.1.311.10.3.4' = 'Encrypting File System'
    '2.5.29.37.0' = 'Any Purpose'
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [string]$Check,
        [string]$Severity,
        [string]$Confidence,
        [string]$ObjectType,
        [string]$ObjectName,
        [string]$CAName = '',
        [string]$Principal = '',
        [string]$Evidence,
        [string]$Limitation = '',
        [string]$DistinguishedName = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{
        Check = $Check
        Severity = $Severity
        Confidence = $Confidence
        ObjectType = $ObjectType
        ObjectName = $ObjectName
        CAName = $CAName
        Principal = $Principal
        Evidence = $Evidence
        Limitation = $Limitation
        DistinguishedName = $DistinguishedName
    })
}

function New-DirectoryEntry {
    param([string]$Path)
    if ($null -ne $Credential) {
        return [System.DirectoryServices.DirectoryEntry]::new($Path, $Credential.UserName, $Credential.Password)
    }
    return [System.DirectoryServices.DirectoryEntry]::new($Path)
}

function Get-LdapPath {
    param([string]$BaseDn)
    if ($DomainController) { return "LDAP://$DomainController/$BaseDn" }
    return "LDAP://$BaseDn"
}

function Get-LdapEntries {
    param(
        [string]$BaseDn,
        [string]$Filter,
        [string[]]$Properties,
        [System.DirectoryServices.SearchScope]$SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    )
    $entry = $null
    $searcher = $null
    $results = $null
    try {
        $entry = New-DirectoryEntry -Path (Get-LdapPath -BaseDn $BaseDn)
        $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)
        $searcher.Filter = $Filter
        $searcher.SearchScope = $SearchScope
        $searcher.PageSize = 1000
        $searcher.SizeLimit = 0
        $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor
            [System.DirectoryServices.SecurityMasks]::Owner -bor
            [System.DirectoryServices.SecurityMasks]::Group
        if ($Properties) { $searcher.PropertiesToLoad.AddRange($Properties) | Out-Null }
        $results = $searcher.FindAll()
        foreach ($result in $results) { $result }
    }
    finally {
        if ($null -ne $results) { $results.Dispose() }
        if ($null -ne $searcher) { $searcher.Dispose() }
        if ($null -ne $entry) { $entry.Dispose() }
    }
}

function Get-PropertyValue {
    param($Result, [string]$Name)
    $values = $Result.Properties[$Name]
    if ($null -ne $values -and $values.Count -gt 0) { return $values[0] }
    return $null
}

function Get-PropertyValues {
    param($Result, [string]$Name)
    $values = $Result.Properties[$Name]
    if ($null -ne $values -and $values.Count -gt 0) {
        foreach ($value in $values) { $value }
    }
}

function Get-IntValue {
    param($Result, [string]$Name, [int64]$Default = 0)
    $value = Get-PropertyValue -Result $Result -Name $Name
    if ($null -eq $value) { return $Default }
    return [Convert]::ToInt64($value)
}

function Get-ByteValue {
    param($Result, [string]$Name)
    $value = Get-PropertyValue -Result $Result -Name $Name
    if ($null -eq $value) { return $null }
    return [byte[]]$value
}

function ConvertTo-LdapFilterValue {
    param([string]$Value)
    return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29')
}

function Convert-SidToName {
    param([string]$Sid)
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $name = $Sid
    try {
        $identifier = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        $name = $identifier.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch { $name = $Sid }
    $script:SidNameCache[$Sid] = $name
    return $name
}

function Test-AdminSid {
    param([string]$Sid)
    if ($Sid -match '^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$') { return $true }
    return $Sid -in @('S-1-5-9','S-1-5-18','S-1-5-32-544')
}

function Test-PrincipalInScope {
    param([string]$Sid)
    if ($script:AllPrincipals) { return -not (Test-AdminSid -Sid $Sid) }
    return $script:UserSids.ContainsKey($Sid)
}

function ConvertFrom-AceBinary {
    param([System.Security.AccessControl.GenericAce]$Ace)
    # Some PowerShell/.NET ACE wrappers do not expose IdentityReference even for
    # relevant ACEs. Parse the stable binary ACE layout instead of relying on it.
    $bytes = [byte[]]::new($Ace.BinaryLength)
    $Ace.GetBinaryForm($bytes, 0)
    if ($bytes.Length -lt 16) { return $null }
    $aceType = [int]$bytes[0]
    if ($aceType -notin @(0,1,5,7)) { return $null } # Allow/Deny, standard/object
    $mask = [int64][BitConverter]::ToUInt32($bytes, 4)
    $isObjectAce = $aceType -in @(5,7)
    $objectType = [guid]::Empty
    $sidOffset = 8
    if ($isObjectAce) {
        if ($bytes.Length -lt 20) { return $null }
        $objectFlags = [BitConverter]::ToInt32($bytes, 8)
        $sidOffset = 12
        if (($objectFlags -band 0x1) -ne 0) {
            if ($bytes.Length -lt ($sidOffset + 16)) { return $null }
            $objectType = [guid]::new([byte[]]$bytes[$sidOffset..($sidOffset + 15)])
            $sidOffset += 16
        }
        if (($objectFlags -band 0x2) -ne 0) { $sidOffset += 16 }
    }
    if ($bytes.Length -le ($sidOffset + 8)) { return $null }
    $sid = [System.Security.Principal.SecurityIdentifier]::new($bytes, $sidOffset).Value
    return [pscustomobject]@{
        Sid = $sid
        Mask = $mask
        Allow = ($aceType -in @(0,5))
        Deny = ($aceType -in @(1,7))
        IsObjectAce = $isObjectAce
        ObjectType = $objectType
    }
}

function Get-AclEntries {
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -lt 20) {
        return @{ OwnerSid = ''; Entries = @(); Parsed = $false }
    }
    try {
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Bytes, 0)
    }
    catch {
        Write-Warning "Could not parse security descriptor: $($_.Exception.Message)"
        return @{ OwnerSid = ''; Entries = @(); Parsed = $false }
    }
    $entries = New-Object System.Collections.ArrayList
    if ($null -ne $descriptor.DiscretionaryAcl) {
        foreach ($ace in $descriptor.DiscretionaryAcl) {
            try { $parsedAce = ConvertFrom-AceBinary -Ace $ace }
            catch {
                Write-Warning "Skipping an unreadable ACE: $($_.Exception.Message)"
                continue
            }
            if ($null -ne $parsedAce) { [void]$entries.Add($parsedAce) }
        }
    }
    return @{
        OwnerSid = $(if ($null -ne $descriptor.Owner) { $descriptor.Owner.Value } else { '' })
        Entries = @($entries)
        Parsed = $true
    }
}

function Test-GenericAll {
    param([int64]$Mask)
    return (($Mask -band 0x10000000L) -ne 0 -or ($Mask -band 0x000f01ffL) -eq 0x000f01ffL)
}

function Test-EnrollAce {
    param($Ace)
    if (Test-GenericAll -Mask $Ace.Mask) { return $true }
    if (($Ace.Mask -band 0x100L) -eq 0) { return $false }
    if (-not $Ace.IsObjectAce) { return $true }
    return ($Ace.ObjectType -eq [guid]::Empty -or $Ace.ObjectType -eq $EnrollmentRightGuid)
}

function Get-EnrollmentPrincipals {
    param($Acl)
    $scoped = @($Acl.Entries | Where-Object { Test-PrincipalInScope -Sid $_.Sid })
    if (@($scoped | Where-Object { $_.Deny -and (Test-EnrollAce -Ace $_) }).Count -gt 0) { return @() }
    $sids = @($scoped | Where-Object { $_.Allow -and (Test-EnrollAce -Ace $_) } |
        Select-Object -ExpandProperty Sid -Unique)
    return @($sids | ForEach-Object { Convert-SidToName -Sid $_ })
}

function Test-DangerousADAce {
    param($Ace)
    if (Test-GenericAll -Mask $Ace.Mask) { return $true }
    if (($Ace.Mask -band 0x40000000L) -ne 0) { return $true } # GENERIC_WRITE
    if (($Ace.Mask -band 0x00040000L) -ne 0) { return $true } # WRITE_DAC
    if (($Ace.Mask -band 0x00080000L) -ne 0) { return $true } # WRITE_OWNER
    if (($Ace.Mask -band 0x20L) -ne 0 -and
        (-not $Ace.IsObjectAce -or $Ace.ObjectType -eq [guid]::Empty)) { return $true }
    return $false
}

function Get-DangerousADPrincipals {
    param($Acl)
    # Match Certipy-style allow-ACE review. A deny ACE may reduce effective access,
    # so the finding text deliberately calls this an access-mask estimate.
    $scoped = @($Acl.Entries | Where-Object { Test-PrincipalInScope -Sid $_.Sid })
    $sids = @($scoped | Where-Object { $_.Allow -and (Test-DangerousADAce -Ace $_) } |
        Select-Object -ExpandProperty Sid -Unique)
    return @($sids | ForEach-Object { Convert-SidToName -Sid $_ })
}

function Get-CAPrincipals {
    param($Acl, [ValidateSet('Enroll','ManageCA','ManageCertificates')]$Right)
    $flag = switch ($Right) { 'Enroll' { 0x200L } 'ManageCA' { 0x1L } 'ManageCertificates' { 0x2L } }
    $scoped = @($Acl.Entries | Where-Object { Test-PrincipalInScope -Sid $_.Sid })
    if (@($scoped | Where-Object { $_.Deny -and (($_.Mask -band $flag) -ne 0) }).Count -gt 0) { return @() }
    $sids = @($scoped | Where-Object { $_.Allow -and (($_.Mask -band $flag) -ne 0) } |
        Select-Object -ExpandProperty Sid -Unique)
    return @($sids | ForEach-Object { Convert-SidToName -Sid $_ })
}

function Get-OidDisplayNames {
    param([string[]]$Oids)
    return @(($Oids | ForEach-Object {
        if ($OidNames.ContainsKey($_)) { "$($OidNames[$_]) ($_)" } else { $_ }
    }) -join '; ')
}

function Get-RemoteRegistryValue {
    param([string]$Computer, [string]$SubKey, [string]$ValueName)
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, $Computer)
        $key = $base.OpenSubKey($SubKey)
        if ($null -eq $key) {
            return [pscustomobject]@{ Success = $false; Present = $false; Value = $null; Error = 'Subkey not found or not readable' }
        }
        $value = $key.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return [pscustomobject]@{ Success = $true; Present = ($null -ne $value); Value = $value; Error = '' }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Present = $false; Value = $null; Error = $_.Exception.Message }
    }
    finally {
        if ($null -ne $key) { $key.Close() }
        if ($null -ne $base) { $base.Close() }
    }
}

function Invoke-CertutilGetReg {
    param([string]$Config, [string]$RegistryPath)
    try {
        $output = @(& certutil.exe -config $Config -getreg $RegistryPath 2>&1 | ForEach-Object { [string]$_ })
        $code = $LASTEXITCODE
        return [pscustomobject]@{
            Success = ($code -eq 0)
            Text = ($output -join "`n")
            Error = $(if ($code -ne 0) { ($output -join ' ') } else { '' })
        }
    }
    catch {
        return [pscustomobject]@{ Success = $false; Text = ''; Error = $_.Exception.Message }
    }
}

function Get-CertutilDword {
    param([string]$Text, [string]$Name)
    $match = [regex]::Match($Text, "(?im)^\s*$([regex]::Escape($Name))\s+REG_DWORD\s+=\s+([0-9a-f]+)")
    if ($match.Success) { return [Convert]::ToInt64($match.Groups[1].Value, 16) }
    return $null
}

function Get-CertutilBinary {
    param([string]$Text, [string]$Name)
    $start = [regex]::Match($Text, "(?im)^\s*$([regex]::Escape($Name))\s+REG_BINARY\s+=")
    if (-not $start.Success) { return $null }
    $tail = $Text.Substring($start.Index + $start.Length)
    $hex = New-Object System.Text.StringBuilder
    foreach ($line in ($tail -split "`r?`n")) {
        if ($line -match '(?i)CertUtil:') { break }
        $clean = $line.Trim()
        if (-not $clean) { if ($hex.Length -gt 0) { break } else { continue } }
        $clean = $clean -replace '[^0-9a-fA-F]', ''
        if ($clean.Length -ge 2 -and $clean.Length % 2 -eq 0) {
            [void]$hex.Append($clean)
        }
        elseif ($hex.Length -gt 0) { break }
    }
    if ($hex.Length -lt 2) { return $null }
    try {
        $bytes = [byte[]]::new([int]($hex.Length / 2))
        $hexText = $hex.ToString()
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($hexText.Substring($i * 2, 2), 16)
        }
        return $bytes
    }
    catch { return $null }
}

function Get-CAConfiguration {
    param([string]$CaName, [string]$DnsHostName)
    $data = [ordered]@{
        EditFlags = $null
        InterfaceFlags = $null
        RequestDisposition = $null
        ActivePolicy = $null
        DisabledExtensions = @()
        DisableExtensionListRead = $false
        SecurityBytes = $null
        Sources = New-Object System.Collections.ArrayList
        Errors = New-Object System.Collections.ArrayList
    }
    $rootPath = "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CaName"
    # Certipy/CSRA semantics: EditFlags, RequestDisposition, and DisableExtensionList
    # belong to the active policy module, not the CA root key.
    $activeRead = Get-RemoteRegistryValue -Computer $DnsHostName -SubKey "$rootPath\PolicyModules" -ValueName 'Active'
    if ($activeRead.Success -and $activeRead.Present) {
        $data.ActivePolicy = ([string]$activeRead.Value).Trim([char]0)
        [void]$data.Sources.Add('RemoteRegistry')
    }
    $activeForPath = $(if ($data.ActivePolicy) { $data.ActivePolicy } else { 'CertificateAuthority_MicrosoftDefault.Policy' })
    $activePolicyPath = "$rootPath\PolicyModules\$activeForPath"
    $registryValues = @(
        @{ Name = 'EditFlags'; SubKey = $activePolicyPath; Value = 'EditFlags' },
        @{ Name = 'InterfaceFlags'; SubKey = $rootPath; Value = 'InterfaceFlags' },
        @{ Name = 'RequestDisposition'; SubKey = $activePolicyPath; Value = 'RequestDisposition' },
        @{ Name = 'SecurityBytes'; SubKey = $rootPath; Value = 'Security' },
        @{ Name = 'DisabledExtensions'; SubKey = $activePolicyPath; Value = 'DisableExtensionList' }
    )
    foreach ($item in $registryValues) {
        $read = Get-RemoteRegistryValue -Computer $DnsHostName -SubKey $item.SubKey -ValueName $item.Value
        if ($read.Success -and $read.Present) {
            $data[$item.Name] = $read.Value
            if ($item.Name -eq 'DisabledExtensions') { $data.DisableExtensionListRead = $true }
            [void]$data.Sources.Add('RemoteRegistry')
        }
    }
    $config = "$DnsHostName\$CaName"
    if ($null -eq $data.EditFlags) {
        $read = Invoke-CertutilGetReg -Config $config -RegistryPath 'Policy\EditFlags'
        if ($read.Success) { $data.EditFlags = Get-CertutilDword -Text $read.Text -Name 'EditFlags'; [void]$data.Sources.Add('certutil') }
        else { [void]$data.Errors.Add("EditFlags: $($read.Error)") }
    }
    if ($null -eq $data.InterfaceFlags) {
        $read = Invoke-CertutilGetReg -Config $config -RegistryPath 'CA\InterfaceFlags'
        if ($read.Success) { $data.InterfaceFlags = Get-CertutilDword -Text $read.Text -Name 'InterfaceFlags'; [void]$data.Sources.Add('certutil') }
        else { [void]$data.Errors.Add("InterfaceFlags: $($read.Error)") }
    }
    if ($null -eq $data.RequestDisposition) {
        $read = Invoke-CertutilGetReg -Config $config -RegistryPath 'Policy\RequestDisposition'
        if ($read.Success) { $data.RequestDisposition = Get-CertutilDword -Text $read.Text -Name 'RequestDisposition'; [void]$data.Sources.Add('certutil') }
        else { [void]$data.Errors.Add("RequestDisposition: $($read.Error)") }
    }
    if ($null -eq $data.ActivePolicy) {
        $read = Invoke-CertutilGetReg -Config $config -RegistryPath 'Policy\Active'
        if ($read.Success -and $read.Text -match '(?im)^\s*Active\s+REG_SZ\s+=\s*(.+?)\s*$') {
            $data.ActivePolicy = $Matches[1]; [void]$data.Sources.Add('certutil')
        }
    }
    if (@($data.DisabledExtensions).Count -eq 0) {
        $read = Invoke-CertutilGetReg -Config $config -RegistryPath 'Policy\DisableExtensionList'
        if ($read.Success) {
            $data.DisabledExtensions = @([regex]::Matches($read.Text, '\b\d+(?:\.\d+){3,}\b') | ForEach-Object { $_.Value } | Select-Object -Unique)
            $data.DisableExtensionListRead = $true
            [void]$data.Sources.Add('certutil')
        }
        else { [void]$data.Errors.Add("DisableExtensionList: $($read.Error)") }
    }
    if ($null -eq $data.SecurityBytes) {
        $read = Invoke-CertutilGetReg -Config $config -RegistryPath 'CA\Security'
        if ($read.Success) {
            $data.SecurityBytes = Get-CertutilBinary -Text $read.Text -Name 'Security'
            [void]$data.Sources.Add('certutil')
        }
        else { [void]$data.Errors.Add("Security: $($read.Error)") }
    }
    return [pscustomobject]$data
}

function Get-WebEnrollmentStatus {
    param([string]$Scheme, [string]$Computer)
    $url = "${Scheme}://${Computer}/certsrv/"
    $response = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.Method = 'GET'
        $request.AllowAutoRedirect = $false
        $request.Timeout = $WebTimeoutSeconds * 1000
        $request.ReadWriteTimeout = $WebTimeoutSeconds * 1000
        $request.UseDefaultCredentials = $false
        $request.Credentials = $null
        $request.UserAgent = 'ReadOnly-ADCS-Audit/1.0'
        $response = $request.GetResponse()
        $status = [int]$response.StatusCode
        return [pscustomobject]@{ Url = $url; Status = $status; Exposed = ($status -in @(200,301,302,401,403)); Error = '' }
    }
    catch [System.Net.WebException] {
        if ($null -ne $_.Exception.Response) {
            $response = $_.Exception.Response
            $status = [int]$response.StatusCode
            return [pscustomobject]@{ Url = $url; Status = $status; Exposed = ($status -in @(200,301,302,401,403)); Error = '' }
        }
        return [pscustomobject]@{ Url = $url; Status = $null; Exposed = $false; Error = $_.Exception.Message }
    }
    catch {
        return [pscustomobject]@{ Url = $url; Status = $null; Exposed = $false; Error = $_.Exception.Message }
    }
    finally {
        if ($null -ne $response) { $response.Close() }
    }
}

function Get-CurrentUserSids {
    $set = @{}
    if ($null -eq $Credential) {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $set[$identity.User.Value] = $true
        foreach ($group in $identity.Groups) { $set[$group.Value] = $true }
    }
    else {
        $userName = $Credential.UserName
        if ($userName.Contains('\')) {
            $sam = $userName.Split('\')[-1]
            $filter = "(&(objectClass=user)(sAMAccountName=$(ConvertTo-LdapFilterValue -Value $sam)))"
        }
        elseif ($userName.Contains('@')) {
            $filter = "(&(objectClass=user)(userPrincipalName=$(ConvertTo-LdapFilterValue -Value $userName)))"
        }
        else {
            $sam = $userName
            $filter = "(&(objectClass=user)(sAMAccountName=$(ConvertTo-LdapFilterValue -Value $sam)))"
        }
        $user = @(Get-LdapEntries -BaseDn $script:DefaultNC -Filter $filter -Properties @('objectSid','tokenGroups')) | Select-Object -First 1
        if ($null -eq $user) { throw "Could not resolve the supplied LDAP credential to a user and tokenGroups." }
        $sidBytes = Get-ByteValue -Result $user -Name 'objectSid'
        $sid = [System.Security.Principal.SecurityIdentifier]::new($sidBytes, 0).Value
        $set[$sid] = $true
        foreach ($groupBytes in @(Get-PropertyValues -Result $user -Name 'tokenGroups')) {
            $groupSid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$groupBytes, 0).Value
            $set[$groupSid] = $true
        }
    }
    $set['S-1-1-0'] = $true
    $set['S-1-5-11'] = $true
    return $set
}

function Get-MappingType {
    param([string]$Mapping)
    if ($Mapping -match '(?i)<SR>') { return 'X509IssuerSerialNumber (strong)' }
    if ($Mapping -match '(?i)<SKI>') { return 'X509SKI (strong)' }
    if ($Mapping -match '(?i)<SHA1-PUKEY>') { return 'X509SHA1PublicKey (strong)' }
    if ($Mapping -match '(?i)<RFC822>') { return 'X509RFC822 (weak)' }
    if ($Mapping -match '(?i)<I>.*<S>') { return 'X509IssuerSubject (weak)' }
    if ($Mapping -match '(?i)^X509:<S>') { return 'X509SubjectOnly (weak)' }
    return 'Unrecognised - manual review'
}

# Connect and discover naming contexts.
Write-Status 'Reading RootDSE and current security context'
$root = $null
try {
    $rootPath = $(if ($DomainController) { "LDAP://$DomainController/RootDSE" } else { 'LDAP://RootDSE' })
    $root = New-DirectoryEntry -Path $rootPath
    $script:DefaultNC = [string]$root.defaultNamingContext
    $configurationNC = [string]$root.configurationNamingContext
    if (-not $script:DefaultNC -or -not $configurationNC) { throw 'RootDSE did not return naming contexts.' }
    $script:UserSids = Get-CurrentUserSids
}
finally {
    if ($null -ne $root) { $root.Dispose() }
}

$pkiBase = "CN=Public Key Services,CN=Services,$configurationNC"
$templateBase = "CN=Certificate Templates,$pkiBase"
$caBase = "CN=Enrollment Services,$pkiBase"
$oidBase = "CN=OID,$pkiBase"

Write-Status 'Enumerating enterprise CAs, certificate templates, and issuance policies'
$templateResults = @(Get-LdapEntries -BaseDn $templateBase -Filter '(objectClass=pKICertificateTemplate)' -Properties @(
    'cn','name','displayName','distinguishedName','flags','msPKI-Enrollment-Flag',
    'msPKI-Private-Key-Flag','msPKI-Certificate-Name-Flag','msPKI-Certificate-Policy',
    'msPKI-Minimal-Key-Size','msPKI-RA-Signature','msPKI-Template-Schema-Version',
    'msPKI-RA-Application-Policies','pKIExtendedKeyUsage','nTSecurityDescriptor',
    'objectGUID','whenCreated','whenChanged'
))
$caResults = @(Get-LdapEntries -BaseDn $caBase -Filter '(objectClass=pKIEnrollmentService)' -Properties @(
    'cn','name','dNSHostName','cACertificateDN','certificateTemplates','distinguishedName',
    'nTSecurityDescriptor','objectGUID'
))
$oidResults = @(Get-LdapEntries -BaseDn $oidBase -Filter '(objectClass=msPKI-Enterprise-Oid)' -Properties @(
    'cn','name','displayName','distinguishedName','msDS-OIDToGroupLink',
    'msPKI-Cert-Template-OID','nTSecurityDescriptor','objectGUID'
))

Write-Status "Found $($caResults.Count) enterprise CA(s), $($templateResults.Count) template(s), and $($oidResults.Count) issuance policy object(s)"
if ($caResults.Count -eq 0) { Write-Warning 'No enterprise CA objects were visible. Templates may still have dangerous ACLs.' }

$oidByValue = @{}
foreach ($oid in $oidResults) {
    $oidValue = [string](Get-PropertyValue -Result $oid -Name 'msPKI-Cert-Template-OID')
    if ($oidValue) { $oidByValue[$oidValue] = $oid }
}

$caByTemplate = @{}
foreach ($ca in $caResults) {
    $caName = [string](Get-PropertyValue -Result $ca -Name 'name')
    foreach ($templateName in @(Get-PropertyValues -Result $ca -Name 'certificateTemplates')) {
        $key = [string]$templateName
        if (-not $caByTemplate.ContainsKey($key)) { $caByTemplate[$key] = New-Object System.Collections.ArrayList }
        [void]$caByTemplate[$key].Add($caName)
    }
}

# Build OID inventory and assess dangerous OID ownership/ACLs.
foreach ($oid in $oidResults) {
    $name = [string](Get-PropertyValue -Result $oid -Name 'name')
    $dn = [string](Get-PropertyValue -Result $oid -Name 'distinguishedName')
    $oidValue = [string](Get-PropertyValue -Result $oid -Name 'msPKI-Cert-Template-OID')
    $linkedGroup = [string](Get-PropertyValue -Result $oid -Name 'msDS-OIDToGroupLink')
    $sdBytes = Get-ByteValue -Result $oid -Name 'nTSecurityDescriptor'
    $acl = Get-AclEntries -Bytes $sdBytes
    $ownerName = $(if ($acl.OwnerSid) { Convert-SidToName -Sid $acl.OwnerSid } else { '' })
    $dangerous = @(Get-DangerousADPrincipals -Acl $acl)
    $ownerInScope = $acl.OwnerSid -and (Test-PrincipalInScope -Sid $acl.OwnerSid)
    [void]$script:OidInventory.Add([pscustomobject]@{
        Name = $name
        DisplayName = [string](Get-PropertyValue -Result $oid -Name 'displayName')
        OID = $oidValue
        LinkedGroup = $linkedGroup
        Owner = $ownerName
        DangerousPrincipals = ($dangerous -join '; ')
        DistinguishedName = $dn
    })
    if ($ownerInScope -or $dangerous.Count -gt 0) {
        $principal = $(if ($ownerInScope) { $ownerName } else { $dangerous -join '; ' })
        Add-Finding -Check 'ESC13' -Severity 'High' -Confidence 'Finding' -ObjectType 'IssuancePolicyOID' `
            -ObjectName $name -Principal $principal -DistinguishedName $dn `
            -Evidence 'Current scope owns the issuance-policy OID or has write/control rights that could change its group link.' `
            -Limitation 'Changing a group link is not performed; review the affected templates and linked group impact.'
    }
}

# Process templates.
foreach ($template in $templateResults) {
    $name = [string](Get-PropertyValue -Result $template -Name 'name')
    $displayName = [string](Get-PropertyValue -Result $template -Name 'displayName')
    $dn = [string](Get-PropertyValue -Result $template -Name 'distinguishedName')
    $enrollmentFlags = Get-IntValue -Result $template -Name 'msPKI-Enrollment-Flag'
    $nameFlags = Get-IntValue -Result $template -Name 'msPKI-Certificate-Name-Flag'
    $schemaVersion = Get-IntValue -Result $template -Name 'msPKI-Template-Schema-Version' -Default 1
    $signatures = Get-IntValue -Result $template -Name 'msPKI-RA-Signature'
    $ekus = @([string[]]@(Get-PropertyValues -Result $template -Name 'pKIExtendedKeyUsage'))
    $applicationPolicies = @([string[]]@(Get-PropertyValues -Result $template -Name 'msPKI-RA-Application-Policies'))
    $issuancePolicies = @([string[]]@(Get-PropertyValues -Result $template -Name 'msPKI-Certificate-Policy'))
    $linkedGroups = New-Object System.Collections.ArrayList
    foreach ($policyOid in $issuancePolicies) {
        if ($oidByValue.ContainsKey($policyOid)) {
            $group = [string](Get-PropertyValue -Result $oidByValue[$policyOid] -Name 'msDS-OIDToGroupLink')
            if ($group) { [void]$linkedGroups.Add($group) }
        }
    }
    $anyPurpose = ($ekus.Count -eq 0 -or $ekus -contains $AnyPurposeOid)
    $clientAuth = ($anyPurpose -or @($ekus | Where-Object { $ClientAuthOids -contains $_ }).Count -gt 0)
    $serverAuth = ($anyPurpose -or $ekus -contains $ServerAuthOid)
    $enrollmentAgent = $ekus -contains $EnrollmentAgentOid
    $suppliesSubject = (($nameFlags -band 0x1L) -ne 0)
    $managerApproval = (($enrollmentFlags -band 0x2L) -ne 0)
    $noSecurityExtension = (($enrollmentFlags -band 0x80000L) -ne 0)
    $enabledOn = @()
    if ($caByTemplate.ContainsKey($name)) { $enabledOn = @($caByTemplate[$name]) }
    $enabled = ($enabledOn.Count -gt 0 -or $IncludeDisabledTemplates)
    $sdBytes = Get-ByteValue -Result $template -Name 'nTSecurityDescriptor'
    $acl = Get-AclEntries -Bytes $sdBytes
    $ownerName = $(if ($acl.OwnerSid) { Convert-SidToName -Sid $acl.OwnerSid } else { '' })
    $enrollable = @(Get-EnrollmentPrincipals -Acl $acl)
    $dangerous = @(Get-DangerousADPrincipals -Acl $acl)
    $ownerInScope = $acl.OwnerSid -and (Test-PrincipalInScope -Sid $acl.OwnerSid)

    [void]$script:TemplateInventory.Add([pscustomobject]@{
        Name = $name
        DisplayName = $displayName
        EnabledOnCAs = ($enabledOn -join '; ')
        Enabled = ($enabledOn.Count -gt 0)
        SchemaVersion = $schemaVersion
        ClientAuthentication = $clientAuth
        ServerAuthentication = $serverAuth
        AnyPurpose = $anyPurpose
        EnrollmentAgent = $enrollmentAgent
        EnrolleeSuppliesSubject = $suppliesSubject
        RequiresManagerApproval = $managerApproval
        AuthorizedSignatures = $signatures
        NoSecurityExtension = $noSecurityExtension
        EKUs = (Get-OidDisplayNames -Oids $ekus)
        ApplicationPolicies = (Get-OidDisplayNames -Oids $applicationPolicies)
        IssuancePolicies = ($issuancePolicies -join '; ')
        LinkedGroups = (@($linkedGroups) -join '; ')
        Owner = $ownerName
        EnrollablePrincipals = ($enrollable -join '; ')
        DangerousPrincipals = ($dangerous -join '; ')
        DistinguishedName = $dn
    })

    $requiresApproval = ($managerApproval -or $signatures -gt 0)
    if ($enabled -and $enrollable.Count -gt 0 -and -not $requiresApproval) {
        $principal = $enrollable -join '; '
        if ($suppliesSubject -and $clientAuth) {
            Add-Finding -Check 'ESC1' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence 'Enabled template permits enrollee-supplied subject, client authentication, and scoped enrolment without manager approval or authorised signatures.'
        }
        if ($anyPurpose) {
            Add-Finding -Check 'ESC2' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence 'Enabled template has Any Purpose EKU or no EKU restriction and is enrolable without issuance approval controls.'
        }
        if ($enrollmentAgent) {
            Add-Finding -Check 'ESC3' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence 'Enabled template grants Certificate Request Agent EKU and is enrolable without manager approval or authorised signatures.' `
                -Limitation 'A suitable target template and CA Enroll permission are prerequisites; CA enrollment-agent restrictions are not evaluated.'
        }
        if ($noSecurityExtension -and $clientAuth) {
            Add-Finding -Check 'ESC9' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence 'Client-authentication template explicitly disables the SID security extension and is enrolable without approval controls.' `
                -Limitation 'Exploitability depends on DC certificate-binding behaviour and an identity-manipulation or ESC6 condition; not tested.'
        }
        if ($clientAuth -and $linkedGroups.Count -gt 0) {
            Add-Finding -Check 'ESC13' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence "Client-authentication template uses issuance policy linked to group(s): $(@($linkedGroups) -join '; ')" `
                -Limitation 'Review the linked group privileges; group membership is not inferred or modified by this script.'
        }
        if ($suppliesSubject -and $schemaVersion -eq 1) {
            Add-Finding -Check 'ESC15' -Severity 'High' -Confidence 'Candidate' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence 'Schema-version-1 template permits enrollee-supplied subject and is enrolable without approval controls.' `
                -Limitation 'Applicable only where the CA is susceptible to CVE-2024-49019; patch level is not established.'
        }
        if ($suppliesSubject -and $serverAuth) {
            Add-Finding -Check 'ESC17' -Severity 'High' -Confidence 'Candidate' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
                -Evidence 'Enabled server-authentication template permits enrollee-supplied subject and scoped enrolment without approval controls.' `
                -Limitation 'A useful target service and certificate-validation path are separate prerequisites; not tested.'
        }
    }

    if ($enabled -and $enrollable.Count -gt 0 -and $clientAuth) {
        if ($schemaVersion -eq 1 -or
            ($schemaVersion -gt 1 -and $signatures -gt 0 -and $applicationPolicies -contains $AnyPurposeOid)) {
            Add-Finding -Check 'ESC2-TARGET' -Severity 'Informational' -Confidence 'Context' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal ($enrollable -join '; ') -DistinguishedName $dn `
                -Evidence 'Client-authentication template matches the schema/signature conditions of an ESC2 target template.' `
                -Limitation 'Context only, not a vulnerability by itself.'
        }
        if ($schemaVersion -eq 1 -or
            ($schemaVersion -gt 1 -and $signatures -gt 0 -and $applicationPolicies -contains $EnrollmentAgentOid)) {
            Add-Finding -Check 'ESC3-TARGET' -Severity 'Informational' -Confidence 'Context' -ObjectType 'CertificateTemplate' `
                -ObjectName $name -CAName ($enabledOn -join '; ') -Principal ($enrollable -join '; ') -DistinguishedName $dn `
                -Evidence 'Client-authentication template matches the schema/signature conditions of an ESC3 target template.' `
                -Limitation 'Context only, not a vulnerability by itself.'
        }
    }

    if ($ownerInScope -or $dangerous.Count -gt 0) {
        $principal = $(if ($ownerInScope) { $ownerName } else { $dangerous -join '; ' })
        Add-Finding -Check 'ESC4' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateTemplate' `
            -ObjectName $name -CAName ($enabledOn -join '; ') -Principal $principal -DistinguishedName $dn `
            -Evidence 'Scoped principal owns the template or has GenericAll/GenericWrite/WriteDacl/WriteOwner/all-object WriteProperty rights.' `
            -Limitation 'ACL evaluation is an access-mask estimate and does not modify the template.'
    }
}

# Process CAs and their live configuration.
foreach ($ca in $caResults) {
    $name = [string](Get-PropertyValue -Result $ca -Name 'name')
    $dns = [string](Get-PropertyValue -Result $ca -Name 'dNSHostName')
    $dn = [string](Get-PropertyValue -Result $ca -Name 'distinguishedName')
    $templates = @([string[]]@(Get-PropertyValues -Result $ca -Name 'certificateTemplates'))
    $ldapAcl = Get-AclEntries -Bytes (Get-ByteValue -Result $ca -Name 'nTSecurityDescriptor')
    $ldapDangerous = @(Get-DangerousADPrincipals -Acl $ldapAcl)
    $ldapOwner = $(if ($ldapAcl.OwnerSid) { Convert-SidToName -Sid $ldapAcl.OwnerSid } else { '' })
    $ldapOwnerInScope = $ldapAcl.OwnerSid -and (Test-PrincipalInScope -Sid $ldapAcl.OwnerSid)
    if ($ldapOwnerInScope -or $ldapDangerous.Count -gt 0) {
        Add-Finding -Check 'ESC5' -Severity 'High' -Confidence 'Finding' -ObjectType 'CA-ADObject' `
            -ObjectName $name -CAName $name -DistinguishedName $dn `
            -Principal $(if ($ldapOwnerInScope) { $ldapOwner } else { $ldapDangerous -join '; ' }) `
            -Evidence 'Scoped principal owns the CA enrollment-service AD object or has dangerous write/control rights.' `
            -Limitation 'This assesses the AD object ACL, not the CA security descriptor stored on the CA server.'
    }

    $config = $null
    if (-not $SkipCAConfiguration -and $dns) {
        Write-Status "Reading CA configuration: $dns\$name"
        $config = Get-CAConfiguration -CaName $name -DnsHostName $dns
    }
    $editFlags = $(if ($null -ne $config) { $config.EditFlags } else { $null })
    $interfaceFlags = $(if ($null -ne $config) { $config.InterfaceFlags } else { $null })
    $requestDisposition = $(if ($null -ne $config) { $config.RequestDisposition } else { $null })
    $disabledExtensions = $(if ($null -ne $config) { @($config.DisabledExtensions) } else { @() })
    $caAcl = $null
    $caEnroll = @()
    $manageCA = @()
    $manageCerts = @()
    $caSecurityState = 'Unknown'
    if ($null -ne $config -and $null -ne $config.SecurityBytes) {
        $caAcl = Get-AclEntries -Bytes ([byte[]]$config.SecurityBytes)
        if ($null -ne $caAcl -and $caAcl.ContainsKey('Entries') -and $caAcl.Parsed) {
            $caEnroll = @(Get-CAPrincipals -Acl $caAcl -Right Enroll)
            $manageCA = @(Get-CAPrincipals -Acl $caAcl -Right ManageCA)
            $manageCerts = @(Get-CAPrincipals -Acl $caAcl -Right ManageCertificates)
            $caSecurityState = 'Read'
        }
    }
    $willIssue = ($null -eq $requestDisposition -or (($requestDisposition -band 0x100L) -eq 0))
    $sanState = $(if ($null -eq $editFlags) { 'Unknown' } elseif (($editFlags -band 0x40000L) -ne 0) { 'Enabled' } else { 'Disabled' })
    $rpcState = $(if ($null -eq $interfaceFlags) { 'Unknown' } elseif (($interfaceFlags -band 0x200L) -ne 0) { 'Enabled' } else { 'Disabled' })
    $requestState = $(if ($null -eq $requestDisposition) { 'Unknown' } elseif (($requestDisposition -band 0x100L) -ne 0) { 'Pending' } else { 'Issue' })

    $http = $null
    $https = $null
    if (-not $SkipWebEnrollment -and $dns) {
        $http = Get-WebEnrollmentStatus -Scheme 'http' -Computer $dns
        $https = Get-WebEnrollmentStatus -Scheme 'https' -Computer $dns
    }

    [void]$script:CAInventory.Add([pscustomobject]@{
        Name = $name
        DNSHostName = $dns
        EnabledTemplates = ($templates -join '; ')
        EditFlags = $editFlags
        UserSpecifiedSAN = $sanState
        InterfaceFlags = $interfaceFlags
        EnforceEncryptionForRequests = $rpcState
        RequestDisposition = $requestState
        ActivePolicy = $(if ($null -ne $config) { [string]$config.ActivePolicy } else { '' })
        DisabledExtensions = ($disabledExtensions -join '; ')
        CASecurity = $caSecurityState
        CAEnrollPrincipals = ($caEnroll -join '; ')
        ManageCAPrincipals = ($manageCA -join '; ')
        ManageCertificatesPrincipals = ($manageCerts -join '; ')
        HTTPStatus = $(if ($null -ne $http) { $http.Status } else { '' })
        HTTPSStatus = $(if ($null -ne $https) { $https.Status } else { '' })
        ConfigurationSources = $(if ($null -ne $config) { (@($config.Sources) | Select-Object -Unique) -join '; ' } else { '' })
        ConfigurationErrors = $(if ($null -ne $config) { (@($config.Errors) -join ' | ') } else { 'Skipped' })
        WebErrors = (@($http,$https) | Where-Object { $null -ne $_ -and $_.Error } | ForEach-Object { "$($_.Url): $($_.Error)" }) -join ' | '
        DistinguishedName = $dn
    })

    if ($manageCA.Count -gt 0 -or $manageCerts.Count -gt 0) {
        $rights = @()
        if ($manageCA.Count -gt 0) { $rights += "ManageCA: $($manageCA -join ', ')" }
        if ($manageCerts.Count -gt 0) { $rights += "ManageCertificates: $($manageCerts -join ', ')" }
        Add-Finding -Check 'ESC7' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateAuthority' `
            -ObjectName $name -CAName $name -Principal ((@($manageCA + $manageCerts) | Select-Object -Unique) -join '; ') `
            -DistinguishedName $dn -Evidence ($rights -join '; ')
    }

    if ($sanState -eq 'Enabled' -and $willIssue) {
        if ($caEnroll.Count -gt 0) {
            Add-Finding -Check 'ESC6' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateAuthority' `
                -ObjectName $name -CAName $name -Principal ($caEnroll -join '; ') -DistinguishedName $dn `
                -Evidence 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled, requests are not configured as pending, and scoped principals have CA Enroll rights.' `
                -Limitation 'A suitable enabled template and other chain prerequisites still apply.'
        }
        elseif ($caSecurityState -eq 'Unknown') {
            Add-Finding -Check 'ESC6' -Severity 'High' -Confidence 'Candidate' -ObjectType 'CertificateAuthority' `
                -ObjectName $name -CAName $name -DistinguishedName $dn `
                -Evidence 'EDITF_ATTRIBUTESUBJECTALTNAME2 is enabled and the CA is not configured for pending requests.' `
                -Limitation 'CA security was unreadable, so scoped CA Enroll permission could not be established.'
        }
    }
    elseif ($sanState -eq 'Unknown') {
        Add-Finding -Check 'ESC6' -Severity 'Informational' -Confidence 'Unknown' -ObjectType 'CertificateAuthority' `
            -ObjectName $name -CAName $name -DistinguishedName $dn -Evidence 'CA EditFlags could not be read.' `
            -Limitation 'Unknown is not safe. Run with CA configuration read permission or check certutil -getreg Policy\EditFlags locally on the CA.'
    }

    if ($rpcState -eq 'Disabled' -and $willIssue) {
        Add-Finding -Check 'ESC11' -Severity 'High' -Confidence 'Finding' -ObjectType 'CertificateAuthority' `
            -ObjectName $name -CAName $name -DistinguishedName $dn `
            -Evidence 'IF_ENFORCEENCRYPTICERTREQUEST is not set in InterfaceFlags and requests are not configured as pending.'
    }
    elseif ($rpcState -eq 'Unknown') {
        Add-Finding -Check 'ESC11' -Severity 'Informational' -Confidence 'Unknown' -ObjectType 'CertificateAuthority' `
            -ObjectName $name -CAName $name -DistinguishedName $dn -Evidence 'CA InterfaceFlags could not be read.' `
            -Limitation 'Unknown is not safe. Verify IF_ENFORCEENCRYPTICERTREQUEST on the CA.'
    }

    if ($disabledExtensions -contains $SecurityExtensionOid -and $willIssue) {
        Add-Finding -Check 'ESC16' -Severity 'High' -Confidence $(if ($caEnroll.Count -gt 0) { 'Finding' } else { 'Candidate' }) `
            -ObjectType 'CertificateAuthority' -ObjectName $name -CAName $name -Principal ($caEnroll -join '; ') `
            -DistinguishedName $dn -Evidence 'The CA DisableExtensionList contains the SID security extension OID 1.3.6.1.4.1.311.25.2.' `
            -Limitation $(if ($caSecurityState -eq 'Unknown') { 'CA Enroll rights could not be verified; other chain prerequisites also apply.' } else { 'Other chain prerequisites apply.' })
    }
    elseif ($null -eq $config -or -not $config.DisableExtensionListRead) {
        Add-Finding -Check 'ESC16' -Severity 'Informational' -Confidence 'Unknown' -ObjectType 'CertificateAuthority' `
            -ObjectName $name -CAName $name -DistinguishedName $dn -Evidence 'The CA DisableExtensionList could not be read.' `
            -Limitation 'Unknown is not safe. Verify whether 1.3.6.1.4.1.311.25.2 appears in the CA policy DisableExtensionList.'
    }

    if ($null -ne $http -and $http.Exposed -and $willIssue) {
        Add-Finding -Check 'ESC8' -Severity 'High' -Confidence 'Candidate' -ObjectType 'WebEnrollment' `
            -ObjectName $http.Url -CAName $name -DistinguishedName $dn `
            -Evidence "HTTP /certsrv/ returned status $($http.Status), indicating web-enrolment exposure without transport security." `
            -Limitation 'Exposure candidate only; no relay, authentication, or certificate request was performed.'
    }
    if ($null -ne $https -and $https.Exposed -and $willIssue) {
        Add-Finding -Check 'ESC8' -Severity 'Medium' -Confidence 'Review' -ObjectType 'WebEnrollment' `
            -ObjectName $https.Url -CAName $name -DistinguishedName $dn `
            -Evidence "HTTPS /certsrv/ returned status $($https.Status)." `
            -Limitation 'EPA/channel binding was not verified. HTTPS exposure alone does not confirm ESC8.'
    }
    if ($caSecurityState -eq 'Unknown') {
        Add-Finding -Check 'ESC7' -Severity 'Informational' -Confidence 'Unknown' -ObjectType 'CertificateAuthority' `
            -ObjectName $name -CAName $name -DistinguishedName $dn -Evidence 'The CA security descriptor could not be read.' `
            -Limitation 'ManageCA/ManageCertificates and CA Enroll rights are unknown, not absent.'
    }
}

# ESC14: inventory explicit certificate mappings and flag weak mapping types for review.
Write-Status 'Reviewing explicit altSecurityIdentities certificate mappings'
$mappingResults = @(Get-LdapEntries -BaseDn $script:DefaultNC -Filter '(&(objectClass=user)(altSecurityIdentities=*))' -Properties @(
    'name','sAMAccountName','distinguishedName','altSecurityIdentities','adminCount'
))
foreach ($account in $mappingResults) {
    $accountName = [string](Get-PropertyValue -Result $account -Name 'sAMAccountName')
    $dn = [string](Get-PropertyValue -Result $account -Name 'distinguishedName')
    $adminCount = Get-IntValue -Result $account -Name 'adminCount'
    foreach ($mapping in @(Get-PropertyValues -Result $account -Name 'altSecurityIdentities')) {
        $mappingText = [string]$mapping
        $mappingType = Get-MappingType -Mapping $mappingText
        $weak = $mappingType -match '\(weak\)'
        [void]$script:MappingInventory.Add([pscustomobject]@{
            Account = $accountName
            AdminCount = $adminCount
            MappingType = $mappingType
            Mapping = $mappingText
            DistinguishedName = $dn
        })
        if ($weak) {
            Add-Finding -Check 'ESC14' -Severity $(if ($adminCount -eq 1) { 'High' } else { 'Medium' }) `
                -Confidence 'Review' -ObjectType 'AccountCertificateMapping' -ObjectName $accountName `
                -DistinguishedName $dn -Evidence "$mappingType explicit mapping is present." `
                -Limitation 'Review only. ESC14 also requires suitable write access to altSecurityIdentities and a usable certificate/mapping path.'
        }
    }
}

# Optional ESC10/ESC9 supporting DC registry checks.
if ($CheckDomainControllers) {
    Write-Status 'Attempting read-only KDC/Schannel registry checks on domain controllers'
    $dcResults = @(Get-LdapEntries -BaseDn $script:DefaultNC -Filter '(&(objectCategory=computer)(primaryGroupID=516))' -Properties @(
        'name','dNSHostName','distinguishedName'
    ))
    foreach ($dc in $dcResults) {
        $name = [string](Get-PropertyValue -Result $dc -Name 'name')
        $dns = [string](Get-PropertyValue -Result $dc -Name 'dNSHostName')
        $dn = [string](Get-PropertyValue -Result $dc -Name 'distinguishedName')
        if (-not $dns) { $dns = $name }
        $kdc = Get-RemoteRegistryValue -Computer $dns -SubKey 'SYSTEM\CurrentControlSet\Services\Kdc' -ValueName 'StrongCertificateBindingEnforcement'
        $schannel = Get-RemoteRegistryValue -Computer $dns -SubKey 'SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -ValueName 'CertificateMappingMethods'
        $kdcValue = $(if ($kdc.Success -and $kdc.Present) { [int64]$kdc.Value } else { $null })
        $schannelValue = $(if ($schannel.Success -and $schannel.Present) { [int64]$schannel.Value } else { $null })
        [void]$script:DCInventory.Add([pscustomobject]@{
            Name = $name
            DNSHostName = $dns
            StrongCertificateBindingEnforcement = $(if ($null -ne $kdcValue) { $kdcValue } else { 'Unknown/not present' })
            CertificateMappingMethods = $(if ($null -ne $schannelValue) { ('0x{0:X}' -f $schannelValue) } else { 'Unknown/not present' })
            KDCReadError = $kdc.Error
            SchannelReadError = $schannel.Error
            DistinguishedName = $dn
        })
        if ($null -ne $schannelValue -and (($schannelValue -band 0x4L) -ne 0)) {
            Add-Finding -Check 'ESC10' -Severity 'High' -Confidence 'Finding' -ObjectType 'DomainController' `
                -ObjectName $name -DistinguishedName $dn `
                -Evidence "Schannel CertificateMappingMethods includes weak UPN mapping (0x4): 0x$($schannelValue.ToString('X'))" `
                -Limitation 'A usable client-authentication certificate and account/UPN control are separate prerequisites.'
        }
        if ($kdc.Success -and $kdc.Present -and $kdcValue -in @(0,1)) {
            Add-Finding -Check 'ESC9-CONTEXT' -Severity 'Medium' -Confidence 'Review' -ObjectType 'DomainController' `
                -ObjectName $name -DistinguishedName $dn `
                -Evidence "StrongCertificateBindingEnforcement is explicitly $kdcValue." `
                -Limitation 'Patch level matters; newer DC updates can change or remove compatibility behaviour.'
        }
    }
}

# Coverage is explicit to avoid interpreting unperformed checks as safe.
$coverage = @(
    [pscustomobject]@{ Check='ESC1'; Coverage='Implemented'; Notes='Enabled template, enrollee-supplied subject, client auth, scoped enrolment, no approval/signatures.' },
    [pscustomobject]@{ Check='ESC2'; Coverage='Implemented + target context'; Notes='Any Purpose or absent EKU; target-template conditions reported separately.' },
    [pscustomobject]@{ Check='ESC3'; Coverage='Implemented + target context'; Notes='Certificate Request Agent EKU and target-template conditions.' },
    [pscustomobject]@{ Check='ESC4'; Coverage='Implemented'; Notes='Template ownership and dangerous AD ACL masks for scoped principals.' },
    [pscustomobject]@{ Check='ESC5'; Coverage='Implemented'; Notes='CA enrollment-service AD object ownership and dangerous ACLs.' },
    [pscustomobject]@{ Check='ESC6'; Coverage='Implemented when CA config is readable'; Notes='EditFlags, request disposition, and CA Enroll security; unknown is reported when unreadable.' },
    [pscustomobject]@{ Check='ESC7'; Coverage='Implemented when CA security is readable'; Notes='ManageCA and ManageCertificates from the CA security descriptor.' },
    [pscustomobject]@{ Check='ESC8'; Coverage='Partial'; Notes='Unauthenticated HTTP(S) exposure only. HTTPS EPA/channel binding is not verified.' },
    [pscustomobject]@{ Check='ESC9'; Coverage='Implemented + optional DC context'; Notes='CT_FLAG_NO_SECURITY_EXTENSION; exploitability still depends on the chain and DC behaviour.' },
    [pscustomobject]@{ Check='ESC10'; Coverage='Optional'; Notes='Requires -CheckDomainControllers and readable Schannel registry values.' },
    [pscustomobject]@{ Check='ESC11'; Coverage='Implemented when CA config is readable'; Notes='IF_ENFORCEENCRYPTICERTREQUEST and request disposition.' },
    [pscustomobject]@{ Check='ESC12'; Coverage='Not implemented'; Notes='YubiHSM2-specific issue; not an AD CS LDAP/template configuration check.' },
    [pscustomobject]@{ Check='ESC13'; Coverage='Implemented'; Notes='Issuance-policy group links plus dangerous OID ownership/ACLs.' },
    [pscustomobject]@{ Check='ESC14'; Coverage='Partial review'; Notes='Weak explicit altSecurityIdentities mappings are inventoried; write access is not established.' },
    [pscustomobject]@{ Check='ESC15'; Coverage='Candidate detection'; Notes='V1 enrollee-supplied-subject template; CVE-2024-49019 patch exposure is not established.' },
    [pscustomobject]@{ Check='ESC16'; Coverage='Implemented when CA config is readable'; Notes='SID security extension in DisableExtensionList.' },
    [pscustomobject]@{ Check='ESC17'; Coverage='Candidate detection'; Notes='Server-auth template with enrollee-supplied subject and scoped enrolment.' }
)

# Export only after all objects are complete; use a new timestamped directory to prevent stale CSV confusion.
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDirectory = Join-Path $OutputDirectory $stamp
New-Item -ItemType Directory -Path $runDirectory -Force | Out-Null
$findingsPath = Join-Path $runDirectory 'ADCS_Findings.csv'
$templatesPath = Join-Path $runDirectory 'ADCS_Templates.csv'
$caPath = Join-Path $runDirectory 'ADCS_CAs.csv'
$oidPath = Join-Path $runDirectory 'ADCS_IssuancePolicies.csv'
$coveragePath = Join-Path $runDirectory 'ADCS_Coverage.csv'

$severityOrder = @{ 'High'=0; 'Medium'=1; 'Low'=2; 'Informational'=3 }
$script:Findings | Sort-Object @{Expression={$severityOrder[$_.Severity]}},Check,ObjectName |
    Export-Csv -Path $findingsPath -NoTypeInformation -Encoding UTF8
$script:TemplateInventory | Sort-Object Name | Export-Csv -Path $templatesPath -NoTypeInformation -Encoding UTF8
$script:CAInventory | Sort-Object Name | Export-Csv -Path $caPath -NoTypeInformation -Encoding UTF8
$script:OidInventory | Sort-Object Name | Export-Csv -Path $oidPath -NoTypeInformation -Encoding UTF8
$coverage | Export-Csv -Path $coveragePath -NoTypeInformation -Encoding UTF8
if ($script:MappingInventory.Count -gt 0) {
    $script:MappingInventory | Sort-Object Account | Export-Csv -Path (Join-Path $runDirectory 'ADCS_CertificateMappings.csv') -NoTypeInformation -Encoding UTF8
}
if ($script:DCInventory.Count -gt 0) {
    $script:DCInventory | Sort-Object Name | Export-Csv -Path (Join-Path $runDirectory 'ADCS_DomainControllers.csv') -NoTypeInformation -Encoding UTF8
}

Write-Host ''
Write-Host "AD CS audit complete: $runDirectory" -ForegroundColor Green
Write-Host "Templates: $($script:TemplateInventory.Count) | CAs: $($script:CAInventory.Count) | Findings/context: $($script:Findings.Count)"
Write-Host 'High/Medium findings and review candidates:'
$script:Findings | Where-Object { $_.Severity -in @('High','Medium') } |
    Sort-Object Check,ObjectName | Format-Table Check,Severity,Confidence,ObjectType,ObjectName,Principal -AutoSize -Wrap
Write-Host ''
Write-Host 'Read ADCS_Coverage.csv before interpreting unknown or partial checks. No certificates were requested and no settings were changed.' -ForegroundColor Yellow
