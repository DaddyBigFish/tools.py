function Invoke-ADAudit{
[CmdletBinding()]
param([switch]$h,[string[]]$DC,[string]$SysvolLoot,[string]$OutFile="adaudit_$(Get-Date -f yyyyMMdd_HHmmss).csv",[pscredential]$Credential)
if($h){@'
Invoke-ADAudit - read-only native AD findings collector (maps to ptdash findings-templates, FP-audited)

usage:
  Invoke-ADAudit                      fingerprint env, run applicable checks, write adaudit_<timestamp>.csv
  Invoke-ADAudit -DC DC01,DC02        override DC auto-discovery for registry/service checks
  Invoke-ADAudit -SysvolLoot x.txt    + grep smblist output for SYSVOL files (GPP lane)
  Invoke-ADAudit -OutFile ''          emit objects to pipeline instead of CSV

load from URL:
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/USER/REPO/main/Invoke-ADAudit.ps1')
  Invoke-ADAudit -Verbose

output: CSV columns Risk,Title,SamAccountName,SID,Detail
  titles match findings-templates exactly where one exists; [*] = invented title (no template fit)
  the fingerprint stage gates checks on DFL/schema/DC-OS so inapplicable checks never fire
'@;return}
$cp=$Credential
$pw=if($cp){$cp.GetNetworkCredential().Password}
$root=if($cp){New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE',$cp.UserName,$pw)}else{[adsi]'LDAP://RootDSE'}
$nc=$root.defaultNamingContext
$cfg=$root.configurationNamingContext
function Q($f){
  $s=if($cp){$de=New-Object DirectoryServices.DirectoryEntry("LDAP://$nc",$cp.UserName,$pw);New-Object DirectoryServices.DirectorySearcher($de,$f)}else{New-Object DirectoryServices.DirectorySearcher([adsi]'',$f)}
  $s.PageSize=1000
  [void]$s.PropertiesToLoad.Add('sAMAccountName')
  [void]$s.PropertiesToLoad.Add('objectSid')
  $s.FindAll()
}
$rows=New-Object System.Collections.Generic.List[object]
$skipped=New-Object System.Collections.Generic.List[string]
function Add-Row($risk,$title,$sam,$sid,$detail){
  $rows.Add([pscustomobject]@{Risk=$risk;Title=$title;SamAccountName=$sam;SID=$sid;Detail=$detail})
  Write-Verbose "[$risk] $title :: $sam :: $detail"
}
function Skip-Row($check,$why){$skipped.Add("$check - N/A: $why");Write-Verbose "[-] skipped $check : $why"}
function SidOf($r){
  $b=$r.Properties.objectsid
  if($b -and $b[0]){(New-Object System.Security.Principal.SecurityIdentifier($b[0],0)).Value}else{''}
}
function SchemaHas($attr){
  $p="LDAP://CN=$attr,CN=Schema,CN=Configuration,$cfg"
  try{$null=(New-Object DirectoryServices.DirectoryEntry($p)).Name;return $true}catch{return $false}
}

# ---------- fingerprint ----------
$d=(Q '(objectClass=domainDNS)')[0].Properties
$dflMap=@{0='2000';1='2003';2='2008';3='2008R2';4='2012';5='2012R2';6='2016';7='2019+'}
$dfl=[int]$d.'msds-behavior-version'[0]
$dflName=$dflMap[$dfl]
$dcObjs=@(Q '(&(objectCategory=computer)(primaryGroupID=516))')
$dcNames=@($dcObjs|%{$_.Properties.dnshostname[0]}|?{$_})
$hasLegacyLaps=SchemaHas 'ms-Mcs-AdmPwd'
$hasWinLaps=SchemaHas 'msLAPS-Password'
$pso=@(Q '(objectClass=msDS-PasswordSettings)').Count
"[i] fingerprint: DFL=$dflName ($dfl) | DCs=$($dcNames.Count) | legacyLAPS-schema=$hasLegacyLaps | winLAPS-schema=$hasWinLaps | PSOs=$pso"|Write-Host -ForegroundColor Cyan

# ---------- domain config ----------
$maq=$d.'ms-ds-machineaccountquota'[0]
if($maq -gt 0){
  Add-Row 'Medium' '[APM] - Active Directory - Machine Account Quota' '' '' "ms-DS-MachineAccountQuota=$maq - any domain user can create $maq machine accounts"
  Add-Row 'Medium' 'Authenticated Users can Create Machine Accounts' '' '' "ms-DS-MachineAccountQuota=$maq"
}else{Skip-Row 'Machine Account Quota' "quota=0"}

$mpl=[int]$d.minpwdlength[0]
$mpaRaw=[long]$d.maxpwdage[0]
$minAgeRaw=[long]$d.minpwdage[0]
$minAge=if($minAgeRaw -eq [long]::MinValue){0}else{[int]([math]::Abs($minAgeRaw)/864000000000)}
$lt=[int]$d.lockoutthreshold[0]
$psoNote=if($pso -gt 0){" (NOTE: $pso fine-grained PSO(s) exist - effective policy may differ per group)"}else{''}
if($mpaRaw -eq [long]::MinValue){
  Add-Row 'Medium' 'Domain Account Policy' '' '' "Maximum password age: NEVER EXPIRES; minLength=$mpl minAge=${minAge}d lockoutThreshold=$lt$psoNote"
}else{
  $mpa=[int]([math]::Abs($mpaRaw)/864000000000)
  if($mpl -lt 12 -or $mpa -gt 90 -or $lt -eq 0 -or $minAge -lt 1){
    Add-Row 'Medium' 'Domain Account Policy' '' '' "minLength=$mpl minAge=${minAge}d maxAge=${mpa}d lockoutThreshold=$lt$psoNote"
  }else{Skip-Row 'Domain Account Policy' 'within hardening thresholds'}
}

if($dfl -le 3){Add-Row 'Medium' 'Domain Functional Level' '' '' "msDS-Behavior-Version=$dfl ($dflName) - legacy functional level"}

# recycle bin: gate - feature cannot exist below DFL 2008R2
if($dfl -ge 3){
  $part=if($cp){New-Object DirectoryServices.DirectoryEntry("LDAP://CN=Partitions,$cfg",$cp.UserName,$pw)}else{[adsi]"LDAP://CN=Partitions,$cfg"}
  $ef=@($part.Properties['msDS-EnabledFeature'])
  if(-not($ef|?{$_ -match 'Recycle Bin Feature'})){Add-Row 'Medium' 'Active Directory Recycle Bin Not Enabled' '' '' 'msDS-EnabledFeature on CN=Partitions lacks Recycle Bin Feature'}
  else{Skip-Row 'Recycle Bin' 'feature enabled'}
}else{Skip-Row 'Recycle Bin' "DFL $dflName too low - feature requires 2008R2+"}

$kt=[DateTime]::FromFileTime((Q '(sAMAccountName=krbtgt)')[0].Properties.pwdlastset[0])
if($kt -lt (Get-Date).AddDays(-180)){Add-Row 'High' 'Krbtgt Password Not Changed Regularly' 'krbtgt' '' ("krbtgt pwdLastSet="+$kt.ToString('yyyy-MM-dd')+" - golden ticket exposure window")}
else{Skip-Row 'krbtgt rotation' 'rotated within 180 days'}

# ---------- account hygiene (self-gating: no objects = no rows) ----------
Q '(&(objectCategory=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'High' 'Domain Vulnerable to Kerberoasting' $_.Properties.samaccountname[0] (SidOf $_) 'enabled account with SPN - ticket requestable, offline-crackable'
}
Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'Medium' 'Kerberos Pre-Authentication Disabled' $_.Properties.samaccountname[0] (SidOf $_) 'DONT_REQUIRE_PREAUTH - AS-REP roastable'
}
$nevList=@(Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
$enUsers=@(Q '(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
if($nevList.Count -gt 0){
  $pct=[math]::Round(100*$nevList.Count/[math]::Max($enUsers,1))
  $nevList|%{Add-Row 'Low' '[APM] - Active Directory - Passwords Never Expire' $_.Properties.samaccountname[0] (SidOf $_) "$($nevList.Count) of $enUsers enabled accounts ($pct%) - DONT_EXPIRE_PASSWORD set"}
}
Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))'|%{
  Add-Row 'Medium' '[*] Active Directory - Reversible Password Encryption Enabled' $_.Properties.samaccountname[0] (SidOf $_) 'ENCRYPTED_TEXT_PASSWORD_ALLOWED - passwords recoverable from AD'
}
Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'Medium' '[*] Active Directory - Password Not Required Flag Set' $_.Properties.samaccountname[0] (SidOf $_) 'PASSWD_NOTREQD - account may have a blank password'
}
$da=@((Q "(distinguishedName=CN=Domain Admins,CN=Users,$nc)")[0].Properties.member)
if($da.Count -gt 5){Add-Row 'Medium' 'Large Number of Domain Administrators' '' '' "$($da.Count) members in Domain Admins"}
Q "(&(objectCategory=user)(servicePrincipalName=*)(memberOf=CN=Domain Admins,CN=Users,$nc))"|%{
  Add-Row 'Medium' '[APM] - Active Directory - Service Account with High Privileges' $_.Properties.samaccountname[0] (SidOf $_) 'SPN-bearing account in Domain Admins'
}
Q '(&(objectCategory=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=1048576))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'Medium' 'Account Delegation' $_.Properties.samaccountname[0] (SidOf $_) 'privileged account (adminCount=1) without NOT_DELEGATED - tokens forwardable'
}
Q '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))'|%{
  Add-Row 'Medium' '[*] Active Directory - Unconstrained Delegation Enabled' $_.Properties.samaccountname[0] (SidOf $_) 'TRUSTED_FOR_DELEGATION - host can impersonate any connecting user'
}
$cut90=(Get-Date).AddDays(-90).ToFileTime()
Q "(&(objectCategory=computer)(lastLogonTimestamp<=$cut90)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"|%{
  Add-Row 'Low' 'Inactive Domain Computer Accounts' $_.Properties.samaccountname[0] (SidOf $_) 'no logon in 90+ days (lastLogonTimestamp)'
}
$cut180=(Get-Date).AddDays(-180).ToFileTime()
Q "(&(objectCategory=user)(lastLogonTimestamp<=$cut180)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"|%{
  Add-Row 'Medium' '[APM] - Active Directory - Inactive Accounts' $_.Properties.samaccountname[0] (SidOf $_) 'enabled, no logon in 180+ days'
}
Q '(&(objectCategory=user)(msDS-SupportedEncryptionTypes=*))'|%{
  $e=[int]$_.Properties.'msds-supportedencryptiontypes'[0]
  if($e-band 7){Add-Row 'Low' '[*] Active Directory - Weak Kerberos Encryption Types (RC4/DES)' $_.Properties.samaccountname[0] (SidOf $_) "msDS-SupportedEncryptionTypes=$e includes RC4/DES bits"}
}
Q '(objectCategory=computer)'|%{
  $o=$_.Properties.operatingsystem
  if($o -and $o[0] -match 'Windows (2000|2003|2008|2012)|Windows XP|Windows Vista|Windows (7|8)'){
    Add-Row 'High' '[APM] - Active Directory - Unsupported Operating Systems' $_.Properties.samaccountname[0] (SidOf $_) $o[0]
  }
}
$oldDC=@($dcObjs|%{$o=$_.Properties.operatingsystem;if($o -and $o[0] -match '2000|2003'){"$($_.Properties.name[0]) ($($o[0]))"}})
if($oldDC.Count -gt 0){Add-Row 'Critical' 'Windows 2003 Domain Controllers' '' '' "$($oldDC -join', ')"}

# LAPS: gate on schema presence for honest wording
if(-not $hasLegacyLaps -and -not $hasWinLaps){
  Add-Row 'Medium' '[APM] - Endpoint - LAPS Implementation' '' '' 'schema never extended for LAPS (neither ms-Mcs-AdmPwd nor msLAPS-Password exists) - LAPS not deployed'
}else{
  $lapsLegacy=if($hasLegacyLaps){@(Q '(&(objectCategory=computer)(ms-Mcs-AdmPwd=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count}else{0}
  $lapsWin=if($hasWinLaps){@(Q '(&(objectCategory=computer)(msLAPS-Password=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count}else{0}
  $laps=[math]::Max($lapsLegacy,$lapsWin)
  $allC=@(Q '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
  if($laps -lt $allC){Add-Row 'Medium' '[APM] - Endpoint - LAPS Implementation' '' '' "LAPS on $laps of $allC enabled computers (legacy=$lapsLegacy windowsLAPS=$lapsWin)"}
  else{Skip-Row 'LAPS' "deployed on all $allC computers"}
}

# ---------- DC checks: auto-discovered, or -DC override ----------
$targets=if($DC){$DC}else{$dcNames}
if($targets){
  foreach($t in $targets){
    if(!(Test-Connection $t -Count 1 -Quiet -EA 0)){Skip-Row "DC checks on $t" 'unreachable';continue}
    $lmLine=reg query "\\$t\HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel 2>$null|Select-String 'LmCompatibilityLevel'
    if($lmLine -and $lmLine.Line -match '0x([0-9a-fA-F]+)'){
      $lm=[Convert]::ToInt32($Matches[1],16)
      if($lm -lt 3){Add-Row 'Medium' 'LM and NTLMv1 Authentication Enabled' $t '' "LmCompatibilityLevel=$lm on $t (<3 permits NTLMv1)"}
      else{Skip-Row "LmCompatibilityLevel on $t" "=$lm"}
    }else{Skip-Row "LmCompatibilityLevel on $t" 'value absent - OS default 3 (NTLMv2 only)'}
    $lsLine=reg query "\\$t\HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity 2>$null|Select-String 'LDAPServerIntegrity'
    $ls=1
    if($lsLine -and $lsLine.Line -match '0x([0-9a-fA-F]+)'){$ls=[Convert]::ToInt32($Matches[1],16)}
    if($ls -lt 2){Add-Row 'Low' 'Domain Controller - Enforce LDAP Signing' $t '' "LDAPServerIntegrity=$ls on $t (2=require)"}
    else{Skip-Row "LDAP signing on $t" 'required'}
    if(sc.exe "\\$t" query spooler 2>$null|Select-String 'RUNNING'){Add-Row 'Medium' 'Spooler Service Running on Domain Controllers' $t '' "spooler RUNNING on $t - coerced-auth exposure"}
    else{Skip-Row "spooler on $t" 'not running'}
  }
}else{Skip-Row 'DC registry/service checks' 'no DCs discovered and none supplied'}

if($SysvolLoot -and(Test-Path $SysvolLoot)){
  $gx=Get-Content $SysvolLoot|Select-String 'SYSVOL'|Select-String '\.xml$|\.inf$|\.ps1$|\.bat$|\.vbs$'
  if($gx){Add-Row 'High' 'Passwords in SYSVOL Share' '' '' "$($gx.Count) candidate files in smblist loot - pull and grep for cpassword= / credentials"}
}elseif($SysvolLoot){Skip-Row 'SYSVOL loot grep' "file not found: $SysvolLoot"}

"[i] $($rows.Count) finding rows, $($skipped.Count) checks skipped as N/A"|Write-Host -ForegroundColor Cyan
$rows|Sort-Object Risk,Title|Format-Table Risk,Title,SamAccountName -Auto
if($skipped.Count){"[i] skipped (not applicable to this environment):"|Write-Host -ForegroundColor DarkYellow;$skipped|%{Write-Host "    - $_" -ForegroundColor DarkYellow}}
if($OutFile){$rows|Export-Csv -NoTypeInformation -Path $OutFile;"[i] CSV -> $OutFile"|Write-Host -ForegroundColor Cyan}else{$rows}
}
if($PSCommandPath){Invoke-ADAudit @args}
