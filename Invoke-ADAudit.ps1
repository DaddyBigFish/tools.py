function Invoke-ADAudit{
[CmdletBinding()]
param([switch]$h,[string[]]$DC,[string]$SysvolLoot,[string]$OutFile="adaudit_$(Get-Date -f yyyyMMdd_HHmmss).xlsx",[pscredential]$Credential)
if($h){@'
Invoke-ADAudit - read-only native AD findings collector (maps to ptdash findings-templates, FP-audited)

usage:
  Invoke-ADAudit                      fingerprint env, run applicable checks, write adaudit_<timestamp>.xlsx
  Invoke-ADAudit -DC DC01,DC02        override DC auto-discovery for registry/service checks
  Invoke-ADAudit -SysvolLoot x.txt    + grep smblist output for SYSVOL files (GPP lane)
  Invoke-ADAudit -OutFile ''          emit objects to pipeline instead of xlsx

load from URL:
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/USER/REPO/main/Invoke-ADAudit.ps1')
  Invoke-ADAudit -Verbose

output:
  .xlsx workbook - one tab per finding (31-char-safe names), one row per affected object
  columns: Risk | SamAccountName | SID | ObjectGUID | Detail
  terminal shows summary + skipped-check ledger only; all data goes to the file
  LAPS proof uses world-readable ExpirationTime attributes (password attrs are confidential)
'@;return}
$cp=$Credential
$pw=if($cp){$cp.GetNetworkCredential().Password}
$root=if($cp){New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE',$cp.UserName,$pw)}else{[adsi]'LDAP://RootDSE'}
$nc=$root.defaultNamingContext
$cfg=$root.configurationNamingContext
function Q($f){
  $s=if($cp){$de=New-Object DirectoryServices.DirectoryEntry("LDAP://$nc",$cp.UserName,$pw);New-Object DirectoryServices.DirectorySearcher($de,$f)}else{New-Object DirectoryServices.DirectorySearcher([adsi]'',$f)}
  $s.PageSize=1000
  $s.FindAll()
}
$rows=New-Object System.Collections.Generic.List[object]
$skipped=New-Object System.Collections.Generic.List[string]
function Add-Row($risk,$title,$sam,$sid,$guid,$detail){
  $rows.Add([pscustomobject]@{Risk=$risk;Title=$title;SamAccountName=$sam;SID=$sid;ObjectGUID=$guid;Detail=$detail})
  Write-Verbose "[$risk] $title :: $sam :: $detail"
}
function Skip-Row($check,$why){$skipped.Add("$check - N/A: $why");Write-Verbose "[-] skipped $check : $why"}
function SidOf($r){
  $b=$r.Properties.objectsid
  if($b -and $b[0]){(New-Object System.Security.Principal.SecurityIdentifier($b[0],0)).Value}else{''}
}
function GuidOf($r){
  $b=$r.Properties.objectguid
  if($b -and $b[0]){(New-Object Guid(,$b[0])).Guid}else{''}
}
function SchemaHas($attr){
  $p="LDAP://CN=$attr,CN=Schema,CN=Configuration,$cfg"
  try{$null=(New-Object DirectoryServices.DirectoryEntry($p)).Name;return $true}catch{return $false}
}
# ---------- xlsx writer (pure zip+xml, no Excel/modules) ----------
$sheetNames=@{
 '[APM] - Active Directory - Machine Account Quota'='Machine Account Quota'
 'Authenticated Users can Create Machine Accounts'='Users Create Machine Accts'
 'Domain Account Policy'='Domain Account Policy'
 'Domain Functional Level'='Domain Functional Level'
 'Active Directory Recycle Bin Not Enabled'='Recycle Bin Not Enabled'
 'Krbtgt Password Not Changed Regularly'='krbtgt Not Rotated'
 'Domain Vulnerable to Kerberoasting'='Kerberoasting'
 'Kerberos Pre-Authentication Disabled'='Pre-Auth Disabled (AS-REP)'
 '[APM] - Active Directory - Passwords Never Expire'='Passwords Never Expire'
 '[*] Active Directory - Reversible Password Encryption Enabled'='Reversible Encryption'
 '[*] Active Directory - Password Not Required Flag Set'='Password Not Required'
 'Large Number of Domain Administrators'='Excessive Domain Admins'
 '[APM] - Active Directory - Service Account with High Privileges'='Privileged Service Accounts'
 'Account Delegation'='Privileged Acct Delegation'
 '[*] Active Directory - Unconstrained Delegation Enabled'='Unconstrained Delegation'
 'Inactive Domain Computer Accounts'='Inactive Computers'
 '[APM] - Active Directory - Inactive Accounts'='Inactive Users'
 '[*] Active Directory - Weak Kerberos Encryption Types (RC4/DES)'='Weak Kerberos Encryption'
 '[APM] - Active Directory - Unsupported Operating Systems'='Unsupported OS'
 'Windows 2003 Domain Controllers'='Windows 2003 DCs'
 '[APM] - Endpoint - LAPS Implementation'='LAPS Implementation'
 'LM and NTLMv1 Authentication Enabled'='LM NTLMv1 Enabled'
 'Domain Controller - Enforce LDAP Signing'='LDAP Signing Not Enforced'
 'Spooler Service Running on Domain Controllers'='Spooler on DCs'
 'Passwords in SYSVOL Share'='Passwords in SYSVOL'
}
function XEsc($s){if($null -eq $s){return ''};("$s" -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;')}
function CellRef($col,$row){[char](65+$col)+([string]$row)}
function Export-FindingsXlsx($rows,$path){
  Add-Type -AssemblyName System.IO.Compression
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $riskRank=@{Critical=0;High=1;Medium=2;Low=3;Informational=4}
  $groups=$rows|Group-Object Title|Sort-Object {$riskRank[$_.Group[0].Risk]},Name
  if(Test-Path $path){Remove-Item $path -Force}
  $fs=[System.IO.File]::Open($path,'Create')
  $zip=New-Object System.IO.Compression.ZipArchive($fs,[System.IO.Compression.ZipArchiveMode]::Create)
  function Put($name,$text){
    $e=$zip.CreateEntry($name)
    $w=New-Object System.IO.StreamWriter($e.Open(),[Text.Encoding]::UTF8)
    $w.Write($text);$w.Flush();$w.Dispose()
  }
  $n=$groups.Count
  $ct='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
  1..$n|%{$ct+="<Override PartName=`"/xl/worksheets/sheet$_.xml`" ContentType=`"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml`"/>"}
  $ct+='</Types>'
  Put '[Content_Types].xml' $ct
  Put '_rels/.rels' '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
  $wb='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
  $used=@{}
  $i=0
  $tabFor=@{}
  foreach($g in $groups){
    $i++
    $tab=$sheetNames[$g.Name]
    if(-not $tab){$tab=($g.Name -replace '\[.*?\]\s*-\s*','') -replace '[\[\]\:\*\?\/\\]',''}
    $tab=$tab.Trim();if($tab.Length -gt 31){$tab=$tab.Substring(0,31)}
    $base=$tab;$k=1
    while($used.ContainsKey($tab)){$sfx=" ($k)";$tab=$base;if($tab.Length -gt (31-$sfx.Length)){$tab=$tab.Substring(0,31-$sfx.Length)};$tab+=$sfx;$k++}
    $used[$tab]=1;$tabFor[$g.Name]=$tab
    $wb+="<sheet name=`"$(XEsc $tab)`" sheetId=`"$i`" r:id=`"rId$i`"/>"
  }
  $wb+='</sheets></workbook>'
  Put 'xl/workbook.xml' $wb
  $rels='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
  1..$n|%{$rels+="<Relationship Id=`"rId$_`" Type=`"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet`" Target=`"worksheets/sheet$_.xml`"/>"}
  $rels+='</Relationships>'
  Put 'xl/_rels/workbook.xml.rels' $rels
  $i=0
  foreach($g in $groups){
    $i++
    $sx='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
    $hdr=@('Risk','SamAccountName','SID','ObjectGUID','Detail')
    $sx+='<row r="1">'
    0..4|%{$sx+="<c r=`"$(CellRef $_ 1)`" t=`"inlineStr`"><is><t>$(XEsc $hdr[$_])</t></is></c>"}
    $sx+='</row>'
    $r=1
    foreach($o in $g.Group){
      $r++
      $vals=@($o.Risk,$o.SamAccountName,$o.SID,$o.ObjectGUID,$o.Detail)
      $sx+="<row r=`"$r`">"
      0..4|%{$sx+="<c r=`"$(CellRef $_ $r)`" t=`"inlineStr`"><is><t>$(XEsc $vals[$_])</t></is></c>"}
      $sx+='</row>'
    }
    $sx+='</sheetData></worksheet>'
    Put "xl/worksheets/sheet$i.xml" $sx
  }
  $zip.Dispose();$fs.Dispose()
  return $tabFor
}

# ---------- fingerprint ----------
$domRes=Q '(objectClass=domainDNS)'
if(!$domRes -or $domRes.Count -eq 0){throw "LDAP returned nothing for domainDNS - are you domain-authenticated? (runas /netonly or -Credential)"}
$d=$domRes[0].Properties
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
  Add-Row 'Medium' '[APM] - Active Directory - Machine Account Quota' '' '' '' "ms-DS-MachineAccountQuota=$maq - any domain user can create $maq machine accounts"
  Add-Row 'Medium' 'Authenticated Users can Create Machine Accounts' '' '' '' "ms-DS-MachineAccountQuota=$maq"
}else{Skip-Row 'Machine Account Quota' "quota=0"}

$mpl=[int]$d.minpwdlength[0]
$mpaRaw=[long]$d.maxpwdage[0]
$minAgeRaw=[long]$d.minpwdage[0]
$minAge=if($minAgeRaw -eq [long]::MinValue){0}else{[int]([math]::Abs($minAgeRaw)/864000000000)}
$lt=[int]$d.lockoutthreshold[0]
$psoNote=if($pso -gt 0){" (NOTE: $pso fine-grained PSO(s) exist - effective policy may differ per group)"}else{''}
if($mpaRaw -eq [long]::MinValue){
  Add-Row 'Medium' 'Domain Account Policy' '' '' '' "Maximum password age: NEVER EXPIRES; minLength=$mpl minAge=${minAge}d lockoutThreshold=$lt$psoNote"
}else{
  $mpa=[int]([math]::Abs($mpaRaw)/864000000000)
  if($mpl -lt 12 -or $mpa -gt 90 -or $lt -eq 0 -or $minAge -lt 1){
    Add-Row 'Medium' 'Domain Account Policy' '' '' '' "minLength=$mpl minAge=${minAge}d maxAge=${mpa}d lockoutThreshold=$lt$psoNote"
  }else{Skip-Row 'Domain Account Policy' 'within hardening thresholds'}
}

if($dfl -le 3){Add-Row 'Medium' 'Domain Functional Level' '' '' '' "msDS-Behavior-Version=$dfl ($dflName) - legacy functional level"}

if($dfl -ge 3){
  $part=if($cp){New-Object DirectoryServices.DirectoryEntry("LDAP://CN=Partitions,$cfg",$cp.UserName,$pw)}else{[adsi]"LDAP://CN=Partitions,$cfg"}
  $ef=@($part.Properties['msDS-EnabledFeature'])
  if(-not($ef|?{$_ -match 'Recycle Bin Feature'})){Add-Row 'Medium' 'Active Directory Recycle Bin Not Enabled' '' '' '' 'msDS-EnabledFeature on CN=Partitions lacks Recycle Bin Feature'}
  else{Skip-Row 'Recycle Bin' 'feature enabled'}
}else{Skip-Row 'Recycle Bin' "DFL $dflName too low - feature requires 2008R2+"}

$ktR=(Q '(sAMAccountName=krbtgt)')[0]
$kt=[DateTime]::FromFileTime($ktR.Properties.pwdlastset[0])
if($kt -lt (Get-Date).AddDays(-180)){Add-Row 'High' 'Krbtgt Password Not Changed Regularly' 'krbtgt' (SidOf $ktR) (GuidOf $ktR) ("krbtgt pwdLastSet="+$kt.ToString('yyyy-MM-dd')+" - golden ticket exposure window")}
else{Skip-Row 'krbtgt rotation' 'rotated within 180 days'}

# ---------- account hygiene (self-gating) ----------
Q '(&(objectCategory=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'High' 'Domain Vulnerable to Kerberoasting' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'enabled account with SPN - ticket requestable, offline-crackable'
}
Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'Medium' 'Kerberos Pre-Authentication Disabled' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'DONT_REQUIRE_PREAUTH - AS-REP roastable'
}
$nevList=@(Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
$enUsers=@(Q '(&(objectCategory=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
if($nevList.Count -gt 0){
  $pct=[math]::Round(100*$nevList.Count/[math]::Max($enUsers,1))
  $nevList|%{Add-Row 'Low' '[APM] - Active Directory - Passwords Never Expire' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) "$($nevList.Count) of $enUsers enabled accounts ($pct%) - DONT_EXPIRE_PASSWORD set"}
}
Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))'|%{
  Add-Row 'Medium' '[*] Active Directory - Reversible Password Encryption Enabled' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'ENCRYPTED_TEXT_PASSWORD_ALLOWED - passwords recoverable from AD'
}
Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'Medium' '[*] Active Directory - Password Not Required Flag Set' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'PASSWD_NOTREQD - account may have a blank password'
}
$da=@((Q "(distinguishedName=CN=Domain Admins,CN=Users,$nc)")[0].Properties.member)
if($da.Count -gt 5){Add-Row 'Medium' 'Large Number of Domain Administrators' '' '' '' "$($da.Count) members in Domain Admins"}
Q "(&(objectCategory=user)(servicePrincipalName=*)(memberOf=CN=Domain Admins,CN=Users,$nc))"|%{
  Add-Row 'Medium' '[APM] - Active Directory - Service Account with High Privileges' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'SPN-bearing account in Domain Admins'
}
Q '(&(objectCategory=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=1048576))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{
  Add-Row 'Medium' 'Account Delegation' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'privileged account (adminCount=1) without NOT_DELEGATED - tokens forwardable'
}
Q '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))'|%{
  Add-Row 'Medium' '[*] Active Directory - Unconstrained Delegation Enabled' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'TRUSTED_FOR_DELEGATION - host can impersonate any connecting user'
}
$cut90=(Get-Date).AddDays(-90).ToFileTime()
Q "(&(objectCategory=computer)(lastLogonTimestamp<=$cut90)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"|%{
  Add-Row 'Low' 'Inactive Domain Computer Accounts' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'no logon in 90+ days (lastLogonTimestamp)'
}
$cut180=(Get-Date).AddDays(-180).ToFileTime()
Q "(&(objectCategory=user)(lastLogonTimestamp<=$cut180)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"|%{
  Add-Row 'Medium' '[APM] - Active Directory - Inactive Accounts' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) 'enabled, no logon in 180+ days'
}
Q '(&(objectCategory=user)(msDS-SupportedEncryptionTypes=*))'|%{
  $e=[int]$_.Properties.'msds-supportedencryptiontypes'[0]
  if($e-band 7){Add-Row 'Low' '[*] Active Directory - Weak Kerberos Encryption Types (RC4/DES)' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) "msDS-SupportedEncryptionTypes=$e includes RC4/DES bits"}
}
Q '(objectCategory=computer)'|%{
  $o=$_.Properties.operatingsystem
  if($o -and $o[0] -match 'Windows (2000|2003|2008|2012)|Windows XP|Windows Vista|Windows (7|8)'){
    Add-Row 'High' '[APM] - Active Directory - Unsupported Operating Systems' $_.Properties.samaccountname[0] (SidOf $_) (GuidOf $_) $o[0]
  }
}
$oldDC=@($dcObjs|%{$o=$_.Properties.operatingsystem;if($o -and $o[0] -match '2000|2003'){"$($_.Properties.name[0]) ($($o[0]))"}})
if($oldDC.Count -gt 0){Add-Row 'Critical' 'Windows 2003 Domain Controllers' '' '' '' "$($oldDC -join', ')"}

# LAPS - counts WORLD-READABLE ExpirationTime attrs (password attrs are confidential = unreadable = FP trap)
if(-not $hasLegacyLaps -and -not $hasWinLaps){
  Add-Row 'Medium' '[APM] - Endpoint - LAPS Implementation' '' '' '' 'schema never extended for LAPS (no ms-Mcs-AdmPwd / msLAPS attributes) - LAPS not deployed'
}else{
  $lapsLegacy=@(Q '(&(objectCategory=computer)(ms-Mcs-AdmPwdExpirationTime=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
  $lapsWin=@(Q '(&(objectCategory=computer)(msLAPS-PasswordExpirationTime=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
  $laps=[math]::Max($lapsLegacy,$lapsWin)
  $allC=@(Q '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
  if($laps -lt $allC){Add-Row 'Medium' '[APM] - Endpoint - LAPS Implementation' '' '' '' "LAPS active on $laps of $allC enabled computers (legacy=$lapsLegacy windowsLAPS=$lapsWin, measured via readable ExpirationTime attributes)"}
  else{Skip-Row 'LAPS' "active on all $allC computers"}
}

# ---------- DC checks ----------
$targets=if($DC){$DC}else{$dcNames}
if($targets){
  foreach($t in $targets){
    if(!(Test-Connection $t -Count 1 -Quiet -EA 0)){Skip-Row "DC checks on $t" 'unreachable';continue}
    $lmLine=reg query "\\$t\HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel 2>$null|Select-String 'LmCompatibilityLevel'
    if($lmLine -and $lmLine.Line -match '0x([0-9a-fA-F]+)'){
      $lm=[Convert]::ToInt32($Matches[1],16)
      if($lm -lt 3){Add-Row 'Medium' 'LM and NTLMv1 Authentication Enabled' $t '' '' "LmCompatibilityLevel=$lm on $t (<3 permits NTLMv1)"}
      else{Skip-Row "LmCompatibilityLevel on $t" "=$lm"}
    }else{Skip-Row "LmCompatibilityLevel on $t" 'value absent - OS default 3 (NTLMv2 only)'}
    $lsLine=reg query "\\$t\HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity 2>$null|Select-String 'LDAPServerIntegrity'
    $ls=1
    if($lsLine -and $lsLine.Line -match '0x([0-9a-fA-F]+)'){$ls=[Convert]::ToInt32($Matches[1],16)}
    if($ls -lt 2){Add-Row 'Low' 'Domain Controller - Enforce LDAP Signing' $t '' '' "LDAPServerIntegrity=$ls on $t (2=require)"}
    else{Skip-Row "LDAP signing on $t" 'required'}
    if(sc.exe "\\$t" query spooler 2>$null|Select-String 'RUNNING'){Add-Row 'Medium' 'Spooler Service Running on Domain Controllers' $t '' '' "spooler RUNNING on $t - coerced-auth exposure"}
    else{Skip-Row "spooler on $t" 'not running'}
  }
}else{Skip-Row 'DC registry/service checks' 'no DCs discovered and none supplied'}

if($SysvolLoot -and(Test-Path $SysvolLoot)){
  $gx=Get-Content $SysvolLoot|Select-String 'SYSVOL'|Select-String '\.xml$|\.inf$|\.ps1$|\.bat$|\.vbs$'
  if($gx){Add-Row 'High' 'Passwords in SYSVOL Share' '' '' '' "$($gx.Count) candidate files in smblist loot - pull and grep for cpassword= / credentials"}
}elseif($SysvolLoot){Skip-Row 'SYSVOL loot grep' "file not found: $SysvolLoot"}

# ---------- output: summary to terminal, data to file ----------
"[i] $($rows.Count) evidence rows across $(@($rows|Group-Object Title).Count) findings, $($skipped.Count) checks skipped as N/A"|Write-Host -ForegroundColor Cyan
$rows|Group-Object Title|Sort-Object Name|%{"[{0}] {1} - {2} row(s)" -f $_.Group[0].Risk,$_.Name,$_.Count}|Write-Host
if($skipped.Count){"[i] skipped (not applicable):"|Write-Host -ForegroundColor DarkYellow;$skipped|%{Write-Host "    - $_" -ForegroundColor DarkYellow}}
if($OutFile){
  $tabs=Export-FindingsXlsx $rows $OutFile
  "[i] workbook -> $OutFile ($($tabs.Count) tabs)"|Write-Host -ForegroundColor Cyan
}else{$rows}
}
if($PSCommandPath){Invoke-ADAudit @args}
