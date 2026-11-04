function Invoke-ADAudit{
[CmdletBinding()]
param([switch]$h,[string]$DC,[string]$SysvolLoot,[string]$OutFile="adaudit_$(Get-Date -f yyyyMMdd_HHmmss).txt",[pscredential]$Credential)
if($h){@'
Invoke-ADAudit - read-only native AD findings collector (maps to ptdash findings-templates)

usage:
  Invoke-ADAudit                      all LDAP checks, writes adaudit_<timestamp>.txt
  Invoke-ADAudit -DC DC01             + DC registry/service checks (LmCompat, LDAP signing, spooler)
  Invoke-ADAudit -SysvolLoot x.txt    + grep smblist output for SYSVOL xml (GPP lane)
  Invoke-ADAudit -OutFile ''          pipeline only

load from URL:
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/USER/REPO/main/Invoke-ADAudit.ps1')
  Invoke-ADAudit -Verbose

output lines: [Risk] Exact Template Title :: evidence   - paste straight into findings.md
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
function Emit($risk,$title,$ev){
  $l="[$risk] $title :: $ev"
  if($OutFile){$l|Add-Content $OutFile}else{$l}
  Write-Verbose $l
}
$d=(Q '(objectClass=domainDNS)')[0].Properties
$maq=$d.'ms-ds-machineaccountquota'[0]
if($maq -gt 0){Emit 'Medium' '[APM] - Active Directory - Machine Account Quota' "ms-DS-MachineAccountQuota=$maq - any user can join $maq machines"}
if($maq -gt 0){Emit 'Medium' 'Authenticated Users can Create Machine Accounts' "quota=$maq"}
$mpl=$d.minpwdlength[0]
$mpa=[int]([math]::Abs($d.maxpwdage[0])/864000000000)
$lt=$d.lockoutthreshold[0]
if($mpl -lt 12 -or $mpa -gt 90 -or $lt -eq 0){Emit 'Medium' 'Domain Account Policy' "minLength=$mpl maxAge=${mpa}d lockoutThreshold=$lt"}
$dflMap=@{0='2000';1='2003';2='2008';3='2008R2';4='2012';5='2012R2';6='2016';7='2019+'}
$dfl=[int]$d.'msds-behavior-version'[0]
$dflName=$dflMap[$dfl]
if($dfl -lt 6){Emit 'Medium' 'Domain Functional Level' "msDS-Behavior-Version=$dfl ($dflName)"}
$rb=Q "(cn=recycle bin feature,cn=optional features,cn=directory service,cn=windows nt,cn=services,$cfg)"
if(!$rb){Emit 'Medium' 'Active Directory Recycle Bin Not Enabled' 'msDS-EnabledFeature absent'}
$kt=[DateTime]::FromFileTime((Q '(sAMAccountName=krbtgt)')[0].Properties.pwdlastset[0])
if($kt -lt (Get-Date).AddDays(-180)){Emit 'High' 'Krbtgt Password Not Changed Regularly' ("krbtgt pwdLastSet="+$kt.ToString('yyyy-MM-dd'))}
$roast=@(Q '(&(objectCategory=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{$_.Properties.samaccountname[0]})
if($roast.Count -gt 0){Emit 'High' 'Domain Vulnerable to Kerberoasting' "$($roast.Count) SPN accounts: $($roast -join', ')"}
$asrep=@(Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{$_.Properties.samaccountname[0]})
if($asrep.Count -gt 0){Emit 'Medium' 'Kerberos Pre-Authentication Disabled' "$($asrep.Count) accounts: $($asrep -join', ')"}
$nev=@(Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
if($nev -gt 0){Emit 'Low' '[APM] - Active Directory - Passwords Never Expire' "$nev accounts"}
$rev=@(Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=128))'|%{$_.Properties.samaccountname[0]})
if($rev.Count -gt 0){Emit 'Medium' 'Insecure Password Policies' "$($rev.Count) reversible-encryption accounts: $($rev -join', ')"}
$pnr=@(Q '(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'|%{$_.Properties.samaccountname[0]})
if($pnr.Count -gt 0){Emit 'High' 'Weak Domain User Passwords' "$($pnr.Count) PASSWD_NOTREQD: $($pnr -join', ')"}
$da=@(Q "(distinguishedName=CN=Domain Admins,CN=Users,$nc)")[0].Properties.member
if($da.Count -gt 5){Emit 'Medium' 'Large Number of Domain Administrators' "$($da.Count) members"}
$svcDA=@(Q "(&(objectCategory=user)(servicePrincipalName=*)(memberOf=CN=Domain Admins,CN=Users,$nc))"|%{$_.Properties.samaccountname[0]})
if($svcDA.Count -gt 0){Emit 'Medium' '[APM] - Active Directory - Service Account with High Privileges' "$($svcDA -join', ')"}
$unc=@(Q '(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))'|%{$_.Properties.name[0]})
if($unc.Count -gt 0){Emit 'Medium' 'Account Delegation' "unconstrained: $($unc -join', ')"}
$cut=(Get-Date).AddDays(-90).ToFileTime()
$stC=@(Q "(&(objectCategory=computer)(lastLogonTimestamp<=$cut)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))").Count
if($stC -gt 0){Emit 'Low' 'Inactive Domain Computer Accounts' "$stC stale 90d+"}
$stU=@(Q "(&(objectCategory=user)(lastLogonTimestamp<=$cut)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))").Count
if($stU -gt 0){Emit 'Medium' '[APM] - Active Directory - Inactive Accounts' "$stU stale users 90d+"}
$weak=@(Q '(&(objectCategory=user)(msDS-SupportedEncryptionTypes=*))'|%{$e=$_.Properties.'msds-supportedencryptiontypes'[0];if($e-band 7){$_.Properties.samaccountname[0]}})
if($weak.Count -gt 0){Emit 'Low' 'Weak Kerberos Encryption Types Supported' "$($weak.Count) RC4/DES: $($weak -join', ')"}
$oldOS=@(Q '(objectCategory=computer)'|%{$o=$_.Properties.operatingsystem;if($o-and$o[0]-match'2000|2003|2008[^R]|XP|Vista|Windows 7'){"$($_.Properties.name[0]) ($($o[0]))"}})
if($oldOS.Count -gt 0){Emit 'High' '[APM] - Active Directory - Unsupported Operating Systems' "$($oldOS.Count): $($oldOS -join', ')"}
$oldDC=@(Q '(&(objectCategory=computer)(primaryGroupID=516))'|%{$o=$_.Properties.operatingsystem;if($o-and$o[0]-match'2000|2003'){"$($_.Properties.name[0]) ($($o[0]))"}})
if($oldDC.Count -gt 0){Emit 'Critical' 'Windows 2003 Domain Controllers' "$($oldDC -join', ')"}
$laps=@(Q '(&(objectCategory=computer)(ms-Mcs-AdmPwd=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
$allC=@(Q '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))').Count
if($laps -lt $allC){Emit 'Medium' '[APM] - Endpoint - LAPS Implementation' "LAPS on $laps/$allC computers"}
$trusts=@(Q '(objectClass=trustedDomain)'|%{$_.Properties.trustpartner[0]})
if($trusts.Count -gt 0){Emit 'Medium' '[APM] - Active Directory - Weak Domain ACLs' "review trusts: $($trusts -join', ')"}
if($DC){
  $lmLine=reg query "\\$DC\HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel 2>$null|Select-String 'LmCompatibilityLevel'
  $lm=0
  if($lmLine -and $lmLine.Line -match '0x([0-9a-fA-F]+)'){$lm=[Convert]::ToInt32($Matches[1],16)}
  if($lm -lt 3){Emit 'Medium' 'LM and NTLMv1 Authentication Enabled' "LmCompatibilityLevel=$lm on $DC"}
  $lsLine=reg query "\\$DC\HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity 2>$null|Select-String 'LDAPServerIntegrity'
  $ls=0
  if($lsLine -and $lsLine.Line -match '0x([0-9a-fA-F]+)'){$ls=[Convert]::ToInt32($Matches[1],16)}
  if($ls -lt 2){Emit 'Low' 'Domain Controller - Enforce LDAP Signing' "LDAPServerIntegrity=$ls on $DC"}
  if(sc.exe "\\$DC" query spooler 2>$null|Select-String 'RUNNING'){Emit 'Medium' 'Spooler Service Running on Domain Controllers' "spooler RUNNING on $DC"}
}
if($SysvolLoot -and(Test-Path $SysvolLoot)){
  $gx=Get-Content $SysvolLoot|Select-String 'SYSVOL'|Select-String '\.xml$|\.inf$|\.ps1$|\.bat$|\.vbs$'
  if($gx){Emit 'High' 'Passwords in SYSVOL Share' "$($gx.Count) candidate files - pull and grep cpassword="}
}
"[i] done -> $(if($OutFile){$OutFile}else{'pipeline'})"|Write-Host -ForegroundColor Cyan
}
if($PSCommandPath){Invoke-ADAudit @args}
