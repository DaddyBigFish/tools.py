# Simple script to check drivers in C:\windows\system32\drivers against the loldrivers list
# Author: Oddvar Moe - @oddvar.moe

$drivers = get-childitem -Path c:\windows\system32\drivers
$web_client = new-object system.net.webclient
$jsonString = $web_client.DownloadString("https://www.loldrivers.io/api/drivers.json")
$jsonString = $jsonString -replace '"INIT"','"init"'
$jsonString = $jsonString -replace '"PAGE"','"page"'
$loldrivers = $jsonString | ConvertFrom-Json

Write-output("Checking {0} drivers in C:\windows\system32\drivers against loldrivers.io json file" -f $drivers.Count)
foreach ($lol in $loldrivers.KnownVulnerableSamples)
{
    # Check for matching driver name
    if($drivers.Name -contains $lol.Filename)
    {
        #CHECK HASH
        $Hash = Get-FileHash -Path "c:\windows\system32\drivers\$($lol.Filename)"
        if($lol.Sha256 -eq $Hash.Hash)
        {
            write-output("The drivername {0} is vulnerable with a matching SHA256 hash of {1}" -f $lol.Filename, $lol.SHA256)
        }
    }
}
