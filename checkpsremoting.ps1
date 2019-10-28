#CheckPsRemoting.ps1
#© Tom Asselman
#

[CmdletBinding()]
#One mandatory parameter, the hostfile we’re going to test
#Each line has one hostname or ip address 
#Warning no error checking , we assume the file to be correct
Param(
   [ Parameter(Mandatory=$True,Position=1)]
   [string]$hostFile
)

# IF our output file exists we remove it
$outputFile = "Ps-Remoting-Enabled-Hosts.txt"
If (Test-Path $outputFile){
    Remove-Item $outputFile
}

Write-Host "Checking for Ps-Remoting enabled hosts : "
# For all the entries in hostlist .
get-content $hostFile | ForEach-Object{
    $machine = $_
    try{
        Write-Host $machine
        #Remote execution on $machine , -ErrorAction Stop used for neatly handling errors in try catch block
        Invoke-Command -ComputerName $machine -ScriptBlock{Write-Host " - PS Remoting Enabled" } -ErrorAction Stop
        Add-Content $outputFile $machine
    }
    catch{
        Write-Host "PS Remoting Failed " 
    }
}
Write-Host "Test Finished." 
