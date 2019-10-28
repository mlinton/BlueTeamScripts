<#
 © Tom Asselman
 This script is free to use but please do not reuse or spread without giving credit to the author.
#>



<#
Checks file system for existence of files / directories .
Hidden file's will be included

$File_IOC_List =>  Array with each entry containing file or directory to search for , wildcards are accepted.
                      
                      Example of entries:

                      c:\temp\EvilFile.exe
                      c:\temp
                      c:\Users\*\ntuser.dat
#>

function checkFileIOCs([string[]] $File_IOC_List ){

    "`r`n<<<<<<<<<Checking filesystem " +  $env:COMPUTERNAME + " user : " + $env:USERDOMAIN +'\' + $env:USERNAME + ">>>>>>>>>"

    foreach ($ioc in $File_IOC_List) { 
       try{
             "`r`n*********SCANNING " + $env:COMPUTERNAME + " FOR " + $ioc.ToUpper() + "    ***********"
             Get-ChildItem $ioc -force  -ErrorAction Stop
             "`r`nHIT FOUND !`r`n" 
        }
        catch{
            #do nothing , just to hide errors from the screen
        }
    }
}


<#
 Reg_IOC_List =>      Array with each entry containing registry key (wildcards are accepted in the keyname) and optionally a value (no wildcards allowed here) to search for in that key.
                      
                      Keys and values need to be seperated by a TAB character.
                      You need to give the powershell notation for the registry keys 

                      Example:
                      HKLM:SOFTWARE\7-Zip   Path
                       
                       --> checks whether value Path exists for a key HKLM:SOFTWARE\7-Zip on the system

                      HKLM:SOFTWARE\*\IBM
                       
                       --> example of wildcard use , NO value specified

                      HKCU:Software\Microsoft\Windows\CurrentVersion\Run\   EvilPersistenceValue

                       --> Checks if EvilPersistenceValue appears in Software\Microsoft\Windows\CurrentVersion\Run\ 
                           in the user hive of the user executing the script !! 
                           Next blog post will include version that scans users registry of ALL the users on the remote machine.
#>
function checkRegIOCs([string[]] $Reg_IOC_List ){

    "`r`n<<<<<<<<<Checking registry " +  $env:COMPUTERNAME + " as user : " + $env:USERDOMAIN +'\' + $env:USERNAME + ">>>>>>>>>"

     foreach ($ioc in $Reg_IOC_List) { 
       try{
             #split Using tab as delimmiter
             $regKey ,$regValue= $ioc.split("`t",2)
             
             #check if key ends on "\" else add it , otherwise lookups may not be correct
             if (-not $regKey.EndsWith("\")){
                 $regKey+= '\'
             }

             "`r`n*********SCANNING " + $env:COMPUTERNAME + " FOR -  Reg Key: " + $regKey.ToUpper() + "  - Value : "+ $regValue +" **********"
             if($regValue -eq $null){
                #If no Reg value specified (only a key)
                ($foundValue = Get-ChildItem $regKey -force  -ErrorAction Stop)
                if ( $foundValue -eq $null) {
                    # If it's a key with no more subkeys we need to use Get-ItemProperty to list any values
                    ($foundValue = Get-ItemProperty -ErrorAction stop $regKey)
                    #no values found ?
                    if ( $foundValue -eq $null) {
                        Write-Error("No Hit") -ErrorAction stop
                    }
                } 
                
             }
             else{
                 #Reg Key + value specified
                 ($foundValue = Get-ItemProperty -ErrorAction stop $regKey   | Select-Object -ExpandProperty $regValue -ErrorAction stop)
                 if ( $foundValue -eq $null) {Write-Error("No Hit") -ErrorAction stop}
             }
             "`r`nHIT FOUND !" 
        }
        catch{
            #do nothing , just to hide errors from the screen
            
        }
    }
}
