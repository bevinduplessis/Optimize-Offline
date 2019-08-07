<#
.SYNOPSIS
    Sets a known folder's path using SHSetKnownFolderPath.
.PARAMETER Folder
    The known folder whose path to set.
.PARAMETER Path
    The path.
#>
function Set-KnownFolderPath {
    Param (
            [Parameter(Mandatory = $true)]
            [ValidateSet('Desktop', 'Documents', 'Downloads','Music','Pictures','Videos')]
            [string]$KnownFolder,

            [Parameter(Mandatory = $true)]
            [string]$Path
    )

    # Define known folder GUIDs
    $KnownFolders = @{
        'Desktop' = @('B4BFCC3A-DB2C-424C-B029-7FE99A87C641');
        'Documents' = @('FDD39AD0-238F-46AF-ADB4-6C85480369C7','f42ee2d3-909f-4907-8871-4c22fc0bf756');
        'Downloads' = @('374DE290-123F-4565-9164-39C4925E467B','7d83ee9b-2244-4e70-b1f5-5393042af1e4');
        'Music' = @('4BD8D571-6D19-48D3-BE97-422220080E43','a0c69a99-21c8-4671-8703-7934162fcf1d');
        'Pictures' = @('33E28130-4E1E-4676-835A-98395C3BC3BB','0ddd015d-b06c-45d5-8c4c-f59713854639');
        'Videos' = @('18989B1D-99B5-455B-841C-AB7C74E4DDFC','35286a68-3c57-41a1-bbb1-0eae73d76c95');
    }

    # Define SHSetKnownFolderPath if it hasn't been defined already
    $Type = ([System.Management.Automation.PSTypeName]'KnownFolders').Type
    if (-not $Type) {
        $Signature = @'
[DllImport("shell32.dll")]
public extern static int SHSetKnownFolderPath(ref Guid folderId, uint flags, IntPtr token, [MarshalAs(UnmanagedType.LPWStr)] string path);
'@
        $Type = Add-Type -MemberDefinition $Signature -Name 'KnownFolders' -Namespace 'SHSetKnownFolderPath' -PassThru
    }

	# Make path, if doesn't exist
	  if(!(Test-Path $Path -PathType Container)) {
		  New-Item -Path $Path -type Directory -Force
    }

    # Validate the path
    if (Test-Path $Path -PathType Container) {
        # Call SHSetKnownFolderPath
        foreach ($guid in $KnownFolders[$KnownFolder]) {
            $result = $Type::SHSetKnownFolderPath([ref]$guid, 0, 0, $Path)
            if ($result -ne 0) {
                $errormsg = "Error redirecting $($KnownFolder). Return code $($result) = $((New-Object System.ComponentModel.Win32Exception($result)).message)"
                throw $errormsg
            }
        }
    } else {
        Throw New-Object -TypeName System.IO.DirectoryNotFoundException -ArgumentList "Could not find part of the path $Path."
    }
	
	# Fix up permissions, if we're still here
	attrib +r $Path

	$Leaf = Split-Path -Path "$Path" -Leaf
	# Move-Item "$HOME\$Leaf\*" $Path
	# rd $HOME\$Leaf -recurse -Force

}

$ONEDRIVESYNC = "$env:USERPROFILE\OneDrive - Edgespace"

# Root Folders
Set-KnownFolderPath -KnownFolder 'Documents' -Path "$ONEDRIVESYNC\Documents"
Set-KnownFolderPath -KnownFolder 'Pictures' -Path "$ONEDRIVESYNC\Pictures"
Set-KnownFolderPath -KnownFolder 'Videos' -Path "$ONEDRIVESYNC\Videos"
Set-KnownFolderPath -KnownFolder 'Music' -Path "$ONEDRIVESYNC\Music"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive" -Name EnableADAL -PropertyType DWORD -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive" -Name EnableAllOcsiClients -PropertyType DWORD -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive" -Name DisablePersonalSync -PropertyType DWORD -Value 1 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive" -Name DefaultToBusinessFRE -PropertyType DWORD -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\OneDrive\Tenants\3240d646-3921-4119-bfae-43be06f3ebbf" -Name DisableCustomRoot -PropertyType DWORD -Value 1

Start-Process odopen://sync?useremail=bevin.duplessis@edgespace.co.za