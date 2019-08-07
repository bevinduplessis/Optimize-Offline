Function Disable-WindowsThemeSounds
{
  [CmdletBinding()]
  Param()
  Process {
    $ThemeSounds = Get-ChildItem -Path 'Registry::HKEY_CURRENT_USER\AppEvents\Schemes\Apps' -Recurse | Get-ItemProperty
    foreach ($RegKey in $ThemeSounds)
    {
      $strVal = [string]$RegKey.'(default)'
      if($strVal.EndsWith('.wav'))
      {
        Set-ItemProperty -Path $RegKey.PSPath -Name '(default)' -Value ''
      }
    }
  }
}

Function Set-TerminalShortcutsAsAdmin
{
  [CmdletBinding()]
  Param  
  ()

  Process 
  {
    $PowerShellPath = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\"
    $CommandPrompt = "$env:SystemDrive\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System Tools\"

    $ShortcutPaths = Get-ChildItem -Path $PowerShellPath -Recurse -Include *.lnk
    $ShortcutPaths += Get-ChildItem -Path $CommandPrompt -Recurse -Include 'Command Prompt.lnk'

    Foreach ($ShortcutPath in $ShortcutPaths) 
    {
      Try 
      {
        $bytes = [IO.File]::ReadAllBytes("$ShortcutPath")
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [IO.File]::WriteAllBytes("$ShortcutPath", $bytes)
      } 
      Catch 
      {
        Write-Error -Message "Unable to set '$ShortcutPath' to always run as administrator"
      }
    }
  }
}

Function Disable-SMBv1 
{
  Process 
  {
    $null = Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    $null = Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
  }
}

Function Enable-F8BootMenu 
{
  # Enable F8 boot menu options
  $null = & "$env:windir\system32\bcdedit.exe" /set `{current`} bootmenupolicy Legacy
}

Function Disable-StartupRecovery 
{
  Write-Verbose -Message 'Disable-StartupRecovery'
  $null = & "$env:windir\system32\bcdedit.exe" /set recoveryenabled No
}

Function Disable-BeepService
{
  Process 
  {
    Set-Service -Name beep -StartupType disabled
  }
}


Function Install-ISLC
{
  Process {
    Try
    {
      Invoke-WebRequest -Uri 'https://www.wagnardsoft.com/ISLC/ISLC%20v1.0.1.1.exe' -OutFile "$(Get-Temp)\ISLC.exe"
    }
    catch
    {
      Write-Error -Message 'Unable to download ISLC'
    }

    Start-Process -FilePath "$(Get-Temp)\ISLC.exe" -ArgumentList "-y -o$([char]34)$($env:ProgramW6432)$([char]34)" -Wait
    
    While(!(Test-Path -Path "$($env:ProgramW6432)\ISLC v1.0.1.1\Intelligent standby list cleaner ISLC.exe")) 
    {
      Start-Sleep -Seconds 1
    }
  }
}


Function Install-CCEnhancer 
{
  Process 
  {

    if(Test-Path -Path "$env:ProgramW6432\CCleaner") 
    {
      Try 
      {
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini' -OutFile "$env:ProgramW6432\CCleaner\Winapp2.ini"
      }
      catch 
      {
        Write-Error -Message 'Unable to download CCEnhancer winapp2.ini file'
      }
    }
    else 
    {
      Write-Warning -Message 'Skipping installation CCleaner is not installed'
    }
  }
}


Function Install-ChocolateyPackage
{
  [CmdletBinding()]
  Param
  (
    [string[]]$Package
  )
	
  Process 
  {
    # Setup Logging
    $LogDir = "$env:HOMEDRIVE"

    $LogFile = "$LogDir\chocolatey_log_$(Get-Date -UFormat '%Y-%m-%d')"
    
    # Attempt to upgrade chocolatey (and all installed packages) else (if the command fails) install it.
    try
    {
      choco.exe upgrade all -y -r --no-progress --log-file=$LogFile
    }
    catch 
    {
      Invoke-Expression -Command ((New-Object -TypeName System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
    
    if(Test-Path -Path "$env:ProgramData\chocolatey\bin\choco.exe") {
      $chocoCmd = Get-Command -Name 'choco' -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Select-Object -ExpandProperty Source
    }

    if ($chocoCmd -eq $null) 
    {
      return
    }
  
    Foreach ($p in $Package)
    {
      Start-Process -FilePath $chocoCmd -ArgumentList "install $p  -y -r --no-progress --log-file=$LogFile --ignore-checksums" -NoNewWindow -Wait
    }
  }
}


Function Set-WindowsPowerPlan
{
  [CmdletBinding()]
  Param(
    [switch]$HighPerformance,
    [switch]$UltimatePerformance,
    [switch]$Balanced
  )

  Begin {

    if($UltimatePerformance.IsPresent) 
    {
      $Filter = 'Ultimate Performance'
    }
    elseif($HighPerformance.IsPresent) 
    {
      $Filter = 'High performance'
    }
    elseif($Balanced.IsPresent) 
    {
      $Filter = 'Balanced'
    }
  }

  Process {
	
    Function Select-Plan
    {
      Process
      {
        if($_.contains($Filter)) 
        {
          $_.split()[3]
        }
      }
    }

    $Plan = & "$env:windir\system32\powercfg.exe" -l | Select-Plan
    $CurrPlan = $(& "$env:windir\system32\powercfg.exe" -getactivescheme).split()[3]
    if ($CurrPlan -ne $Plan) 
    {
      & "$env:windir\system32\powercfg.exe" -setactive $Plan
    }
  }
}

Function Disable-8dot3FileNames
{
  Process {
    $null = & "$env:windir\system32\fsutil.exe" behavior set Disable8dot3 1
  }
}

Function Set-DEPOptOut 
{
  Process 
  {
    $null = & "$env:windir\system32\bcdedit.exe" /set `{current`} nx OptOut
  }
}

Function Invoke-SetupNetscan 
{
  $LicenseFile = "$env:APPDATA\SoftPerfect Network Scanner\netscan.lic"

  $License = @'
<?xml version="1.0"?>
<network-scanner-license>
  <license>MgAFn25/4exVuZcK8cgl3Wp9tNardDcXu3huXQwh5qZO9JLcS64SQnz1WcmxCxyeoAQG/MU8FFJTqDoqEyjjKklJIYC8ef1svPxdG0PsJtKrNLdoiVyJZmVwUOzRDN3PGi26GJvlSaTS1VsB/+OqQ9mQksdd7mvanqv3M0Tj1j0=</license>
  <upgrade>0</upgrade>
  <language>English</language>
  <autoupdate>
    <prompt>false</prompt>
    <enabled>false</enabled>
    <lastcheck>0</lastcheck>
  </autoupdate>
</network-scanner-license>
'@

  New-Item -Path $LicenseFile -ItemType File -Value $License -Force
}

Function Invoke-SetupUtilities 
{
  $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
  $newpath = "$oldpath;C:\Windows\Utilities"
  Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newpath
}


Function Set-DesktopIconSize {

  $IconSize = 12
  If (Test-Path -Path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop) 
    { 
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -Name IconSize -Value $IconSize 
    } 
    Elseif(Test-Path -Path 'HKCU:\Control Panel\Desktop\WindowMetrics') 
    { 
        Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'Shell Icon Size' -Value $IconSize 
    }
}

Start-Transcript -Path "$env:SystemDrive\FirstLogonScriptLog.txt" -Force

Set-DesktopIconSize
Stop-Process -Name Explorer
Disable-WindowsThemeSounds
Disable-BeepService
Enable-F8BootMenu
Disable-StartupRecovery
Invoke-SetupNetscan
Invoke-SetupUtilities
Set-DEPOptOut
Disable-8dot3FileNames
Set-WindowsPowerPlan -UltimatePerformance
Disable-SMBv1
Set-TerminalShortcutsAsAdmin

Install-ChocolateyPackage -Package @(
        'vcredist-all'
        'git'
        'sudo'
        'googlechrome'
        'directx'
        '7zip'
        'ccleaner'
        'cpu-z'
        'gpu-z'
        'grepwin'
        'irfanviewplugins'
        'irfanview'
        'k-litecodecpackmega'
        'notepadplusplus'
        'PSWindowsUpdate'
        'putty'
        'qbittorrent'
        'sysinternals'
        'youtube-dl'
        'ffmpeg'
        'imageresizerapp'
        'winscp'
        'vscode'
        'vscode-powershell'
        'vscode-icons'
        'vscode-autohotkey'
        'openinvscode'
        'k-litecodecpackfull'
        'nugetpackageexplorer'
        'winbox'
        'discord'
        #'origin'
        #'geforce-game-ready-driver-win10'
        #'Office365ProPlus'
        #'kodi'
        )

Install-CCEnhancer
Install-ISLC

Stop-Transcript -ErrorAction SilentlyContinue