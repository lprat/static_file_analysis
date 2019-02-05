//Ref: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows+Registry+Auditing+Cheat+Sheet+ver+Nov+2017.pdf
//Ref: https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml

rule REGfile_change_ie_zone{
	meta:
		description = "Regfile Change conf IE zone internet"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users"
		tag = "attack.persistence"
	strings:
	    $persi = "\\Internet Settings\\Zones\\3" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
//code:
//  1001     ActiveX controls and plug-ins: Download signed ActiveX controls
//   1004     ActiveX controls and plug-ins: Download unsigned ActiveX controls
//   1200     ActiveX controls and plug-ins: Run ActiveX controls and plug-ins
//   1201     ActiveX controls and plug-ins: Initialize and script ActiveX controls not marked as safe for scripting
//   1206     Miscellaneous: Allow scripting of Internet Explorer Web browser control ^
//   1207     Reserved #
//   1208     ActiveX controls and plug-ins: Allow previously unused ActiveX controls to run without prompt ^
//   1209     ActiveX controls and plug-ins: Allow Scriptlets
//   120A     ActiveX controls and plug-ins: ActiveX controls and plug-ins: Override Per-Site (domain-based) ActiveX restrictions
//   120B     ActiveX controls and plug-ins: Override Per-Site (domain-based) ActiveX restrictions
//   1400     Scripting: Active scripting
//   1402     Scripting: Scripting of Java applets
//   1405     ActiveX controls and plug-ins: Script ActiveX controls marked as safe for scripting
//   1406     Miscellaneous: Access data sources across domains
//   1407     Scripting: Allow Programmatic clipboard access
//   1408     Reserved #
//   1409     Scripting: Enable XSS Filter
//   1601     Miscellaneous: Submit non-encrypted form data
//   1604     Downloads: Font download
//   1605     Run Java #
//   1606     Miscellaneous: Userdata persistence ^
//   1607     Miscellaneous: Navigate sub-frames across different domains
//   1608     Miscellaneous: Allow META REFRESH * ^
//   1609     Miscellaneous: Display mixed content *
//   160A     Miscellaneous: Include local directory path when uploading files to a server ^
//   1800     Miscellaneous: Installation of desktop items
//   1802     Miscellaneous: Drag and drop or copy and paste files
//   1803     Downloads: File Download ^
//   1804     Miscellaneous: Launching programs and files in an IFRAME
//   1805     Launching programs and files in webview #
//   1806     Miscellaneous: Launching applications and unsafe files
//   1807     Reserved ** #
//   1808     Reserved ** #
//   1809     Miscellaneous: Use Pop-up Blocker ** ^
//   180A     Reserved # 
//   180B     Reserved #
//   180C     Reserved #
//   180D     Reserved #
//   180E     Allow OpenSearch queries in Windows Explorer #
//   180F     Allow previewing and custom thumbnails of OpenSearch query results in Windows Explorer #
//   1A00     User Authentication: Logon
//   1A02     Allow persistent cookies that are stored on your computer #
//   1A03     Allow per-session cookies (not stored) #
//   1A04     Miscellaneous: Don't prompt for client certificate selection when no certificates or only one certificate exists *
//   1A05     Allow 3rd party persistent cookies *
//   1A06     Allow 3rd party session cookies *
//   1A10     Privacy Settings *
//   1C00     Java permissions #
//   1E05     Miscellaneous: Software channel permissions
//   1F00     Reserved ** #
//   2000     ActiveX controls and plug-ins: Binary and script behaviors
//   2001     .NET Framework-reliant components: Run components signed with Authenticode
//   2004     .NET Framework-reliant components: Run components not signed with Authenticode
//   2007     .NET Framework-Reliant Components: Permissions for Components with Manifests
//   2100     Miscellaneous: Open files based on content, not file extension ** ^
//   2101     Miscellaneous: Web sites in less privileged web content zone can navigate into this zone **
//   2102     Miscellaneous: Allow script initiated windows without size or position constraints ** ^
//   2103     Scripting: Allow status bar updates via script ^
//   2104     Miscellaneous: Allow websites to open windows without address or status bars ^
//   2105     Scripting: Allow websites to prompt for information using scripted windows ^
//   2200     Downloads: Automatic prompting for file downloads ** ^
//   2201     ActiveX controls and plug-ins: Automatic prompting for ActiveX controls ** ^
//   2300     Miscellaneous: Allow web pages to use restricted protocols for active content **
//   2301     Miscellaneous: Use Phishing Filter ^
//   2400     .NET Framework: XAML browser applications
//   2401     .NET Framework: XPS documents
//   2402     .NET Framework: Loose XAML
//   2500     Turn on Protected Mode [Vista only setting] #
//   2600     Enable .NET Framework setup ^
//   2702     ActiveX controls and plug-ins: Allow ActiveX Filtering
//   2708     Miscellaneous: Allow dragging of content between domains into the same window
//   2709     Miscellaneous: Allow dragging of content between domains into separate windows
//   270B     Miscellaneous: Render legacy filters
//   270C     ActiveX Controls and plug-ins: Run Antimalware software on ActiveX controls 
}

rule REGfile_change_ie_addons{
	meta:
		description = "Regfile Change IE addons or plugin"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://blog.malwarebytes.com/threats/browser-hijack-objects-bhos/"
		tag = "attack.persistence"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_change_ie_toolbar_extension {
	meta:
		description = "Regfile Change IE toolbar or extension"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.exterminate-it.com/malpedia/remove-mywebsearch"
		tag = "attack.persistence"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Internet Explorer\\Toolbar" nocase
	    $persi1 = "\\Software\\Microsoft\\Internet Explorer\\Extensions" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_change_ie {
	meta:
		description = "Regfile Change IE configuration"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = ""
		tag = "attack.persistence"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Internet Explorer\\Main" nocase
	    $persi1 = "\\Software\\Microsoft\\Internet Explorer\\Security" nocase
	    $persi2 = "\\SearchScopes\\" nocase
	    $param1 = "Start Page" nocase
        $param2 = "Default_Page_URL" nocase
        $param3 = "Local Page" nocase
        $param4 = "Search Page" nocase
        $param5 = "url" nocase
        $param6 = "DisableSecuritySettingsCheck" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and (any of ($persi*) and any of ($param*))
}
			
rule REGfile_change_network_wpad {
	meta:
		description = "Regfile Change network configuration WPAD"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		tag = "attack.persistence"
	strings:
	    $persi = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" nocase
	    $param = "AutoConfigURL" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_change_network_dns {
	meta:
		description = "Regfile Change network configuration DNS"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		tag = "attack.persistence"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters" nocase
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip\\Parameters" nocase
	    $param1 = "NameServer" nocase
	    $param2 = "DhcpNameServer" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($param*) and any of ($persi*)
}

rule REGfile_change_network_dhcp {
	meta:
		description = "Regfile Change network configuration DHCP"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		tag = "attack.persistence"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters" nocase
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip\\Parameters" nocase
	    $param1 = "DhcpServer" nocase
	    $param2 = "DhcpDomain" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($param*) and any of ($persi*)
}

rule REGfile_change_network_gateway {
	meta:
		description = "Regfile Change network configuration GATEWAY"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		tag = "attack.persistence"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters" nocase
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip\\Parameters" nocase
	    $param1 = "DhcpDefaultGateway" nocase
	    $param2 = "DefaultGateway" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($param*) and any of ($persi*)
}

rule REGfile_change_network_proxy {
	meta:
		description = "Regfile Change network configuration PROXY"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		tag = "attack.persistence"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Setting" nocase
	    $persi1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Setting" nocase
	    $param1 = "ProxyServer" nocase
	    $param2 = "ProxyEnable" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*) and any of ($param*)
}
rule REGfile_persistence_t1004 {
	meta:
		description = "Regfile Winlogon Helper DLL"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1004/"
		tag = "attack.persistence,attack.t1004"
	strings:
	    $persi = "\\Windows NT\\CurrentVersion\\Winlogon" nocase
	    $param0 = "Userinit" nocase
	    $param1 = "Shell" nocase
	    $param2 = "Notify" nocase
	    $param3 = "System" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and any of ($param*)
}

rule REGfile_persistence_t1209 {
	meta:
		description = "Regfile Time Providers"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://attack.mitre.org/techniques/T1209/"
		tag = "attack.persistence,attack.t1209"
	strings:
	    $persi = "\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\" nocase
	    $param = "DllName" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_persistence_t1198 {
	meta:
		description = "Regfile SIP and Trust Provider Hijacking"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1198/"
		tag = "attack.persistence,attack.t1198"
	strings:
	    $persi0 = "\\Microsoft\\Cryptography\\OID\\" nocase
	    $persi1 = "\\Microsoft\\Cryptography\\Providers\\Trust" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_persistence_t1101 {
	meta:
		description = "Regfile Security Support Provider"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1101/"
		tag = "attack.persistence,attack.t1101"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa" nocase
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" nocase
	    $param = "Security Packages"
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*) and $param
}

rule REGfile_persistence_t1180 {
	meta:
		description = "Regfile Screensaver"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://attack.mitre.org/techniques/T1180/"
		tag = "attack.persistence,attack.t1180"
	strings:
	    $first = "\\Control Panel\\Desktop" nocase
	    $param0 = "SCRNSAVE.exe"
	    $param1 = "ScreenSaveActive"
	    $param2 = "ScreenSaverIsSecure"
	    $param3 = "ScreenSaveTimeout"
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $first and any of ($param*)
}

rule REGfile_persistence_t1037 {
	meta:
		description = "Regfile Logon Scripts"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1037/"
		tag = "attack.persistence,attack.t1037"
	strings:
	    $persi0 = "\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts" nocase
	    $persi1 = "\\Group Policy\\Scripts" nocase
	    $persi2 = "UserInitMprLogonScript" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_persistence_t1060 {
	meta:
		description = "Regfile Run Keys"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1060/"
		tag = "attack.persistence,attack.t1060"
	strings:
	    $persi0 = "\\CurrentVersion\\Run" nocase
	    $persi1 = "\\CurrentVersion\\Policies\\Explorer\\Run" nocase
	    $persi2 = "\\Software\\Run" nocase
	    $persi3 = "\\CurrentVersion\\Explorer\\Shell Folders" nocase
	    $persi4 = "\\CurrentVersion\\Explorer\\User Shell Folders" nocase
	    $persi5 = "\\CurrentVersion\\Windows\\load" nocase
	    $persi6 = "\\CurrentVersion\\Windows\\Run" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_persistence_t1013 {
	meta:
		description = "Regfile Port Monitors"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1013/"
		tag = "attack.persistence,attack.t1013"
	strings:
	    $persi = "\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_persistence_t1137 {
	meta:
		description = "Regfile Office Application Startup"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1137/"
		tag = "attack.persistence,attack.t1137"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Office test\\Special\\Perf" nocase
	    $persi1 = /\\Software\\Microsoft\\Office\\[0-9\.]+\\[A-Z]+\\Options/i
	    $persi2 = /\\Software\\Microsoft\\Office\\[0-9\.]+\\[A-Z0-9_\-]+\\AddIns\\/i
	    $persi3 = /\\Software\\Microsoft\\Office\\[A-Z0-9_\-]+\\Addins\\/i
	    $persi4 = /\\Software\\Microsoft\\VBA\\VBE\\[0-9\.]+\\Addins\\/i
	    $param0 = "FriendlyName" nocase
	    $param1 = "LoadBehaviour" nocase
	    $param2 = "Autoload" nocase
	    $param3 = "Path" nocase
	    $param4 = "Open" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*) and any of ($param*)
}

rule REGfile_persistence_t1128 {
	meta:
		description = "Regfile Netsh Helper DLL"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1128/"
		tag = "attack.persistence,attack.t1128"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Netsh" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_persistence_t1031_or_t1050 {
	meta:
		description = "Regfile Modify Existing Service or Create new service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1031/"
		tag = "attack.persistence,attack.t1031,attack.t1050"
	strings:
	    $first = "\\SYSTEM\\CurrentControlSet\\Services\\" nocase
	    $param1 = "ServiceDll" nocase
	    $param2 = "ServiceManifest" nocase
	    $param3 = "ImagePath" nocase
	    $param4 = "Start" nocase
	    $param5 = "HelperDllName" nocase
	    $param6 = "Library" nocase
	    $param7 = "Path" nocase
	    $param8 = "DllPath" nocase
	    $param9 = "DllName" nocase
	    $param10 = "NameSpace_Callout" nocase
	    $param11 = "AppFullPath" nocase
	    $param12 = "AppArgs" nocase
	    $param23 = "LibraryPath" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $first and any of ($param*)
}

rule REGfile_persistence_t1122 {
	meta:
		description = "Regfile Component Object Model Hijacking"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1122/"
		//other reference: https://docs.microsoft.com/fr-fr/windows/desktop/shell/reg-shell-exts
		tag = "attack.persistence,attack.t1122"
	strings:
	    $base = "\\Software\\Classes\\CLSID\\{" nocase
	    $persi1 = "InprocServer" nocase
	    $persi2 = "LocalServer" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $base and any of ($persi*)
}


rule REGfile_persistence_t1131 {
	meta:
		description = "Regfile Authentication Package"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1131/"
		tag = "attack.persistence,attack.t1131"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa" nocase
	    $persi1 = "Authentication Packages" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and all of ($persi*)
}

rule REGfile_persistence_t1138 {
	meta:
		description = "Regfile Application Shimming"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1138/"
		tag = "attack.persistence,attack.t1138"
	strings:
	    $persi0 = "software\\microsoft\\windows nt\\currentversion\\appcompatflags\\installedsdb" nocase
	    $persi1 = "software\\microsoft\\windows nt\\currentversion\\appcompatflags\\custom" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_persistence_t1103 {
	meta:
		description = "Regfile AppInit DLLs"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1103/"
		tag = "attack.persistence,attack.t1182"
	strings:
	    $persi0 = "\\Microsoft\\Windows NT\\CurrentVersion\\Windows" nocase
	    $persi1 = "AppInit_DLLs" nocase
	    $persi2 = "LoadAppInit_DLLs" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and 2 of ($persi*)
}

rule REGfile_persistence_t1182 {
	meta:
		description = "Regfile AppCert DLLs"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1182/"
		tag = "attack.persistence,attack.t1182"
	strings:
	    $persi0 = "\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls" nocase
	    $persi1 = "\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_persistence_t1015 {
	meta:
		description = "Regfile Accessibility Features"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://attack.mitre.org/techniques/T1015/"
		tag = "attack.persistence,attack.t1015"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_persistence_t1183 {
	meta:
		description = "Regfile Image File Execution Options Injection"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1183/"
		tag = "attack.persistence,attack.t1183"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_persistence_t1042 {
	meta:
		description = "Regfile Change Default File Association"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1042/"
		tag = "attack.persistence,attack.t1042"
	strings:
	    $persi1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts" nocase
	    $persi2 = "[HKEY_CLASSES_ROOT\\.]" nocase
	    $persi3 = /[HKEY_USERS\\S-[^\\]\\\.\S+]/i
	    $persi4 = /\\shell\\\S+\\command/i //in HKEY_CLASSES_ROOT
	    $persi5 = /\\shell\\\S+\\ddeexec\\/i //in HKEY_CLASSES_ROOT
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and any of ($persi*)
}

rule REGfile_persistence_t1039 {
	meta:
		description = "Regfile Path Interception"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1039/"
		tag = "attack.persistence,attack.t1039"
	strings:
	    $persi = "\\CurrentVersion\\App Paths\\" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_hidden_file {
	meta:
		description = "Regfile Change conf hidden file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://attack.mitre.org/techniques/T1089/"
		tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\CurrentVersion\\Explorer\\Advanced" nocase
	    $param1 = "HideFileExt" nocase
	    $param2 = "ShowSuperHidden" nocase
	    $param3 = "Hidden" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and any of ($param*)
}

rule REGfile_macrowarning {
	meta:
		description = "Regfile Change macro warning config"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/"
		tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\Security" nocase
	    $param = "VBAWarnings" nocase //if == 1 then bad!
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_persistence_t1109 {
	meta:
		description = "Regfile Driver"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1109/"
		tag = "attack.persistence,attack.t1109"
	strings:
	    $persi = "\\CurrentVersion\\Drivers32" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_persistence_bootexecute {
	meta:
		description = "Regfile Run at boot before logon"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
		tag = "attack.persistence"
	strings:
	    $persi = "\\Control\\Session Manager\\" nocase
	    $param = "BootExecute" nocase
 	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_persistence_oncrash {
	meta:
		description = "Regfile Run on crash"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2007-050712-5453-99&tabid=2"
		tag = "attack.persistence"
	strings:
	    $persi = "\\CurrentVersion\\AeDebug" nocase
 	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi
}

rule REGfile_persistence_runonrdplogon {
	meta:
		description = "Regfile Run on rdp logon"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2007-050712-5453-99&tabid=2"
		tag = "attack.persistence"
	strings:
	    $persi = "\\Terminal Server\\WinStations\\RDP-Tcp" nocase
	    $param = "InitialProgram" nocase
 	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_UAC {
	meta:
		description = "Regfile Change config UAC"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\CurrentVersion\\Policies\\System" nocase
	    $param1 = "EnableLUA" nocase // 0 == Disabled UAC
	    $param2 = "LocalAccountTokenFilterPolicy" nocase // Default value == 0
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and any of ($param*)
}

rule REGfile_Change_ConfSecCenter {
	meta:
		description = "Regfile Change conf Security Center"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Security Center" nocase
	    $param1 = "AntiSpywareOverride" nocase
	    $param2 = "AllAlertsDisabled" nocase
	    $param3 = "AntiVirusOverride" nocase
	    $param4 = "AntiVirusDisableNotify" nocase
	    $param5 = "DisableMonitoring" nocase
	    $param6 = "FirewallDisableNotify" nocase
	    $param7 = "FirewallOverride" nocase
	    $param8 = "UacDisableNotify" nocase
	    $param9 = "UpdatesDisableNotify" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and any of ($param*)
}

rule REGfile_Change_ProfilFW {
	meta:
		description = "Regfile Change Profile Firewall"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\FirewallPolicy\\" nocase
	    $param1 = "EnableFirewall" nocase
	    $param2 = "DoNotAllowExceptions" nocase
	    $change1 = "\\GloballyOpenPorts\\List" nocase
	    $change2 = "\\AuthorizedApplications\\List" nocase
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and (any of ($change*) or ($persi and any of ($param*)))
}

rule REGfile_change_WDigest_store {
	meta:
		description = "Regfile Change WDigest storage credential"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		tag = "attack.Defense_Evasion,attack.t1089,"
	strings:
	    $persi = "\\SecurityProviders\\WDigest" nocase
	    $param = "UseLogonCredential" nocase // if == 1 then store credential in clear text
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_disabled_CredentialProvider {
	meta:
		description = "Regfile Disable Credential Provider"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" //https://fr.slideshare.net/securityxploded/exposing-the-secrets-of-windows-credential-providerer
		tag = "attack.Defense_Evasion,attack.t1089,"
	strings:
	    $persi = "\\Authentication\\Credential\\" nocase
	    $param = "Disabled" nocase //if == 1 then disabled
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}

rule REGfile_disabled_GPO {
	meta:
		description = "Regfile Disabled GPO"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" //https://blogs.technet.microsoft.com/mikehall/2013/01/31/group-policy-client-side-extensions/
		tag = "attack.Defense_Evasion,attack.t1089,"
	strings:
	    $persi = "\\CurrentVersion\\Winlogon\\GPExtensions\\" nocase
	    $param = "NoMachinePolicy" nocase //if == 1 then disabled gpo
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    2 of ($regmagic*) and FileType matches /CL_TYPE_ASCII/ and $persi and $param
}




