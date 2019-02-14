//Ref: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5a00963153450a8779b23489/1509987890282/Windows+Registry+Auditing+Cheat+Sheet+ver+Nov+2017.pdf
//Ref: https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml

rule Registry_change_ie_zone{
	meta:
		description = "Registry Change conf IE zone internet"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://support.microsoft.com/en-us/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users"
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi = "\\Internet Settings\\Zones\\3" nocase ascii wide
	condition:
	    check_registry_bool and $persi
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

rule Registry_change_ie_addons{
	meta:
		description = "Registry Change IE addons or plugin"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://blog.malwarebytes.com/threats/browser-hijack-objects-bhos/"
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_change_ie_toolbar_extension {
	meta:
		description = "Registry Change IE toolbar or extension"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.exterminate-it.com/malpedia/remove-mywebsearch"
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Internet Explorer\\Toolbar" nocase ascii wide
	    $persi1 = "\\Software\\Microsoft\\Internet Explorer\\Extensions" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_change_ie {
	meta:
		description = "Registry Change IE configuration"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = ""
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Internet Explorer\\Main" nocase ascii wide
	    $persi1 = "\\Software\\Microsoft\\Internet Explorer\\Security" nocase ascii wide
	    $persi2 = "\\SearchScopes\\" nocase ascii wide
	    $param1 = "Start Page" nocase ascii wide
        $param2 = "Default_Page_URL" nocase ascii wide
        $param3 = "Local Page" nocase ascii wide
        $param4 = "Search Page" nocase ascii wide
        $param5 = "url" nocase ascii wide
        $param6 = "DisableSecuritySettingsCheck" nocase ascii wide
	condition:
	    check_registry_bool and (any of ($persi*) and any of ($param*))
}
			
rule Registry_change_network_wpad {
	meta:
		description = "Registry Change network configuration WPAD"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" nocase ascii wide
	    $param = "AutoConfigURL" nocase ascii wide
	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_change_network_dns {
	meta:
		description = "Registry Change network configuration DNS"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters" nocase ascii wide
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip\\Parameters" nocase ascii wide
	    $param1 = "NameServer" nocase ascii wide
	    $param2 = "DhcpNameServer" nocase ascii wide
	condition:
	    check_registry_bool and any of ($param*) and any of ($persi*)
}

rule Registry_change_network_dhcp {
	meta:
		description = "Registry Change network configuration DHCP"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters" nocase ascii wide
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip\\Parameters" nocase ascii wide
	    $param1 = "DhcpServer" nocase ascii wide
	    $param2 = "DhcpDomain" nocase ascii wide
	condition:
	    check_registry_bool and any of ($param*) and any of ($persi*)
}

rule Registry_change_network_gateway {
	meta:
		description = "Registry Change network configuration GATEWAY"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip6\\Parameters" nocase ascii wide
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Services\\tcpip\\Parameters" nocase ascii wide
	    $param1 = "DhcpDefaultGateway" nocase ascii wide
	    $param2 = "DefaultGateway" nocase ascii wide
	condition:
	    check_registry_bool and any of ($param*) and any of ($persi*)
}

rule Registry_change_network_proxy {
	meta:
		description = "Registry Change network configuration PROXY"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = ""
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Setting" nocase ascii wide
	    $persi1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Setting" nocase ascii wide
	    $param1 = "ProxyServer" nocase ascii wide
	    $param2 = "ProxyEnable" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*) and any of ($param*)
}
rule Registry_persistence_t1004 {
	meta:
		description = "Registry Winlogon Helper DLL"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1004/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1004"
	strings:
	    $persi = "\\Windows NT\\CurrentVersion\\Winlogon" nocase ascii wide
	    $param0 = "Userinit" nocase ascii wide
	    $param1 = "Shell" nocase ascii wide
	    $param2 = "Notify" nocase ascii wide
	    $param3 = "System" nocase ascii wide
	condition:
	    check_registry_bool and $persi and any of ($param*)
}

rule Registry_persistence_t1209 {
	meta:
		description = "Registry Time Providers"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://attack.mitre.org/techniques/T1209/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1209"
	strings:
	    $persi = "\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\" nocase ascii wide
	    $param = "DllName" nocase ascii wide
	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_persistence_t1198 {
	meta:
		description = "Registry SIP and Trust Provider Hijacking"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1198/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1198"
	strings:
	    $persi0 = "\\Microsoft\\Cryptography\\OID\\" nocase ascii wide
	    $persi1 = "\\Microsoft\\Cryptography\\Providers\\Trust" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_persistence_t1101 {
	meta:
		description = "Registry Security Support Provider"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1101/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1101"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa" nocase ascii wide
	    $persi1 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig" nocase ascii wide
	    $param = "Security Packages"
	condition:
	    check_registry_bool and any of ($persi*) and $param
}

rule Registry_persistence_t1180 {
	meta:
		description = "Registry Screensaver"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://attack.mitre.org/techniques/T1180/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1180"
	strings:
	    $first = "\\Control Panel\\Desktop" nocase ascii wide
	    $param0 = "SCRNSAVE.exe"
	    $param1 = "ScreenSaveActive"
	    $param2 = "ScreenSaverIsSecure"
	    $param3 = "ScreenSaveTimeout"
	condition:
	    check_registry_bool and $first and any of ($param*)
}

rule Registry_persistence_t1037 {
	meta:
		description = "Registry Logon Scripts"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1037/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1037"
	strings:
	    $persi0 = "\\Software\\Policies\\Microsoft\\Windows\\System\\Scripts" nocase ascii wide
	    $persi1 = "\\Group Policy\\Scripts" nocase ascii wide
	    $persi2 = "UserInitMprLogonScript" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_persistence_t1060 {
	meta:
		description = "Registry Run Keys"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1060/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1060"
	strings:
	    $persi0 = "\\CurrentVersion\\Run" nocase ascii wide
	    $persi1 = "\\CurrentVersion\\Policies\\Explorer\\Run" nocase ascii wide
	    $persi2 = "\\Software\\Run" nocase ascii wide
	    $persi3 = "\\CurrentVersion\\Explorer\\Shell Folders" nocase ascii wide
	    $persi4 = "\\CurrentVersion\\Explorer\\User Shell Folders" nocase ascii wide
	    $persi5 = "\\CurrentVersion\\Windows\\load" nocase ascii wide
	    $persi6 = "\\CurrentVersion\\Windows\\Run" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_persistence_t1013 {
	meta:
		description = "Registry Port Monitors"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1013/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1013"
	strings:
	    $persi = "\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_persistence_t1137 {
	meta:
		description = "Registry Office Application Startup"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1137/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1137"
	strings:
	    $persi0 = "\\Software\\Microsoft\\Office test\\Special\\Perf" nocase ascii wide
	    $persi1 = /\\Software\\Microsoft\\Office\\[0-9\.]+\\[A-Z]+\\Options/i
	    $persi2 = /\\Software\\Microsoft\\Office\\[0-9\.]+\\[A-Z0-9_\-]+\\AddIns\\/i
	    $persi3 = /\\Software\\Microsoft\\Office\\[A-Z0-9_\-]+\\Addins\\/i
	    $persi4 = /\\Software\\Microsoft\\VBA\\VBE\\[0-9\.]+\\Addins\\/i
	    $param0 = "FriendlyName" nocase ascii wide
	    $param1 = "LoadBehaviour" nocase ascii wide
	    $param2 = "Autoload" nocase ascii wide
	    $param3 = "Path" nocase ascii wide
	    $param4 = "Open" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*) and any of ($param*)
}

rule Registry_persistence_t1128 {
	meta:
		description = "Registry Netsh Helper DLL"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1128/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1128"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Netsh" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_persistence_t1031_or_t1050 {
	meta:
		description = "Registry Modify Existing Service or Create new service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1031/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1031,attack.t1050"
	strings:
	    $first = "\\SYSTEM\\CurrentControlSet\\Services\\" nocase ascii wide
	    $param1 = "ServiceDll" nocase ascii wide
	    $param2 = "ServiceManifest" nocase ascii wide
	    $param3 = "ImagePath" nocase ascii wide
	    $param4 = "Start" nocase ascii wide
	    $param5 = "HelperDllName" nocase ascii wide
	    $param6 = "Library" nocase ascii wide
	    $param7 = "Path" nocase ascii wide
	    $param8 = "DllPath" nocase ascii wide
	    $param9 = "DllName" nocase ascii wide
	    $param10 = "NameSpace_Callout" nocase ascii wide
	    $param11 = "AppFullPath" nocase ascii wide
	    $param12 = "AppArgs" nocase ascii wide
	    $param23 = "LibraryPath" nocase ascii wide
	condition:
	    check_registry_bool and $first and any of ($param*)
}

rule Registry_persistence_t1122 {
	meta:
		description = "Registry Component Object Model Hijacking"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1122/"
		//other reference: https://docs.microsoft.com/fr-fr/windows/desktop/shell/reg-shell-exts
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1122"
	strings:
	    $base = "\\Software\\Classes\\CLSID\\{" nocase ascii wide
	    $persi1 = "InprocServer" nocase ascii wide
	    $persi2 = "LocalServer" nocase ascii wide
	condition:
	    check_registry_bool and $base and any of ($persi*)
}


rule Registry_persistence_t1131 {
	meta:
		description = "Registry Authentication Package"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1131/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1131"
	strings:
	    $persi0 = "\\SYSTEM\\CurrentControlSet\\Control\\Lsa" nocase ascii wide
	    $persi1 = "Authentication Packages" nocase ascii wide
	condition:
	    check_registry_bool and all of ($persi*)
}

rule Registry_persistence_t1138 {
	meta:
		description = "Registry Application Shimming"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1138/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1138"
	strings:
	    $persi0 = "software\\microsoft\\windows nt\\currentversion\\appcompatflags\\installedsdb" nocase ascii wide
	    $persi1 = "software\\microsoft\\windows nt\\currentversion\\appcompatflags\\custom" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_persistence_t1103 {
	meta:
		description = "Registry AppInit DLLs"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1103/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1182"
	strings:
	    $persi0 = "\\Microsoft\\Windows NT\\CurrentVersion\\Windows" nocase ascii wide
	    $persi1 = "AppInit_DLLs" nocase ascii wide
	    $persi2 = "LoadAppInit_DLLs" nocase ascii wide
	condition:
	    check_registry_bool and 2 of ($persi*)
}

rule Registry_persistence_t1182 {
	meta:
		description = "Registry AppCert DLLs"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1182/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1182"
	strings:
	    $persi0 = "\\System\\CurrentControlSet\\Control\\Session Manager\\AppCertDlls" nocase ascii wide
	    $persi1 = "\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs" nocase ascii wide
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_persistence_t1015 {
	meta:
		description = "Registry Accessibility Features"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://attack.mitre.org/techniques/T1015/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1015"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_persistence_t1183 {
	meta:
		description = "Registry Image File Execution Options Injection"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://attack.mitre.org/techniques/T1183/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1183"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_persistence_t1042 {
	meta:
		description = "Registry Change Default File Association"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1042/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1042"
	strings:
	    $persi1 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts" nocase ascii wide
	    $persi2 = "HKEY_CLASSES_ROOT\\." nocase ascii wide
	    $persi3 = /HKEY_USERS\\S-[^\\]\\\.\S+/i
	    $persi4 = /\\shell\\\S+\\command/i //in HKEY_CLASSES_ROOT
	    $persi5 = /\\shell\\\S+\\ddeexec\\/i //in HKEY_CLASSES_ROOT
	condition:
	    check_registry_bool and any of ($persi*)
}

rule Registry_persistence_t1039 {
	meta:
		description = "Registry Path Interception"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1039/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1039"
	strings:
	    $persi = "\\CurrentVersion\\App Paths\\" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_hidden_file {
	meta:
		description = "Registry Change conf hidden file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://attack.mitre.org/techniques/T1089/"
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\CurrentVersion\\Explorer\\Advanced" nocase ascii wide
	    $param1 = "HideFileExt" nocase ascii wide
	    $param2 = "ShowSuperHidden" nocase ascii wide
	    $param3 = "Hidden" nocase ascii wide
	condition:
	    check_registry_bool and $persi and any of ($param*)
}

rule Registry_macrowarning {
	meta:
		description = "Registry Change macro warning config"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/"
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\Security" nocase ascii wide
	    $param = "VBAWarnings" nocase ascii wide //if == 1 then bad!
	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_persistence_t1109 {
	meta:
		description = "Registry Driver"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1109/"
		ids = "win_reg"
	    tag = "attack.persistence,attack.t1109"
	strings:
	    $persi = "\\CurrentVersion\\Drivers32" nocase ascii wide
	condition:
	    check_registry_bool and $persi
}

rule Registry_persistence_bootexecute {
	meta:
		description = "Registry Run at boot before logon"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi = "\\Control\\Session Manager\\" nocase ascii wide
	    $param = "BootExecute" nocase ascii wide
 	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_persistence_oncrash {
	meta:
		description = "Registry Run on crash"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2007-050712-5453-99&tabid=2"
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi = "\\CurrentVersion\\AeDebug" nocase ascii wide
 	condition:
	    check_registry_bool and $persi
}

rule Registry_persistence_runonrdplogon {
	meta:
		description = "Registry Run on rdp logon"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.symantec.com/security_response/writeup.jsp?docid=2007-050712-5453-99&tabid=2"
		ids = "win_reg"
	    tag = "attack.persistence"
	strings:
	    $persi = "\\Terminal Server\\WinStations\\RDP-Tcp" nocase ascii wide
	    $param = "InitialProgram" nocase ascii wide
 	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_UAC {
	meta:
		description = "Registry Change config UAC"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\CurrentVersion\\Policies\\System" nocase ascii wide
	    $param1 = "EnableLUA" nocase ascii wide // 0 == Disabled UAC
	    $param2 = "LocalAccountTokenFilterPolicy" nocase ascii wide // Default value == 0
	condition:
	    check_registry_bool and $persi and any of ($param*)
}

rule Registry_Change_ConfSecCenter {
	meta:
		description = "Registry Change conf Security Center"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\SOFTWARE\\Microsoft\\Security Center" nocase ascii wide
	    $param1 = "AntiSpywareOverride" nocase ascii wide
	    $param2 = "AllAlertsDisabled" nocase ascii wide
	    $param3 = "AntiVirusOverride" nocase ascii wide
	    $param4 = "AntiVirusDisableNotify" nocase ascii wide
	    $param5 = "DisableMonitoring" nocase ascii wide
	    $param6 = "FirewallDisableNotify" nocase ascii wide
	    $param7 = "FirewallOverride" nocase ascii wide
	    $param8 = "UacDisableNotify" nocase ascii wide
	    $param9 = "UpdatesDisableNotify" nocase ascii wide
	condition:
	    check_registry_bool and $persi and any of ($param*)
}

rule Registry_Change_ProfilFW {
	meta:
		description = "Registry Change Profile Firewall"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089"
	strings:
	    $persi = "\\FirewallPolicy\\" nocase ascii wide
	    $param1 = "EnableFirewall" nocase ascii wide
	    $param2 = "DoNotAllowExceptions" nocase ascii wide
	    $change1 = "\\GloballyOpenPorts\\List" nocase ascii wide
	    $change2 = "\\AuthorizedApplications\\List" nocase ascii wide
	condition:
	    check_registry_bool and (any of ($change*) or ($persi and any of ($param*)))
}

rule Registry_change_WDigest_store {
	meta:
		description = "Registry Change WDigest storage credential"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" // https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089,"
	strings:
	    $persi = "\\SecurityProviders\\WDigest" nocase ascii wide
	    $param = "UseLogonCredential" nocase ascii wide // if == 1 then store credential in clear text
	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_disabled_CredentialProvider {
	meta:
		description = "Registry Disable Credential Provider"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" //https://fr.slideshare.net/securityxploded/exposing-the-secrets-of-windows-credential-providerer
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089,"
	strings:
	    $persi = "\\Authentication\\Credential\\" nocase ascii wide
	    $param = "Disabled" nocase ascii wide //if == 1 then disabled
	condition:
	    check_registry_bool and $persi and $param
}

rule Registry_disabled_GPO {
	meta:
		description = "Registry Disabled GPO"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://attack.mitre.org/techniques/T1089/" //https://blogs.technet.microsoft.com/mikehall/2013/01/31/group-policy-client-side-extensions/
		ids = "win_reg"
	    tag = "attack.Defense_Evasion,attack.t1089,"
	strings:
	    $persi = "\\CurrentVersion\\Winlogon\\GPExtensions\\" nocase ascii wide
	    $param = "NoMachinePolicy" nocase ascii wide //if == 1 then disabled gpo
	condition:
	    check_registry_bool and $persi and $param
}



