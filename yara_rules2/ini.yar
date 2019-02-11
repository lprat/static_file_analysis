//https://hwiegman.home.xs4all.nl/desktopini.html
//https://forum.malekal.com/viewtopic.php?t=56035&start=

rule INI_ressource_uri {
	meta:
		description = "Windows INI File (.ini) with get URI"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://hwiegman.home.xs4all.nl/desktopini.html"
	strings:
	    $ressource = /[^=]+\s*=(\s*\")*\S+\:\/\// nocase wide ascii
	condition:
	    check_ini_bool and $ressource
}

rule INI_ressource_ext {
	meta:
		description = "Windows INI File (.ini) with get external ressource"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://canarytokens.org"
	strings:
	    $ressource = /[^=]+\s*=(\s*\")*\\\\/ nocase wide ascii
	condition:
	    check_ini_bool and $ressource
}

rule INI_desktop_enc {
	meta:
		description = "Windows DESKTOP.INI with disable EFS encryption in folder"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://hwiegman.home.xs4all.nl/desktopini.html"
	strings:
	    $part = "[Encryption" nocase wide ascii
	    $param = /Disable\s*=(\s*\")*1/
	condition:
	    check_ini_bool and $part and $param
}

rule INI_desktop_URI {
	meta:
		description = "Windows DESKTOP.INI contains potential external link (http[s]://)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://hwiegman.home.xs4all.nl/desktopini.html"
	strings:
	    $part0 = "[.ShellClassInfo" nocase wide ascii
	    $part2 = "[{5984FFE0-28D4-11CF-AE66-08002B2E1262" nocase wide ascii
	    $part3 = "[{BE098140-A513-11D0-A3A4-00C04FD706EC" nocase wide ascii
	    $part5 = "[Channel" nocase wide ascii
	    $part6 = "[LocalizedFileNames" nocase wide ascii
	    $param0 = "Icon" nocase wide ascii
	    $param1 = "HTMLInfoTipFile" nocase wide ascii
	    $param2 = "URL" nocase wide ascii
	    $param3 = "Logo" nocase wide ascii
	    $param4 = "LocalizedResourceName" nocase wide ascii
	    $param5 = "PersistMoniker" nocase wide ascii
	    $param6 = "WebViewTemplate.NT5" nocase wide ascii
	    $param7 = "PersistMonikerPreview" nocase wide ascii
	    $param8 = "Windows-catalogus.lnk" nocase wide ascii
	    $uri = /=(\s*\")*\S+\:\/\// nocase wide ascii
	condition:
	   check_ini_bool and any of ($part*) and any of ($param*) and $uri
}

rule INI_desktop_link {
	meta:
		description = "Windows DESKTOP.INI contains potential external link (\\host)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://hwiegman.home.xs4all.nl/desktopini.html"
	strings:
	    $part0 = "[.ShellClassInfo" nocase wide ascii
	    $part2 = "[{5984FFE0-28D4-11CF-AE66-08002B2E1262" nocase wide ascii
	    $part3 = "[{BE098140-A513-11D0-A3A4-00C04FD706EC" nocase wide ascii
	    $part5 = "[Channel" nocase wide ascii
	    $part6 = "[LocalizedFileNames" nocase wide ascii
	    $param0 = "Icon" nocase wide ascii
	    $param1 = "HTMLInfoTipFile" nocase wide ascii
	    $param2 = "URL" nocase wide ascii
	    $param3 = "Logo" nocase wide ascii
	    $param4 = "LocalizedResourceName" nocase wide ascii
	    $param5 = "PersistMoniker" nocase wide ascii
	    $param6 = "WebViewTemplate.NT5" nocase wide ascii
	    $param7 = "PersistMonikerPreview" nocase wide ascii
	    $param8 = "Windows-catalogus.lnk" nocase wide ascii
	    $smb = /=(\s*\")*\\\\/ nocase wide ascii
	condition:
	   check_ini_bool and any of ($part*) and any of ($param*) and $smb
}

rule INI_desktop {
	meta:
		description = "Windows DESKTOP.INI File"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		reference = "https://hwiegman.home.xs4all.nl/desktopini.html"
	strings:
	    $part0 = "[.ShellClassInfo" nocase wide ascii
	    $part1 = "[.ExtShellFolderViews" nocase wide ascii
	    $part2 = "[{5984FFE0-28D4-11CF-AE66-08002B2E1262" nocase wide ascii
	    $part3 = "[{BE098140-A513-11D0-A3A4-00C04FD706EC" nocase wide ascii
	    $part4 = "[{8BEBB290-52D0-11d0-B7F4-00C04FD706EC" nocase wide ascii
	    $part5 = "[Channel" nocase wide ascii
	    $part6 = "[LocalizedFileNames" nocase wide ascii
	    $part7 = "[Encryption" nocase wide ascii
	    $part8 = "[DeleteOnCopy" nocase wide ascii
	    $part9 = "[ViewState" nocase wide ascii
	    $part10 = "[{F29F85E0-4FF9-1068-AB91-08002B27B3D9" nocase wide ascii
	condition:
	    check_ini_bool and any of ($part*)
}


rule INF_autorun {
	meta:
		description = "Windows autorun.inf File"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://fr.wikipedia.org/wiki/Autorun.inf"
	strings:
	    $auto = "AutoRun" nocase wide ascii
	    $part1 = "open" nocase wide ascii
	    $part2 = "icon" nocase wide ascii
	    $part3 = "useautorun" nocase wide ascii
	    $part4 = "shell" nocase wide ascii
	condition:
	    check_ini_bool and $auto and any of ($part*)
}

rule INF_autorund {
	meta:
		description = "Windows autorun.inf File with driver device install"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://docs.microsoft.com/en-us/windows-hardware/drivers/install/inf-ddinstall-section"
	strings:
	    $div0 = "DeviceInstall" nocase wide ascii
	    $div1 = "DDInstall" nocase wide ascii
	    $div2 = "ClassInstall" nocase wide ascii
	    $div3 = "DeviceInstall" nocase wide ascii
	    $div4 = "DeviceInstall" nocase wide ascii
	    $part1 = "CopyFiles" nocase wide ascii
	    $part2 = "DriverVer" nocase wide ascii
	    $part3 = "AddReg" nocase wide ascii
	    $part4 = "RegisterDlls" nocase wide ascii
	    $part5 = "HardwareId" nocase wide ascii
	    $part6 = "AddService" nocase wide ascii
	condition:
	    check_ini_bool and any of ($div*) and any of ($part*)
}
