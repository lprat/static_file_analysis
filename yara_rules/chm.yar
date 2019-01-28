//CHM HEADER ref: https://github.com/file/file/blob/63b17e62e3aeaf4eb22564538e9041402974ad49/magic/Magdir/msdos

rule chm_powershell_obfusc {
	meta:
		description = "CHM contains powershell with obfuscation"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1086,attack.execution,attack.defense_evasion"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
	    $pws0 = "powershell" nocase
		$pws1 = "IEX" nocase
		$dc1 = "-Join" nocase
		$dc2 = ".split" nocase
        $dc3 = ".Replace" nocase
        $dc4 = "Concat(" nocase
        $dc5 = "Reverse" nocase
        $dc6 = "-EncodedCommand" nocase
        $dc7 = "-Enc " nocase
        $dc8 = " -f "
		$script1 = "<script>"
	    $script2 = "<script "
	condition:
	    ($chmmagic at 0 or chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and any of ($dc*) and any of ($pws*) and (any of ($script*) or chm_file_script_bool)
}

rule chm_network {
	meta:
		description = "CHM contains network risk"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1064,attack.execution,attack.defense_evasion"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
		$dc0 = "XMLHTTP" nocase
		$dc1 = "Net.WebClient" nocase
		$dc2 = "DownloadFile" nocase
		$dc3 = "Start-BitsTransfer" nocase
		$dc4 = "BitsTransfer" nocase
		$dc5 = "WebRequest" nocase
		$dc6 = "/download" nocase
		$dc7 = "-urlcache" nocase
		$dc8 = "WinHttpRequest" nocase
		$dc9 = "DownloadString" nocase
		$dc10 = "RestMethod" nocase
		$dc11 = "InternetExplorer" nocase
		$script1 = "<script>"
	    $script2 = "<script "
	condition:
	    ($chmmagic at 0 or chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and any of ($dc*) and (any of ($script*) or chm_file_script_bool)
}

rule chm_activeX {
	meta:
		description = "CHM contains ActiveX suspect"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.cert.ssi.gouv.fr/avis/CERTA-2000-AVI-009/"
	    tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1064,attack.execution,attack.defense_evasion"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
		$dc0 = "CreateObject" nocase
		$dc1 = "ADB880A6-D8FF-11CF-9377-00AA003B7A11" nocase
		$dc2 = "ActiveXObject" nocase
		$script1 = "<script>"
	    $script2 = "<script "
	condition:
	    ($chmmagic at 0 or chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and any of ($dc*) and (any of ($script*) or chm_file_script_bool)
}

rule chm_suspect {
	meta:
		description = "CHM contains suspect command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1064,attack.execution,attack.defense_evasion"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
		$dc0 = "powershell" nocase
		$dc1 = "cmd" nocase
		$dc2 = "regsvr32" nocase
		$dc3 = "rundll32" nocase
		$dc4 = "hh.exe" nocase
		$dc5 = "InstallUtil" nocase
		$dc6 = "schtasks" nocase
		$dc7 = "Mshta" nocase
		$dc8 = "Regsvcs" nocase
		$dc9 = "Regasm" nocase
		$dc10 = "cscript" nocase
		$dc11 = "msxsl" nocase
        $dc12 = "wmic" nocase
        $dc13 = "sc.exe" nocase
        $dc14 = "sc" nocase
		$rdc = /sc (co|en|fa|pa|q|st)/
		$script1 = "<script>"
	    $script2 = "<script "
	condition:
	    ($chmmagic at 0 or chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and (any of ($dc*) or $rdc) and (any of ($script*) or chm_file_script_bool)
}

rule CHM_script {
	meta:
		description = "MS Windows HtmlHelp Data with party script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		reference = "eb680f46c268e6eac359b574538de569"
		var_match = "chm_file_script_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
	strings:
	    $script1 = "<script>"
	    $script2 = "<script "
	condition:
	    (chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and any of ($script*)
}

rule CHM_file {
	meta:
		description = "MS Windows HtmlHelp Data (.chm)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		reference = "eb680f46c268e6eac359b574538de569"
		var_match = "chm_file_bool"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
	condition:
	    $chmmagic at 0 or FileType matches /CL_TYPE_MS_CHM/
}
