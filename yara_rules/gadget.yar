//https://media.blackhat.com/bh-us-12/Briefings/Shkatov/BH_US_12_Shkatov_Kohlenberg_Blackhat_Have_You_By_The_Gadgets_WP.pdf

rule Sidebar_gadget_powershell_obfusc {
	meta:
		description = "Sidebar gadget contains powershell with obfuscation"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1086,attack.execution,attack.defense_evasion"
	strings:
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
	    gadget_file_bool and any of ($dc*) and any of ($pws*) and (any of ($script*) or gadget_file_script_bool)
}

rule Sidebar_gadget_network {
	meta:
		description = "Sidebar gadget contains network risk"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1064,attack.execution,attack.defense_evasion"
	strings:
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
	    gadget_file_bool and any of ($dc*) and (any of ($script*) or gadget_file_script_bool)
}

rule Sidebar_gadget_activeX {
	meta:
		description = "Sidebar gadget contains ActiveX suspect"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.cert.ssi.gouv.fr/avis/CERTA-2000-AVI-009/"
	    tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1064,attack.execution,attack.defense_evasion"
	strings:
		$dc0 = "CreateObject" nocase
		$dc1 = "ADB880A6-D8FF-11CF-9377-00AA003B7A11" nocase
		$dc2 = "ActiveXObject" nocase
		$script1 = "<script>"
	    $script2 = "<script "
	condition:
	    gadget_file_bool and any of ($dc*) and (any of ($script*) or gadget_file_script_bool)
}

rule Sidebar_gadget_suspect {
	meta:
		description = "Sidebar gadget contains suspect command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.t1064,attack.execution,attack.defense_evasion"
	strings:
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
	    gadget_file_bool and (any of ($dc*) or $rdc) and (any of ($script*) or gadget_file_script_bool)
}

rule Sidebar_gadget_script {
	meta:
		description = "Sidebar gadget Data with party script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		reference = "eb680f46c268e6eac359b574538de569"
		var_match = "gadget_file_script_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
	strings:
	    $script1 = "<script>"
	    $script2 = "<script "
	condition:
	    gadget_file_bool and any of ($script*)
}


rule Sidebar_gadget_file_xml {
	meta:
		description = "Sidebar gadget File XML"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://nakedsecurity.sophos.com/2012/07/12/disable-windows-sidebar-gadgets/"
		var_match = "gadget_file_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
	    $xml = "<?xml" nocase
	    $gadget0 = "/gadget" nocase
	    $gadget1 = "<gadget" nocase
	    
	condition:
	    FileParentType matches /->CL_TYPE_ZIP$/ and $xml and any of ($gadget*)
}

rule Sidebar_gadget_file {
	meta:
		description = "Sidebar Gadget File archive"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "gadget_file_bool"
	strings:
	    $zip1magic = { 50 4b 03 04 0a }
	    $gadget = "gadget.xml" nocase
	condition:
	    ($zip1magic at 0 or FileType matches /CL_TYPE_ZIP/) and $gadget
}
