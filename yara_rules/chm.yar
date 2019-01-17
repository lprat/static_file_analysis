//CHM HEADER ref: https://github.com/file/file/blob/63b17e62e3aeaf4eb22564538e9041402974ad49/magic/Magdir/msdos

rule chm_suspect {
	meta:
		description = "CHM contains suspect command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	strings:
	    $lnkmagic = { 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 }
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
	    (chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and (any of ($dc*) or $rdc) and (any of ($script*) or chm_file_script_bool)
}

rule CHM_script {
	meta:
		description = "MS Windows HtmlHelp Data with party script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		reference = "eb680f46c268e6eac359b574538de569"
		var_match = "chm_file_script_bool"
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
