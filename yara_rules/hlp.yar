//Old format *.hlp before windows vista - https://github.com/file/file/blob/884982aa3468a05a7756ba1a46e4fe79c399ba6b/magic/Magdir/windows

rule chm_suspect {
	meta:
		description = "Potential exploit CVE-2010-0483 in HLP file - contains suspect command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/11615.zip"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
	    $hlpmagic = { 3f 5f 03 00 }
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
        $dc15 = /reg(.exe)? [QADCSRLUEIF]{1}/i
		$rdc = /sc (co|en|fa|pa|q|st)/
	condition:
	    $hlpmagic at 0 and (any of ($dc*) or $rdc)
}

rule HLP_file {
	meta:
		description = "MS Windows Help (.hlp) - not supported after windows vista"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://github.com/file/file/blob/884982aa3468a05a7756ba1a46e4fe79c399ba6b/magic/Magdir/windows"
	strings:
	    $hlpmagic = { 3f 5f 03 00 }
	condition:
	    $hlpmagic at 0 or FileType matches /CL_TYPE_MS_CHM/
}
