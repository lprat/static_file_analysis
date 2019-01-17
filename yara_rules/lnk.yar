//LNK header 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 ref: https://github.com/file/file/blob/884982aa3468a05a7756ba1a46e4fe79c399ba6b/magic/Magdir/windows
rule Lnk_suspect {
	meta:
		description = "Lnk use suspect command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://github.com/carnal0wnage/python_lnk_make"
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
	condition:
	    $lnkmagic at 0 and (any of ($dc*) or $rdc)
}

rule Lnk_exploit_CVE {
	meta:
		description = "Lnk exploit CVE-2010-2568 or CVE-2015-0096"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 10
		reference = "https://github.com/CCrashBandicot/helpful/blob/master/CVE-2015-0096.rb & https://www.exploit-db.com/exploits/16574"
	strings:
	    $lnkmagic = { 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 }
	    $sploit1 = { 1f 00 e0 4f d0 20 ea 3a 69 10 a2 d8 08 00 2b 30 30 9d }
	    $sploit2 = { 2e 1e 20 20 ec 21 ea 3a 69 10 a2 dd 08 00 2b 30 30 9d }
	condition:
	    $lnkmagic at 0 and any of ($sploit*)
}

rule Lnk_file {
	meta:
		description = "Lnk Windows shortcut"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		reference = "eb680f46c268e6eac359b574538de569"
	strings:
	    $lnkmagic = { 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 }
	condition:
	    $lnkmagic at 0
}
