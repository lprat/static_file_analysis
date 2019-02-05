//LNK header 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 ref: https://github.com/file/file/blob/884982aa3468a05a7756ba1a46e4fe79c399ba6b/magic/Magdir/windows


rule Lnk_exploit_CVE {
	meta:
		description = "Lnk exploit CVE-2010-2568 or CVE-2015-0096"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 10
		reference = "https://github.com/CCrashBandicot/helpful/blob/master/CVE-2015-0096.rb & https://www.exploit-db.com/exploits/16574"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
	    $lnkmagic = { 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 }
	    $sploit1 = { 1f 00 e0 4f d0 20 ea 3a 69 10 a2 d8 08 00 2b 30 30 9d }
	    $sploit2 = { 2e 1e 20 20 ec 21 ea 3a 69 10 a2 dd 08 00 2b 30 30 9d }
	condition:
	    ($lnkmagic at 0 or FileType matches /CL_TYPE_Microsoft_Windows_Shortcut_File/) and any of ($sploit*)
}

rule Lnk_file {
	meta:
		description = "Windows shortcut (.lnk)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		check_level2 = "check_command_bool"
	strings:
	    $lnkmagic = { 4c 00 00 00 01 14 02 00  00 00 00 00 c0 00 00 00 00 00 00 46 }
	condition:
	    $lnkmagic at 0 or FileType matches /CL_TYPE_Microsoft_Windows_Shortcut_File/ or PathFile matches /.*\.lnk$/i or CDBNAME matches /.*\.lnk$/i
}
