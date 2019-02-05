rule command_certutil {
	meta:
		description = "Contains certutil command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.defense_evasion,attack.t1140"
	strings:
		$cmd = "certutil" nocase ascii wide
		$param = "decode" nocase ascii wide
	condition:
	    check_command_bool and $cmd and $param
}
		
rule command_cmd {
	meta:
		description = "Contains cmd.exe command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1059"
	strings:
		$cmd0 = "cmd " nocase ascii wide
		$cmd1 = "cmd." nocase ascii wide
		$cmd2 = "cmd," nocase ascii wide
		$cmd3 = "cmd;" nocase ascii wide
		$cmd4 = "command " nocase ascii wide
		$cmd5 = "command." nocase ascii wide
		$cmd6 = "command;" nocase ascii wide
		$cmd7 = "command," nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_bitsadmin {
	meta:
		description = "Contains cmd.exe command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1197,attack.persistence,attack.defense_evasion"
	strings:
		$cmd = "bitsadmin" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_regsvr32 {
	meta:
		description = "Contains regsvr32 command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1117,attack.defense_evasion"
	strings:
		$cmd = "regsvr32" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_rundll32 {
	meta:
		description = "Contains rundll32 command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1085,attack.defense_evasion"
	strings:
		$cmd = "rundll32" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_Regsvcs {
	meta:
		description = "Contains Regsvcs/Regasm command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1121,attack.defense_evasion"
	strings:
		$cmd0 = "Regsvcs" nocase ascii wide
		$cmd1 = "Regasm" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_InstallUtil {
	meta:
		description = "Contains InstallUtil command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1118,attack.defense_evasion"
	strings:
		$cmd = "InstallUtil" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_schtasks {
	meta:
		description = "Contains schtasks command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1053,attack.persistence,attack.defense_evasion"
	strings:
		$cmd = "schtasks" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_cscript {
	meta:
		description = "Contains cscript command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1064"
	strings:
		$cmd = "cscript" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_reg {
	meta:
		description = "Contains reg command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.persistence"
	strings:
		$cmd0 = /reg(.exe)? [QADCSRLUEIF]{1}/i nocase ascii wide
		$cmd1 = "regedit"
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_sc {
	meta:
		description = "Contains sc (service) command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1035,attack.persistence"
	strings:
		$cmd0 = /sc (co|en|fa|pa|q|st)/i nocase ascii wide
		$cmd1 = "sc.exe" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_Mshta {
	meta:
		description = "Contains Mshta command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1170,attack.defense_evasion"
	strings:
		$cmd = "Mshta" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_msxsl {
	meta:
		description = "Contains msxsl command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1220,attack.defense_evasion"
	strings:
		$cmd = "msxsl" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_hh {
	meta:
		description = "Contains hh (load chm) command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1223,attack.defense_evasion"
	strings:
		$cmd0 = "hh.exe" nocase ascii wide
		$cmd1 = "hh " nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_Bin_Ex_Proxy {
	meta:
		description = "Contains Binary Proxy Execution command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1218,attack.defense_evasion"
	strings:
		$cmd0 = "mavinject" nocase ascii wide
		$cmd1 = "SyncAppvPublishingServer" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_CMSTP {
	meta:
		description = "Contains CMSTP command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1191,attack.defense_evasion"
	strings:
		$cmd = "CMSTP" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule command_Script_Ex_Proxy {
	meta:
		description = "Contains Script Proxy Execution command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1216,attack.defense_evasion"
	strings:
		$cmd0 = "Pubprn" nocase ascii wide
		$cmd1 = "Slmgr" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_dev_utl {
	meta:
		description = "Contains Trusted dev utils command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1216,attack.defense_evasion"
	strings:
		$cmd0 = "MSBuild" nocase ascii wide
		$cmd1 = "dnx." nocase ascii wide
		$cmd2 = "rcsi." nocase ascii wide
		$cmd3 = "WinDbg" nocase ascii wide
		$cmd4 = "cdb." nocase ascii wide
		$cmd5 = "tracker." nocase ascii wide
		$cmd6 = "cdb " nocase ascii wide
		$cmd7 = "tracker " nocase ascii wide
		$cmd8 = "dnx " nocase ascii wide
		$cmd9 = "rcsi " nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

//https://ss64.com/nt/
rule cmdnt_adduser {
	meta:
		description = "Command Addusers/CMDkey"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.persistence,attack.credential_access"
	strings:
	    $cmd0 = "AddUsers " nocase ascii wide
	    $cmd1 = "AddUsers.exe" nocase ascii wide
	    $cmd2 = "cmdkey.exe" nocase ascii wide
	    $cmd3 = "cmdkey " nocase ascii wide
	    $param0 = "/c" nocase ascii wide //add
	    $param1 = "/d" nocase ascii wide //dump
	    $param2 = "/add" nocase ascii wide //add
	    $param3 = "/generic" nocase ascii wide //add
	condition:
	    check_command_bool and any of ($cmd*) and any of ($param*)
}

rule cmdnt_assoc {
	meta:
		description = "Command (assoc) Change association file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.persistence"
	strings:
	    $cmd = /ASSOC(.exe)? \.\S+=\S+/ nocase
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_bcdedit {
	meta:
		description = "Command (bcdedit) Manage Boot Configuration Data"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.persistence"
	strings:
	    $cmd = "bcdedit" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_dnscmd {
	meta:
		description = "Command (dnscmd) Manage DNS servers"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	strings:
	    $cmd = "dnscmd" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_ad {
	meta:
		description = "Command (dsget/dsquey) AD items"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	strings:
	    $cmd0 = "dsget" nocase ascii wide
	    $cmd1 = "dsquery" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule cmdnt_netsh {
	meta:
		description = "Command netsh"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	strings:
	    $cmd = "netsh" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_psexec {
	meta:
		description = "Command psexec"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.execution"
	strings:
	    $cmd = "psexec" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_SCHTASKS {
	meta:
		description = "Command SCHTASKS"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.execution"
	strings:
	    $cmd = "SCHTASKS" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_VSSADMIN {
	meta:
		description = "Command (vssadmin) shadow copu"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	strings:
	    $cmd = "VSSADMIN" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_winrm {
	meta:
		description = "Command winrm/winrs (remote control)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion,attack.discovery"
	strings:
	    $cmd0 = "winrs" nocase ascii wide
	    $cmd1 = "winrm" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}
