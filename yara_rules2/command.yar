rule command_certutil {
	meta:
		description = "Contains certutil command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
		ids = "win_exec"
		ids = "win_exec"
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
		ids = "win_exec"
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
		description = "bitsadmin command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
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
		ids = "win_exec"
	    tag = "attack.defense_evasion"
	strings:
	    $cmd = "dnscmd" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_dsad {
	meta:
		description = "Command (dsget/dsquey/dsadd) AD items"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	strings:
	    $cmd0 = "dsget" nocase ascii wide
	    $cmd1 = "dsquery" nocase ascii wide
	    $cmd2 = "dsadd" nocase ascii wide
	    $cmd3 = "dsacls" nocase ascii wide
	    $cmd4 = "dsmod" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule cmdnt_netshb {
	meta:
		description = "Command netsh"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.discovery"
	strings:
	    $cmd = "netsh" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_netsh {
	meta:
		description = "Command netsh change config"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_exec"
	    tag = "attack.defense_evasion"
	strings:
	    $cmd = /netsh(.exe)* [^\n]* (add|set|install|delete)/ nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_psexec {
	meta:
		description = "Command psexec"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
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
		ids = "win_exec"
	    tag = "attack.execution"
	strings:
	    $cmd = "SCHTASKS" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_VSSADMIN {
	meta:
		description = "Command (vssadmin/diskshadow) shadow copu"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.defense_evasion"
	strings:
	    $cmd0 = "VSSADMIN" nocase ascii wide
	    $cmd1 = "diskshadow" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule cmdnt_winrm {
	meta:
		description = "Command winrm/winrs (remote control)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.defense_evasion,attack.discovery"
	strings:
	    $cmd0 = "winrs" nocase ascii wide
	    $cmd1 = "winrm" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_fdisk {
	meta:
		description = "Command fdisk"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		ids = "win_exec"
	    tag = "attack.defense_evasion,attack.discovery"
	strings:
	    $cmd0 = "fdisk" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_ipconfig {
	meta:
		description = "Command ipconfig"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		ids = "win_exec"
	    tag = "attack.defense_evasion,attack.discovery"
	strings:
	    $cmd0 = "ipconfig" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net0 {
	meta:
		description = "Command net manage service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		ids = "win_exec"
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/net-service.html"
	strings:
	    $cmd0 = /(\s+|^|\n)net(.exe)* start \S+/ nocase ascii wide
	    $cmd1 = /(\s+|^|\n)net(.exe)* pause \S+/ nocase ascii wide
	    $cmd2 = /(\s+|^|\n)net(.exe)* stop \S+/ nocase ascii wide
	    $cmd3 = /(\s+|^|\n)net(.exe)* continue \S+/ nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net1 {
	meta:
		description = "Command net change time"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		ids = "win_exec"
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/net-time.html"
	strings:
	    $cmd0 = /(\s+|^|\n)net(.exe)* time [^\n]* \/SET/ nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net2 {
	meta:
		description = "Command net print"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		reference = "https://ss64.com/nt/net-print.html"
	strings:
	    $cmd0 = "net print" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net3 {
	meta:
		description = "Command net file/session"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/net-session.html"
	strings:
	    $cmd0 = "net file" nocase ascii wide
	    $cmd1 = "net session" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net4 {
	meta:
		description = "Command net config change"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/net-config.html"
	strings:
	    $cmd0 = "net config server" nocase ascii wide
	    $cmd1 = "net config workstation" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net4b {
	meta:
		description = "Command net computer"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/net-config.html"
	strings:
	    $cmd0 = "net computer" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net5 {
	meta:
		description = "Command net add user"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_exec"
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/net-useradmin.html"
	strings:
	    $cmd0 = /net(.exe)* user [^\n]*\/add/ nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net6 {
	meta:
		description = "Command net add group"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_exec"
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/net-useradmin.html"
	strings:
	    $cmd0 = /net(.exe)* (group|localgroup) [^\n]*\/add/ nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net7 {
	meta:
		description = "Command net account change"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_exec"
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/net-useradmin.html"
	strings:
	    $net = /net(.exe)* account [^\n]*(FORCELOGOFF|MINPWLENGTH|MAXPWAGE|MINPWAGE|UNIQUEPW)/ nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_net7b {
	meta:
		description = "Command net account"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/net-useradmin.html"
	strings:
	    $net = "net account" nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_net8 {
	meta:
		description = "Command net user/group"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/net-useradmin.html"
	strings:
	    $cmd0 = "net user" nocase ascii wide
	    $cmd1 = "net group" nocase ascii wide
	condition:
	    check_command_bool and any of($cmd*)
}

rule cmdnt_net9 {
	meta:
		description = "Command net modify user"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_exec"
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/net-useradmin.html"
	strings:
	    $net = /net(.exe)* user [^\n]*(\/PROFILEPATH|\/scriptpath)|net user \S+ \S+/ nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_net10 {
	meta:
		description = "Command net share"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/net-share.html"
	strings:
	    $net = "net share" nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_net11 {
	meta:
		description = "Command net share create"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.discovery,attack.collection"
	    reference = "https://ss64.com/nt/net-share.html"
	strings:
	    $net = /net(.exe)* share [^\n]*=[^\n]*/ nocase ascii wide
	    $net0 = "/delete"
	condition:
	    check_command_bool and $net and not $net0
}

rule cmdnt_net12 {
	meta:
		description = "Command net use"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/net-use.html"
	strings:
	    $net = "net use" nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_net13 {
	meta:
		description = "Command net use URI"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/net-use.html"
	strings:
	    $net = /net(.exe)* use [^\n]*\\\\[^\n]*/ nocase ascii wide
	    $net0 = "/delete"
	condition:
	    check_command_bool and $net and not $net0
}

rule cmdnt_net14 {
	meta:
		description = "Command net use persist"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		ids = "win_exec"
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/net-use.html"
	strings:
	    $net = /net(.exe)* use [^\n]*(\/PERSISTENT|\/P\:yes)/ nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_net15 {
	meta:
		description = "Command net view"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/net-view.html"
	strings:
	    $net = "net view" nocase ascii wide
	condition:
	    check_command_bool and $net
}

rule cmdnt_ad {
	meta:
		description = "Command csvde/ldifde explore AD"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery,attack.collect"
	    reference = "https://ss64.com/nt/csvde.html"
	strings:
	    $cmd0 = "csvde" nocase ascii wide
	    $cmd1 = "ldifde" nocase ascii wide
	condition:
	    check_command_bool and all of ($cmd*)
}

rule cmdnt_info {
	meta:
		description = "Command systeminfo/msinfo32"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/msinfo32.html"
	strings:
	    $cmd0 = "systeminfo" nocase ascii wide
	    $cmd1 = "msinfo32" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule cmdnt_task {
	meta:
		description = "Command tasklist"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/tasklist.html"
	strings:
	    $cmd0 = "tasklist" nocase ascii wide
	    $cmd1 = "tlist" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule cmdnt_taskk {
	meta:
		description = "Command taskkill"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/taskkill.html"
	strings:
	    $cmd0 = "taskkill" nocase ascii wide
	    $cmd1 = "tskill" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule cmdnt_telnet {
	meta:
		description = "Command telnet"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/telnet.html"
	strings:
	    $cmd = "telnet" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_wbadmin {
	meta:
		description = "Command wbadmin"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/wbadmin.html"
	strings:
	    $cmd = "wbadmin" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_wevtutil {
	meta:
		description = "Command wevtutil"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion,attack.t1070"
	    reference = "https://ss64.com/nt/wevtutil.html"
	strings:
	    $cmd = "wevtutil" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_vmconnect {
	meta:
		description = "Command vmconnect"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/vmconnect.html"
	strings:
	    $cmd = "vmconnect" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_sysmon {
	meta:
		description = "Command sysmon"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/sysmon.html"
	strings:
	    $cmd = "sysmon" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_start {
	meta:
		description = "Command start a program with minimiz"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion"
	    ids = "win_exec"
	    reference = "https://ss64.com/nt/start.html"
	strings:
	    $cmd = /start(.exe)* [^\n]*\/MIN(\s+|$|\n)/ nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_shortcut {
	meta:
		description = "Command shortcut"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.persistence"
	    ids = "win_exec"
	    reference = "https://ss64.com/nt/shortcut.html"
	strings:
	    $cmd = /SHORTCUT(.exe)* [^\n]*\-n [^\n]*/ nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_runas {
	meta:
		description = "Command runas/shellrunas"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion,attack.Privilege_Escalation,attack.T1134"
	    reference = "https://ss64.com/nt/runas.html"
	strings:
	    $cmd = "runas" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_share0 {
	meta:
		description = "Command share list"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/share.html"
	strings:
	    $cmd = "Share.vbs /L" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_share1 {
	meta:
		description = "Command share create"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.collect,attack.discovery"
	    reference = "https://ss64.com/nt/share.html"
	strings:
	    $cmd = "Share.vbs /C" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_route {
	meta:
		description = "Command route add/change"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/route.html"
	strings:
	    $cmd = "route" nocase ascii wide
	    $para0 = "add" nocase ascii wide
	    $para1 = "change" nocase ascii wide
	condition:
	    check_command_bool and $cmd and any of ($para*)
}


rule cmdnt_query {
	meta:
		description = "Command query"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/query-session.html"
	strings:
	    $cmd = /query(.exe)* (session|process|termserver|user)/ nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_pspasswd {
	meta:
		description = "Command pspasswd"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.credential_access"
	    reference = "https://ss64.com/nt/pspasswd.html"
	strings:
	    $cmd = "pspasswd" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_ntbackup {
	meta:
		description = "Command ntbackup"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/ntbackup.html"
	strings:
	    $cmd = "ntbackup" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_netstat {
	meta:
		description = "Command netstat"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion,attack.discovery"
	    reference = "https://ss64.com/nt/netstat.html"
	strings:
	    $cmd = "netstat" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_nbtstat {
	meta:
		description = "Command nbtstat"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/nbtstat.html"
	strings:
	    $cmd = "nbtstat" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_mstsc {
	meta:
		description = "Command mstsc"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.discovery"
	    reference = "https://ss64.com/nt/mstsc.html"
	strings:
	    $cmd = "mstsc" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_msiexec {
	meta:
		description = "Command msiexec"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.persistence"
	    reference = "https://ss64.com/nt/msiexec.html"
	strings:
	    $cmd = "msiexec" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_gpresult {
	meta:
		description = "Command gpresult"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	    reference = "https://ss64.com/nt/gpresult.html"
	strings:
	    $cmd = "gpresult" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_ftp {
	meta:
		description = "Command ftp"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.discovery"
	    ids = "win_exec"
	    reference = "https://ss64.com/nt/ftp.html"
	strings:
	    $cmd = /(^|\n|\s+)ftp(.exe)* [^\n]*/ nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_python {
	meta:
		description = "Command python"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	strings:
	    $cmd = "python" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_cipher {
	meta:
		description = "Command cipher"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion"
	    ids = "win_exec"
	    reference = "https://ss64.com/nt/cipher.html"
	strings:
	    $cmd = /cipher(.exe)* (\/e|\/d|\/x) [^\n]*/ nocase ascii wide
	condition:
	    check_command_bool and $cmd
}

rule cmdnt_rat {
	meta:
		description = "Use famous tool RAT"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
	    tag = "attack.defense_evasion,attack.command_control"
	    ids = "win_exec"
	strings:
	    $rat0 = "TeamViewer" nocase ascii wide
	    $rat1 = "Splashtop" nocase ascii wide
	    $rat2 = "TightVNC" nocase ascii wide
	    $rat3 = "Mikogo" nocase ascii wide
	    $rat4 = "LogMeIn" nocase ascii wide
	    $rat5 = "pcAnywhere" nocase ascii wide
	    $rat6 = "GoToMyPC" nocase ascii wide
	    $rat7 = "Radmin" nocase ascii wide
	    $rat8 = "UltraVNC" nocase ascii wide
	    $rat9 = "AeroAdmin" nocase ascii wide
	    $rat10 = "AnyDesk" nocase ascii wide
	    $rat11 = "Uvnc" nocase ascii wide
	    $rat12 = "RealVnc" nocase ascii wide
	    $rat13 = "Bomgar" nocase ascii wide
	    $rat14 = "meterpreter" nocase ascii wide
	condition:
	    check_command_bool and any of ($rat*)
}

rule cmdnt_cred {
	meta:
		description = "Use famous tool for credential dump"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
	    tag = "attack.credential_access,attack.t1003"
	    reference = "https://attack.mitre.org/techniques/T1003/"
	    ids = "win_exec"
	strings:
	    $cred1 = "pwdumpx" nocase ascii wide
	    $cred2 = "gsecdump" nocase ascii wide
	    $cred3 = "Mimikatz" nocase ascii wide
	    $cred4 = "secretsdump" nocase ascii wide
	    $cred5 = "reg save HKLM\\sam" nocase ascii wide
	    $cred6 = "reg save HKLM\\system" nocase ascii wide
	    $cred7 = "ntdsutil" nocase ascii wide
	    $cred8 = "Minidump" nocase ascii wide
	    $cred9 = "sekurlsa" nocase ascii wide
	    $cred10 = "lsadump" nocase ascii wide
	    $cred11 = "laZagne" nocase ascii wide
	    $cred12 = "WCESERVICE" nocase ascii wide
	    $cred13 = "WCE_SERVICE" nocase ascii wide
	    $cred14 = "mimilib" nocase ascii wide
	    $cred15 = "eo.oe.kiwi" nocase ascii wide
	    $cred16 = /(cred|crendential|pass|)dump|keylogger|sniff/ nocase ascii wide
	condition:
	    check_command_bool and any of ($cred*)
}

rule cmdnt_evil {
	meta:
		description = "Suspect evil command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.execution"
	    ids = "win_exec"
	    reference = "https://github.com/Neo23x0/signature-base/blob/7c8745c59ed43cf60f1dd5bace2339f19824fc9c/yara/gen_p0wnshell.yar"
	strings:
	    $evil1 = "pwdumpx" nocase ascii wide
	    $evil2 = "gsecdump" nocase ascii wide
	    $evil3 = "powersploit" nocase ascii wide
	    $evil4 = "empire" nocase ascii wide
	    $evil5 = "EncodedPayload.bat" nocase ascii wide
	    $evil6 = "powercat" nocase ascii wide
	    $evil7 = "p0wnedShell" nocase ascii wide
	    $evil8 = "TaterCommand" nocase ascii wide
	    $evil9 = "P0wnedListener" nocase ascii wide
	    $evil10 = "Pshell." nocase ascii wide
	    $evil11 = "TaterCommand" nocase ascii wide
	condition:
	    check_command_bool and any of ($evil*)
}

rule command_Msdt {
	meta:
		description = "Contains Msdt command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
		ids = "win_exec"
	    tag = "attack.execution,attack.tT1170,attack.defense_evasion"
	strings:
		$cmd = "msdt" nocase ascii wide
	condition:
	    check_command_bool and $cmd
}
