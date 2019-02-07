//https://ss64.com/vb/
//Deobfusc by emulation with https://github.com/decalage2/ViperMonkey
rule vbscript_obfusc {
	meta:
		description = "Vbscript obfuscated"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
	    tag = "attack.defense_evasion"
	strings:
		$obf0 = "Replace" nocase
		$obf1 = "split" nocase
		$obf2 = "Xor" nocase
		$obf3 = "Mod" nocase
		$obf4 = "chr(" nocase
		$obf5 = "mid(" nocase
		$obf6 = "asc(" nocase
		$obf7 = "KeyString(" nocase
		$obf8 = /([^ ]+\^[^ ]+){2,}/ nocase
		$obf9 = /[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf10 = /[aeuoiy]{4,}/ nocase
		$obf11 = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/ nocase // base 64
		$obf12 = "ChrW(" nocase
		$obf13 = "ChrB(" nocase
		$obf14 = "abs(" nocase
		$obf15 = "eval(" nocase
		$obf16 = "join(" nocase
	condition:
	    check_vbscript_bool and 3 of ($obf*)
}

rule vbscript_regm {
	meta:
		description = "Vbscript modify registry"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.persistence"
	strings:
		$elem0 = ".RegDelete" nocase
		$elem1 = ".RegWrite" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_regr {
	meta:
		description = "Vbscript read registry"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.persistence"
	strings:
		$elem0 = ".RegRead" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_run {
	meta:
		description = "Vbscript run command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
	    tag = "attack.execution"
	strings:
		$elem0 = ".Run" nocase
		$elem1 = ".ShellExecute" nocase
		$elem2 = "Shell.Application" nocase
		$elem3 = ".Exec" nocase
		$elem4 = "wscript.shell" nocase
		$elem5 = "Execute " nocase
		$elem6 = ".AppActivate" nocase
		$elem7 = "Wscript.Application" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_lnk {
	meta:
		description = "Vbscript Create shortcut"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.persistence"
	strings:
		$elem0 = ".CreateShortcut" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_key {
	meta:
		description = "Vbscript send keys"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.execution"
	strings:
		$elem0 = ".SendKeys" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_service {
	meta:
		description = "Vbscript service start/stop"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.execution"
	strings:
		$elem0 = ".servicest" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_shutd {
	meta:
		description = "Vbscript shutdown windows"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.execution"
	strings:
		$elem0 = ".ShutdownWindow" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_network {
	meta:
		description = "Vbscript use network drive"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.discovery"
	strings:
		$elem0 = ".Network" nocase
		$elem1 = ".EnumNetworkDrives" nocase
		$elem2 = ".MapNetworkDrive" nocase
		$elem3 = ".RemoveNetworkDrive" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}


rule vbscript_fs {
	meta:
		description = "Vbscript use filesystem"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.exfiltration,attack.collection"
	strings:
		$elem0 = "FileSystemObject" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_fs_copy {
	meta:
		description = "Vbscript use filesystem for copy/move file/folder"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.exfiltration,attack.collection"
	strings:
		$elem0 = ".CopyFile" nocase
		$elem1 = ".CopyFolder" nocase
		$elem2 = ".MoveFile" nocase
		$elem3 = ".MoveFolder" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_fs_create {
	meta:
		description = "Vbscript use filesystem for create file/folder"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.exfiltration"
	strings:
		$elem0 = ".CreateFolder" nocase
		$elem1 = ".CreateTextFile" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_fs_delete {
	meta:
		description = "Vbscript use filesystem for delete file/folder"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	strings:
		$elem0 = ".DeleteFile" nocase
		$elem1 = ".DeleteFolder" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_fs_checkf {
	meta:
		description = "Vbscript use filesystem for check file exist"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	strings:
		$elem0 = ".DriveExists" nocase
		$elem1 = ".FileExists" nocase
		$elem2 = ".FolderExists" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_fs_open {
	meta:
		description = "Vbscript use filesystem for open file (exist or create)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.exfiltration"
	strings:
		$elem0 = ".OpenTextFile" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_eval {
	meta:
		description = "Vbscript use function eval()"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.defense_evasion"
	strings:
		$elem0 = "eval(" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

rule vbscript_wmi {
	meta:
		description = "Vbscript call wmi"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion,attack.collection,attack.persistence"
	strings:
		$elem0 = "\\root\\cimv2" nocase
		//$elem1 = ".ExecQuery" nocase // false positive
		$elem2 = "Winmgmts:" nocase
		$elem3 = "WbemScripting.SWbemLocator" nocase
	condition:
	    check_vbscript_bool and any of ($elem*)
}

