//https://ss64.com/ps/
rule powershell_comp {
	meta:
		description = "Powershell use (un)compress archive"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.execution,attack.t1086,attack.exfiltration"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "Compress-Archive" nocase ascii wide
		$dc1 = "Expand-Archive" nocase ascii wide
		$dc2 = "New-Zipfile" nocase ascii wide
		$dc3 = "Expand-Zipfile" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}

rule powershell_com {
	meta:
		description = "Powershell use COM obj"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.execution,attack.defense_evasion"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "-com " nocase ascii wide
		$dc1 = "-comobject" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}

rule powershell_cim {
	meta:
		description = "Powershell use CIM/WMI class"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.collection,attack.discovery"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "-CimInstance" nocase ascii wide
		$dc1 = "-CIMSession" nocase ascii wide
		$dc2 = "-cimclass" nocase ascii wide
		$dc3 = "Register-WmiEvent" nocase ascii wide
		$dc4 = "-gcim" nocase ascii wide
		$dc5 = "-ncim" nocase ascii wide
		$dc6 = "WmiObject" nocase ascii wide
		$dc7 = "WmiMethod" nocase ascii wide
		$dc8 = "-iwmi" nocase ascii wide
		$dc9 = "-gwmi" nocase ascii wide
		$dc10 = "-rwmi" nocase ascii wide
		$dc11 = "WmiInstance" nocase ascii wide
		$dc12 = "CIMMethod" nocase ascii wide
		$dc13 = "CimIndicationEvent" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}

rule powershell_iex {
	meta:
		description = "Powershell run powershell expression"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.collection,attack.discovery"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "Invoke-Expression" nocase ascii wide
		$dc1 = "-IEX" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}


rule powershell_get {
	meta:
		description = "Powershell get item (registry/file)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.collection,attack.discovery"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "Get-Item" nocase ascii wide
		$dc1 = "-gi" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}

rule powershell_enc {
	meta:
		description = "Powershell use encoded objet in param (obfuscation)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "-enc " nocase ascii wide
		$dc1 = "-EncodedCommand" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}

rule powershell_log {
	meta:
		description = "Powershell use clear eventlog"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc0 = "Clear-eventlog" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($dc*)
}

rule command_powershell {
	meta:
		description = "Contains powershell command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1086"
	strings:
		$pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$cmd0 = "Invoke-Command" nocase ascii wide
		$cmd1 = "-icm" nocase ascii wide
		$cmd2 = "Invoke-Item" nocase ascii wide
		$cmd3 = "-ii " nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($cmd*)
}

rule powershell_job {
	meta:
		description = "Powershell use scheduled job"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.persistence"
	strings:
		$pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$cmd0 = "start-Job" nocase ascii wide
		$cmd1 = "-sajb" nocase ascii wide
		$cmd2 = "ScheduledJob" nocase ascii wide
		$cmd3 = "JobTrigger" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($cmd*)
}

rule powershell_service {
	meta:
		description = "Powershell use service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.persistence"
	strings:
		$pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$cmd0 = "-service" nocase ascii wide
		$cmd1 = "-gsv" nocase ascii wide
		$cmd2 = "-sasv" nocase ascii wide
		$cmd3 = "-spsv" nocase ascii wide
	condition:
	    check_command_bool and any of ($pws*) and any of ($cmd*)
}

rule powershell_obfusc {
	meta:
		description = "Powershell command obfuscated"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://www.sans.org/cyber-security-summit/archives/file/summit-archive-1492186586.pdf"
		tag = "attack.execution,attack.t1086,attack.defense_evasion"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc1 = "-Join" nocase ascii wide
		$dc2 = ".split" nocase ascii wide
        $dc3 = ".Replace" nocase ascii wide
        $dc4 = "Concat(" nocase ascii wide
        $dc5 = "Reverse" nocase ascii wide
        $dc6 = "-EncodedCommand" nocase ascii wide
        $dc7 = "-Enc " nocase ascii wide
        $dc8 = " -f "
        $dc9 = "hidden" nocase ascii wide
        $dc10 = "-nop" nocase ascii wide
	condition:
	    check_command_bool and 2 of ($dc*) and any of ($pws*)
}

rule powershell_netw {
	meta:
		description = "Powershell use network"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		tag = "attack.execution,attack.t1086,attack.defense_evasion"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc1 = "downloadfile" nocase ascii wide
		$dc2 = "webclient" nocase ascii wide
        $dc3 = "DownloadString" nocase ascii wide
        $dc4 = "webrequest" nocase ascii wide
        $dc5 = "RestMethod" nocase ascii wide 
        $dc6 = "BitsTransfer" nocase ascii wide
        $dc7 = "WebServiceProxy" nocase ascii wide
	condition:
	    check_command_bool and any of ($dc*) and any of ($pws*)
}

rule powershell_amsi {
	meta:
		description = "Powershell AmsiUtils (Bypass AMSI)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		tag = "attack.execution,attack.t1086,attack.defense_evasion"
	strings:
	    $pws0 = "powershell" nocase ascii wide
		$pws1 = "IEX" nocase ascii wide
		$pws2 = ".Invoke" nocase ascii wide
		$pws3 = "new-object" nocase ascii wide
		$dc1 = "AmsiUtils" nocase ascii wide
	condition:
	    check_command_bool and any of ($dc*) and any of ($pws*)
}

rule Base64_PS1_Shellcode {
   meta:
      description = "Detects Base64 encoded PS1 Shellcode"
      author = "Nick Carr, David Ledbetter"
      reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
      date = "2018-11-14"
      weight = 6
      tag = "attack.execution,attack.t1086,attack.defense_evasion"
   strings:
      $substring = "AAAAYInlM"
      $pattern1 = "/OiCAAAAYInlM"
      $pattern2 = "/OiJAAAAYInlM"
   condition:
      check_command_bool and $substring and 1 of ($p*)
}
