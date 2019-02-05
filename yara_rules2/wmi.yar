rule command_wmic {
	meta:
		description = "Contains wmic command call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.tT1047"
	strings:
		$cmd0 = "wmic" nocase ascii wide
		$cmd1 = "WBEMTEST" nocase ascii wide
	condition:
	    check_command_bool and any of ($cmd*)
}

rule command_wmis {
	meta:
		description = "WMI call with persistence subscription"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "http://la.trendmicro.com/media/misc/understanding-wmi-malware-research-paper-en.pdf"
	    tag = "attack.persistence"
	strings:
		$first = "subscription" nocase ascii wide
		$param0 = "__EventFilter" nocase ascii wide
		$param1 = "__FilterToConsumerBinding" nocase ascii wide
		$param2 = "__TimerInstruction" nocase ascii wide
		$param3 = "__EventConsumer" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and $first and any of ($param*)
}

rule command_wmirun {
	meta:
		description = "WMI call with persistence start menu"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf"
	    tag = "attack.persistence"
	strings:
		$first = "__InstanceCreationEvent" nocase ascii wide
		$param = "Win32_StartupCommand" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and $first and $param
}

rule command_wmireg {
	meta:
		description = "WMI call change registry"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf"
	    tag = "attack.persistence"
	strings:
		$wmi0 = "RegistryKeyChangeEvent" nocase ascii wide
		$wmi1 = "RegistryValueChangeEvent" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and any of ($wmi*)
}

rule command_wmiserv {
	meta:
		description = "WMI call with persistence service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf"
	    tag = "attack.persistence"
	strings:
		$first = "__InstanceCreationEvent" nocase ascii wide
		$param = "Win32_Service" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and $first and $param
}

rule command_wmiprov {
	meta:
		description = "WMI create provider"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf"
	    tag = "attack.persistence"
	strings:
		$first = "__InstanceCreationEvent" nocase ascii wide
		$param = "__Provider" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and $first and $param
}

rule command_wminamed {
	meta:
		description = "WMI create namepipe"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf"
	    tag = "attack.c2c"
	strings:
		$wmi0 = "__NamespaceCreationEvent" nocase ascii wide
		$wmi1 = "__NamespaceModificationEvent" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and any of ($wmi*)
}

rule command_wmir {
	meta:
		description = "WMI create new call command"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Graeber-Abusing-Windows-Management-Instrumentation-WMI-To-Build-A-Persistent%20Asynchronous-And-Fileless-Backdoor-wp.pdf"
	    tag = "attack.persistence"
	strings:
		$el0 = "Win32_Process" nocase ascii wide
		$el1 = "-Name" nocase ascii wide
		$el2 = "Create" nocase ascii wide
	condition:
	    (check_command_bool or check_vbscript_bool) and all of ($el*)
}
