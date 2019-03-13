rule xxe_command{
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 0
		description = "Extract XXE Command"
		ids = "xxe_command"
	strings:
	    $xxe = /SYSTEM [^\>]+\>/ nocase ascii wide
	condition:
		extract_xxe_bool and $xxe
}
