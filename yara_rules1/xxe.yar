//Reference: https://www.blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf

rule xxe_system {
	meta:
		description = "XML with XXE SYSTEM exploit"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "MITRE ATTACK"
	    tag = "attack.execution"
	    check_level2 = "check_command_bool,extract_xxe_bool"
	strings:
	    $xml = "<?xml" nocase
	    $soap = "<soap"
		$xxe0 = /<!entity [^>]+ SYSTEM / nocase ascii wide
		$xxe1 = "<!doctype " nocase ascii wide
	condition:
	    all of ($xxe*) and ($soap or $xml or PathFile matches /.*\.xml$/i or CDBNAME matches /.*\.xml$/i)
}
