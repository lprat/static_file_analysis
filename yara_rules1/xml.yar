// XML CONTENT

rule xml_with_script {
	meta:
		description = "XML with script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "MITRE ATTACK"
	    tag = "attack.execution"
	    check_level2 = "check_command_bool,check_clsid_bool,check_vbscript_bool"
	    var_match = "xmlscript_file_bool"
	strings:
	    $xml = "<?xml" nocase ascii wide
	    $soap = "<soap" nocase ascii wide
	    $script = "</script>" nocase ascii wide
	    $script1 = "<![CDATA[" nocase ascii wide
	condition:
	    ($soap or $xml or PathFile matches /.*\.xml$/i or CDBNAME matches /.*\.xml$/i) and (any of ($script*))
}

rule xml_content {
	meta:
		description = "XML content"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		reference = "MITRE ATTACK"
	    var_match = "xml_file_bool"
	strings:
	    $xml = "<?xml" nocase ascii wide
	    $soap = "<soap" nocase ascii wide
	condition:
	    ($soap or $xml or PathFile matches /.*\.xml$/i or CDBNAME matches /.*\.xml$/i)
}
