rule vbscript {
	meta:
		description = "Potential vbscript file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 0
		check_level2 = "check_vbscript_bool"
	strings:
		$vb0 = /(^|\s+|\n)sub\s+[^\(]+\(.*\)/ nocase
		$vb1 = /(^|\s+|\n)set\s+[^ ]+\s*\=\s*[^\(]+\(/ nocase
		$vb2 = /(^|\s+|\n)end\s+sub(\s+|\n|$)/ nocase
	condition:
	    any of ($vb*)
}
