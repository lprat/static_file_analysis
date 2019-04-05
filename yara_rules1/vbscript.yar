rule File_contains_VB {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Suspect vbscript file embed from another File (PARENT)"
                check_level2 = "check_vbscript_bool,check_command_bool,check_clsid_bool,check_winapi_bool,check_registry_bool"
	strings:
		$vb0 = /(^|\s+|\n)sub\s+[^\(]+\(.*\)/ nocase
		$vb1 = /(^|\s+|\n)set\s+[^ ]+\s*\=\s*[^\(]+\(/ nocase
		$vb2 = /(^|\s+|\n)end\s+sub(\s+|\n|$)/ nocase
                $scriptvb0 = "CreateObject" nocase
                $scriptvb1 = "</script>" nocase
	condition:
		(any of ($vb*) or FileType matches /CL_TYPE_VBA/ or all of ($scriptvb*)) and FileParentType matches /->/
}

rule vbscript {
	meta:
		description = "Potential vbscript file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		check_level2 = "check_vbscript_bool,check_command_bool,check_clsid_bool,check_winapi_bool,check_registry_bool"
		var_match = "vb_file_bool"
	strings:
		$vb0 = /(^|\s+|\n)sub\s+[^\(]+\(.*\)/ nocase
		$vb1 = /(^|\s+|\n)set\s+[^ ]+\s*\=\s*[^\(]+\(/ nocase
		$vb2 = /(^|\s+|\n)end\s+sub(\s+|\n|$)/ nocase
	condition:
	    (any of ($vb*) or FileType matches /CL_TYPE_VBA/)
}
