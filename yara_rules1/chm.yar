rule CHM_script {
	meta:
		description = "MS Windows HtmlHelp Data with party script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		var_match = "chm_file_script_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
		check_level2 = "check_registry_bool,check_command_bool,check_vbscript_bool"
	strings:
	    $script1 = "<script>" nocase
	    $script2 = "<script " nocase
	condition:
	    (chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and any of ($script*)
}

rule CHM_files_interne {
	meta:
		description = "File of CHM file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 0
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
		check_level2 = "check_entropy_bool"
	condition:
	    FileParentType matches /->CL_TYPE_MS_CHM$/
}

rule CHM_obj_classid {
	meta:
		description = "MS Windows HtmlHelp Data with party Obj Classid"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		var_match = "chm_file_script_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
		check_level2 = "check_clsid_bool,check_command_bool"
	strings:
	    $script1 = "<OBJECT>" nocase
	    $script2 = "<OBJECT " nocase
	    $param = "classid" nocase
	condition:
	    (chm_file_bool or FileParentType matches /->CL_TYPE_MS_CHM$/ or FileType matches /CL_TYPE_MS_CHM/) and any of ($script*) and $param
}

rule CHM_file {
	meta:
		description = "MS Windows HtmlHelp Data (.chm)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "chm_file_bool"
	strings:
	    $chmmagic = { 49 54 53 46 03 00 00 00  60 00 00 00 }
	condition:
	    $chmmagic at 0 or FileType matches /CL_TYPE_MS_CHM/ or PathFile matches /.*\.chm$/i or CDBNAME matches /.*\.chm$/i
}
