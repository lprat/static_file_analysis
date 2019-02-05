//https://media.blackhat.com/bh-us-12/Briefings/Shkatov/BH_US_12_Shkatov_Kohlenberg_Blackhat_Have_You_By_The_Gadgets_WP.pdf

rule Sidebar_obj_classid {
	meta:
		description = "Sidebar gadget Data with party Obj Classid"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		var_match = "gadget_file_script_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
		check_level2 = "check_clsid_bool,check_command_bool"
	strings:
	    $script1 = "<OBJECT>" nocase
	    $script2 = "<OBJECT " nocase
	    $param = "classid" nocase
	condition:
	    gadget_file_bool and any of ($script*) and $param
}

rule Sidebar_gadget_script {
	meta:
		description = "Sidebar gadget Data with party script"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		var_match = "gadget_file_script_bool"
		check_level2 = "check_registry_bool,check_command_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
	strings:
	    $script1 = "<script>"
	    $script2 = "<script "
	condition:
	    gadget_file_bool and any of ($script*)
}

rule Sidebar_interne_file {
	meta:
		description = "Sidebar interne file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 0
		check_level2 = "check_entropy_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
	condition:
	    gadget_file_bool
}

rule Sidebar_gadget_file_xml {
	meta:
		description = "Sidebar gadget File XML"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://nakedsecurity.sophos.com/2012/07/12/disable-windows-sidebar-gadgets/"
		var_match = "gadget_file_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
	    $xml = "<?xml" nocase
	    $gadget0 = "/gadget" nocase
	    $gadget1 = "<gadget" nocase	    
	condition:
	    (gadget_file_bool or FileParentType matches /->CL_TYPE_ZIP$/) and $xml and any of ($gadget*)
}

rule Sidebar_gadget_file {
	meta:
		description = "Sidebar Gadget File archive"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "gadget_file_bool"
	strings:
	    $zip1magic = { 50 4b 03 04 0a }
	    $gadget = "gadget.xml" nocase
	condition:
	    (($zip1magic at 0 or FileType matches /CL_TYPE_ZIP/) and $gadget) or PathFile matches /.*\.gadget$/i or CDBNAME matches /.*\.gadget$/i
}
