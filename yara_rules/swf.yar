rule URLLoaderCommand_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "URLLoaderCommand call in SWF"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
    strings:
        $url = "URLLoaderCommand"
	condition:
		FileType matches /CL_TYPE_SWF/ and $url
}

rule UseNetwork_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "SWF attributes: Use network"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
	condition:
		FileType matches /CL_TYPE_SWF/ and swf_attributes_use_network_bool
}

rule ActionScript3_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "SWF attributes: ActionScript 3.0"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
	condition:
		FileType matches /CL_TYPE_SWF/ and swf_attributes_actionscript_30_bool
}

rule Metadata_in_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "SWF attributes: has metadata"
	condition:
		FileType matches /CL_TYPE_SWF/ and swf_attributes_has_metadata_bool
}
