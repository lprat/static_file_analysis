rule HLP_file {
	meta:
		description = "MS Windows Help (.hlp) - not supported after windows vista"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://github.com/file/file/blob/884982aa3468a05a7756ba1a46e4fe79c399ba6b/magic/Magdir/windows"
		check_level2 = "check_command_bool,check_entropy_bool"
	strings:
	    $hlpmagic = { 3f 5f 03 00 }
	condition:
	    $hlpmagic at 0 or FileType matches /CL_TYPE_MS_CHM/ or PathFile matches /.*\.hlp$/i or CDBNAME matches /.*\.hlp$/i
}
