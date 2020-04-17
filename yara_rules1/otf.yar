//ref: https://github.com/file/file/blob/0d1e8d97eae10cf51dc6c991fae6a310dea858ad/magic/Magdir/fonts

rule Otf_file_size {
	meta:
		description = "OpenType font data with size suspect (.otf)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	strings:
	    $lnkmagic = { 4f 54 54 4f }
	condition:
	    $lnkmagic at 0 and filesize > 300KB
}

rule Otf_file {
	meta:
		description = "OpenType font data (.otf)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "otf_file_bool"
	strings:
	    $lnkmagic = { 4f 54 54 4f }
	condition:
	    $lnkmagic at 0 or FileType matches /CL_TYPE_Microsoft_Windows_Shortcut_File/ or PathFile matches /.*\.otf$/i or CDBNAME matches /.*\.otf$/i
}

