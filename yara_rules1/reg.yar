rule REG_file {
	meta:
		description = "Windows REG File (.reg)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		reference = "https://support.microsoft.com/en-us/help/310516/how-to-add-modify-or-delete-registry-subkeys-and-values-by-using-a-reg"
		check_level2 = "check_registry_bool"
	strings:
	    $regmagic1 = "Windows Registry Editor Version" nocase
	    $regmagic2 = /(^|[\x0a]+)\[[\-]?HKEY_[^\]]+\]\s*[\x0a\x0d]+/i
	    $regmagic3 = /[\x0a\x0d]+(\"[^\"]+\"|@)=([\"]?[^:]+:[^\x0a\x0d]|\-|[\"]?[^\x0a\x0d]+)(\s*[\"]?\s*)([\x0a\x0d]+|$)/i
	condition:
	    (2 of ($regmagic*) or PathFile matches /.*\.reg$/i or CDBNAME matches /.*\.reg$/i) and FileType matches /CL_TYPE_ASCII/
}
