//https://hwiegman.home.xs4all.nl/desktopini.html


rule INI_file {
	meta:
		description = "Windows INI File (.ini)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		reference = "https://fr.wikipedia.org/wiki/Fichier_INI"
		var_match = "ini_file_bool"
		check_level2 = "check_ini_bool"
	strings:
	    $inimagic0 = /^\[[^\]]+\]\s*$/ nocase wide ascii
	    $inimagic1 = /^[^=]+=[^=]+(;.*)*$/ nocase wide ascii
	    $regmagic = "Windows Registry Editor Version" nocase
	condition:
	    ((2 of ($inimagic*) and (not $regmagic)) or PathFile matches /.*\.ini$/i or CDBNAME matches /.*\.ini$/i) and FileType matches /CL_TYPE_ASCII|CL_TYPE_UTF/
}
