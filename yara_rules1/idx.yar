//IDX header https://github.com/Rurik/Java_IDX_Parser/blob/master/idx_parser.py


rule IDX_file {
	meta:
		description = "Java IDX (history of java applet)"
		author = "Lionel PRAT"
		reference = "https://github.com/Rurik/Java_IDX_Parser/"
        version = "0.1"
		weight = 1
		var_match = "idx_file_bool"
	strings:
	    $magic0 = { 02 5A }
	    $magic1 = { 02 5B }
	    $magic2 = { 02 5C }
	    $magic3 = { 02 5D }
	    $magic4 = { 02 5E }
	condition:
	    ($magic0 in (2..6) or $magic1 in (2..6) or $magic2 in (2..6) or $magic3 in (2..6) or $magic4 in (2..6)) or PathFile matches /.*\.idx$/i or CDBNAME matches /.*\.idx$/i
}
