//https://www.robvanderwoude.com/batchcommands.php

rule batch_file {
	meta:
		description = "Batch file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
	    check_level2 = "check_command_bool"
	    reference = "https://en.wikipedia.org/wiki/Batch_file"
	strings:
	    $batch0 = "@echo " nocase
	    $batch1 = /(^|\n)::|(^|\n)REM/
	    $batch2 = /(^|\n):\S+(\n|$)/
	    $batch3 = /(\s+|\n)(set|for|if|exist|echo|exit|findstr|goto)(\s+|\n)/
	condition:
	    2 of ($batch*) or PathFile matches /.*\.cmd$|.*\.bat$|.*\.btm$|.*\.cmdline$/i or CDBNAME matches /.*\.cmd$|.*\.bat$|.*\.btm$|.*\.cmdline$/i
}
