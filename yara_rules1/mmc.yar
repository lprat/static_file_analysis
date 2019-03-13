rule msc_file {
	meta:
		description = "File Microsoft System Console [MSC - MMC]"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
	    check_level2 = "check_command_bool"
	    reference = "https://www.vulnerability-lab.com/get_content.php?id=2094"
	strings:
	    $mmc0 = "<MMC_ConsoleFile " nocase
	    $mmc1 = "</MMC_ConsoleFile>"
	condition:
	    all of ($mmc*) or PathFile matches /.*\.msc$/i or CDBNAME matches /.*\.msc$/i
}
