//SDB header https://github.com/file/file/blob/73d89fec800dfda5d8cdc0922adc351dc5fedae1/magic/Magdir/database

rule SDB_file_exe {
	meta:
		description = "SDB file with exe command_line should be in c:\\windows\\AppPatch\\Custom"
		author = "Lionel PRAT"
		reference = "https://www.fireeye.com/blog/threat-research/2017/05/fin7-shim-databases-persistence.html"
        version = "0.1"
		weight = 5
		tag = "attack.persistence,attack.t1138"
	strings:
	    $magic = { 02 78 }
	    $magic2 = { 00 }
	    $exe = { 07 70 ?? ?? 00 00 }
	    $command = { 08 60 ?? ?? 00 00 }
	condition:
	    ((uint32(8) == 0x66626473 and $magic in (0..12) and $magic2 in (0..7)) or PathFile matches /.*\.sdb$/i or CDBNAME matches /.*\.sdb$/i) and $exe and $command
}

rule SDB_file {
	meta:
		description = "Windows application compatibility Shim DataBase (.sdb)"
		author = "Lionel PRAT"
		reference = "https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1138/src"
        version = "0.1"
		weight = 1
		check_level2 = "check_command_bool,check_clsid_bool"
		var_match = "sdb_file_bool"
	strings:
	    $magic = { 02 78 }
	    $magic2 = { 00 }
	condition:
	    (uint32(8) == 0x66626473 and $magic in (0..12) and $magic2 in (0..7)) or PathFile matches /.*\.sdb$/i or CDBNAME matches /.*\.sdb$/i
}
