//TODO: complete list  
//     .application$|.chm$|.appref-ms$|.cmdline$|.jnlp$|.exe$|.gadget$|.dll$|.lnk$|.pif$|.com$|.sfx$|.bat$|.cmd$|.scr$|.sys$|.hta$|.cpl$|.msc$|.inf$|.scf$|.reg$|.jar$|.vb\.*$|.js\.*$|.ws\.+$|.ps\w+$|.ms\w+$|.jar$|.url$
//     .rtf$|\.ppt\.*$|.xls\.*$|.doc\.*$|.pdf$|.zip$|.rar$|.tmp$|.py\.*$|.dotm$|.xltm$|.xlam$|.potm$|.ppam$|.ppsm$|.sldm$

rule dangerous_embed_file{
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Dangerous embed file"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
		var_match = "dembed_find_bool"
	condition:
		FileParentType matches /->/ and not FileParentType matches /->CL_TYPE_SWF$|->CL_TYPE_SWF_\(zlib_compressed\)$/ and FileType matches /CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_ELF|CL_TYPE_MACHO|CL_TYPE_OLE2|CL_TYPE_MSOLE2|CL_TYPE_MSCAB|CL_TYPE_RTF|CL_TYPE_ZIP|CL_TYPE_OOXML|CL_TYPE_AUTOIT|CL_TYPE_JAVA|CL_TYPE_SWF|CL_TYPE_MS_CHM/
}

rule embed_file{
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 0
		description = "Dangerous embed file"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution,attack.defense_evasion"
		var_match = "dembed_find_bool"
		check_level2 = "check_entropy_bool"
	condition:
		FileParentType matches /->/
}
