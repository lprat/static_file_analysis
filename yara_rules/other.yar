rule ACE_file {
    meta:
        author = "Florian Roth - based on Nick Hoffman' rule - Morphick Inc -- Modified by Lionel PRAT"
        description = "Looks for ACE Archives"
        date = "2015-09-09"
        weight = 5
        tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
    strings:
        $header = { 2a 2a 41 43 45 2a 2a }

    condition:
        $header at 7
}

rule UserAgent_JS {
    meta:
        author = "Lionel PRAT"
        description = "Suspect use string user-agent in JS"
        version = "0.1"
        weight = 4
    strings:
        $s1 = "User-Agent"
        $js0 = "function "
        $js1 = "return"
        $js2 = "var "
        $k0 = "if "
        $k1 = "do "
        $k2 = "while "
        $k3 = "for "
        $var = /(^|\s+)var\s+\S+=[^;]+;/
        $func = /(^|\s+)function\s+\S+\([^\)]+\)\s+{/
    condition:
        $s1 and 2 of ($js*) and 2 of ($k*) and $func and $var
}

rule eval_in_JS {
    meta:
        author = "Lionel PRAT"
        description = "Suspect use string user-agent in JS"
        version = "0.1"
        weight = 4
    strings:
        $s1 = "eval("
        $s2 = /(^|\s+)eval\([^\)]+\);/
        $js0 = "function "
        $js1 = "return"
        $js2 = "var "
        $k0 = "if "
        $k1 = "do "
        $k2 = "while "
        $k3 = "for "
        $var = /(^|\s+)var\s+\S+=[^;]+;/
        $func = /(^|\s+)function\s+\S+\([^\)]+\)\s+{/
    condition:
        $s1 and 2 of ($js*) and 2 of ($k*) and $s2 and $func and $var
}

rule dangerous_embed_file{
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Dangerous embed file"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	condition:
		FileParentType matches /->/ and FileType matches /CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_ELF|CL_TYPE_MACHO|CL_TYPE_OLE2|CL_TYPE_MSOLE2|CL_TYPE_MSCAB|CL_TYPE_RTF|CL_TYPE_ZIP|CL_TYPE_OOXML|CL_TYPE_AUTOIT|CL_TYPE_JAVA|CL_TYPE_SWF/
}
