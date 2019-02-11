//todo: 
// function risk
// obuscate js
// content obj

rule File_contains_JS {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Suspect JS file embed from another File (PARENT)"
	strings:
        $js0 = "function " nocase
        $js1 = "return" nocase
        $js2 = "var " nocase
        $k0 = "if " nocase
        $k1 = "else " nocase
        $k2 = "do " nocase
        $k3 = "while " nocase
        $k4 = "for " nocase
        $var = /(^|\s+)var\s+\S+\s*=[^;]+;/ nocase
        $func = /(^|\s+)function\s+\S+\([^\)]+\)\s*{/ nocase
	condition:
		((2 of ($js*) and 2 of ($k*) and $func and $var) or PathFile matches /.*\.js$/i or CDBNAME matches /.*\.js$/i) and FileParentType matches /->/
}

rule JS_content {
    meta:
        author = "Lionel PRAT"
        description = "File content potential code javascript"
        version = "0.1"
        weight = 2
        tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
        check_level2 = "check_command_bool,check_clsid_bool,check_js_bool"
        var_match = "js_file_bool"
    strings:
        $js0 = "function " nocase
        $js1 = "return" nocase
        $js2 = "var " nocase
        $k0 = "if " nocase
        $k1 = "else " nocase
        $k2 = "do " nocase
        $k3 = "while " nocase
        $k4 = "for " nocase
        $var = /(^|\s+)var\s+\S+\s*=[^;]+;/ nocase
        $func = /(^|\s+)function\s+\S+\([^\)]+\)\s*{/ nocase
    condition:
        (2 of ($js*) and 2 of ($k*) and $func and $var) or PathFile matches /.*\.js$/i or CDBNAME matches /.*\.js$/i
}

