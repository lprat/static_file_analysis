//deobfusc js: https://github.com/CapacitorSet/box-js

rule JS_obfusc {
	meta:
		description = "Javascript obfuscated"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
	    tag = "attack.defense_evasion"
	strings:
		$obf0 = /[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf1 = /[aeuoiy]{4,}/ nocase
		$obf2 = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/ nocase // base 64
		$obf3 = "eval(" nocase
		$obf4 = /(function\s+.*){3,}/ nocase // base 64
	condition:
	    check_js_bool and 3 of ($obf*)
}

rule JS_activeX {
	meta:
		description = "Javascript call ActiveX Object"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.defense_evasion"
	strings:
		$activ = "ActiveXObject" nocase
	condition:
	    check_js_bool and $activ
}

rule UserAgent_JS {
    meta:
        author = "Lionel PRAT"
        description = "Suspect use string user-agent in JS"
        version = "0.1"
        weight = 4
    strings:
        $s1 = "User-Agent" nocase
    condition:
        check_js_bool and $s1
}

rule eval_in_JS {
    meta:
        author = "Lionel PRAT"
        description = "Suspect use function eval() in JS"
        version = "0.1"
        weight = 5
    strings:
        $s1 = "eval(" nocase
    condition:
        check_js_bool and $s1
}
