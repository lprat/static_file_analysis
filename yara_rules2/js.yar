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
        weight = 4
    strings:
        $s1 = "eval(" nocase
        $s2 = /(^|\s+)eval\([^\)]+\);/ nocase
    condition:
        check_js_bool and $s1 and $s2
}
