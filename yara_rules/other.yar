rule ACE_file {
    meta:
        author = "Florian Roth - based on Nick Hoffman' rule - Morphick Inc -- Modified by Lionel PRAT"
        description = "Looks for ACE Archives"
        date = "2015-09-09"
        weight = 5
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
