//todo: 
// function risk
// obuscate js
// content obj

rule JS_content {
    meta:
        author = "Lionel PRAT"
        description = "File content potential code javascript"
        version = "0.1"
        weight = 2
        tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
        check_level2 = "check_command_bool"
    strings:
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
        (2 of ($js*) and 2 of ($k*) and $func and $var) or PathFile matches /.*\.js$/i or CDBNAME matches /.*\.js$/i
}
