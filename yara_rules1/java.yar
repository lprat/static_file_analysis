rule java_content {
    meta:
        author = "Lionel PRAT"
        description = "File content potential source code java"
        version = "0.1"
        weight = 1
        check_level2 = "check_command_bool,check_java_bool"
        var_match = "java_file_bool"
    strings:
        $class0 = "public class" nocase
        $class1 = "private class" nocase
        $par0 = "{" nocase
        $par1 = "}" nocase
        $import = /import [A-Z0-9\._-]+;/ nocase
        $lex0 = "void " nocase
        $lex1 = "int " nocase
        $lex2 = "main(" nocase
        $lex3 = "static " nocase
        $lex4 = "void " nocase
        $lex5 = "String " nocase
        $lex6 = "System. " nocase
        $lex7 = "Catch " nocase
        $lex8 = "Exception " nocase
        $lex9 = "Return " nocase
        $lex10 = "Object " nocase
        $func0 = /(\s+|\n)[0-9A-Z\._-]+\s+[0-9A-Z\._-]+\=\s*(\S+)*\s*\([^\;]+\;/ nocase
        $func1 = /(\s+|\n)[0-9A-Z\._-]+\([^\;]\;/ nocase
    condition:
        (all of ($par*) and 1 of ($class*) and $import and 4 of ($lex*) and 1 of ($func*)) or PathFile matches /.*\.java$/i or CDBNAME matches /.*\.java$/i
}

//NOT REMOVE OR CHANGE NAME OF RULE BECAUSE THIS RULE USED TO DECOMPIL CLASS
rule java_class {
    meta:
        author = "Lionel PRAT"
        description = "File class java"
        version = "0.1"
        weight = 1
        check_level2 = "check_command_bool,check_java_bool"
        var_match = "java_file_bool"
        reference = "https://github.com/file/file/blob/b205e7889b9ef8d058fdc1dba2822d95d744e738/magic/Magdir/cafebabe" 
    strings:
        $magic = { ca fe ba be }
    condition:
        $magic at 0 or PathFile matches /.*\.class$/i or CDBNAME matches /.*\.class$/i
}

//NOT REMOVE OR CHANGE NAME OF RULE BECAUSE THIS RULE USED TO DECOMPIL CLASS
rule java_jar {
    meta:
        author = "Lionel PRAT"
        description = "File java archive data (JAR)"
        version = "0.1"
        weight = 1
        check_level2 = "check_command_bool,check_java_bool"
        var_match = "java_file_bool"
        reference = "https://github.com/file/file/blob/b205e7889b9ef8d058fdc1dba2822d95d744e738/magic/Magdir/cafebabe" 
    strings:
        $magic1 = { 50 4b 03 04 }
        $magic2 = { fe ca }
        $magic3 = "META-INF/"
    condition:
        $magic1 at 0 and ($magic2 in (38..48) or $magic3 in (26..48)) or PathFile matches /.*\.jar$/i or CDBNAME matches /.*\.jar$/i
}

