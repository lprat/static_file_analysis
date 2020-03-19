rule angler_jar : EK
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "Angler Exploit Kit - JAR"
		hash0 = "3de78737b728811af38ea780de5f5ed7"
		sample_filetype = "unknown"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
		weight = 7
		tag = "attack.initial"
	strings:
		$string0 = "myftysbrth"
		$string1 = "classPK"
		$string2 = "8aoadN"
		$string3 = "j5/_<F"
		$string4 = "FXPreloader.class"
		$string5 = "V4w\\K,"
		$string6 = "W\\Vr2a"
		$string7 = "META-INF/MANIFEST.MF"
		$string8 = "Na8$NS"
		$string9 = "_YJjB'"
	condition:
		9 of them
}

rule blackhole1_jar
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BlackHole1 Exploit Kit JAR"
   hash0 = "724acccdcf01cf2323aa095e6ce59cae"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "Created-By: 1.6.0_18 (Sun Microsystems Inc.)"
   $string1 = "workpack/decoder.classmQ]S"
   $string2 = "workpack/decoder.classPK"
   $string3 = "workpack/editor.classPK"
   $string4 = "xmleditor/GUI.classmO"
   $string5 = "xmleditor/GUI.classPK"
   $string6 = "xmleditor/peers.classPK"
   $string7 = "v(SiS]T"
   $string8 = ",R3TiV"
   $string9 = "META-INF/MANIFEST.MFPK"
   $string10 = "xmleditor/PK"
   $string11 = "Z[Og8o"
   $string12 = "workpack/PK"
condition:
   12 of them
}

rule blackhole2_jar : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit JAR"
   hash0 = "86946ec2d2031f2b456e804cac4ade6d"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "k0/3;N"
   $string1 = "g:WlY0"
   $string2 = "(ww6Ou"
   $string3 = "SOUGX["
   $string4 = "7X2ANb"
   $string5 = "r8L<;zYH)"
   $string6 = "fbeatbea/fbeatbee.classPK"
   $string7 = "fbeatbea/fbeatbec.class"
   $string8 = "fbeatbea/fbeatbef.class"
   $string9 = "fbeatbea/fbeatbef.classPK"
   $string10 = "fbeatbea/fbeatbea.class"
   $string11 = "fbeatbea/fbeatbeb.classPK"
   $string12 = "nOJh-2"
   $string13 = "[af:Fr"
condition:
   13 of them
}

rule blackhole2_jar2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit JAR"
   hash0 = "add1d01ba06d08818ff6880de2ee74e8"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "6_O6d09"
   $string1 = "juqirvs.classPK"
   $string2 = "hw.classPK"
   $string3 = "a.classPK"
   $string4 = "w.classuS]w"
   $string5 = "w.classPK"
   $string6 = "YE}0vCZ"
   $string7 = "v)Q,Ff"
   $string8 = "%8H%t("
   $string9 = "hw.class"
   $string10 = "a.classmV"
   $string11 = "2CniYFU"
   $string12 = "juqirvs.class"
condition:
   12 of them
}

rule blackhole2_jar3 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-27"
   description = "BlackHole2 Exploit Kit JAR"
   hash0 = "c7abd2142f121bd64e55f145d4b860fa"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "69/sj]]o"
   $string1 = "GJk5Nd"
   $string2 = "vcs.classu"
   $string3 = "T<EssB"
   $string4 = "1vmQmQ"
   $string5 = "Kf1Ewr"
   $string6 = "c$WuuuKKu5"
   $string7 = "m.classPK"
   $string8 = "chcyih.classPK"
   $string9 = "hw.class"
   $string10 = "f';;;;{"
   $string11 = "vcs.classPK"
   $string12 = "Vbhf_6"
condition:
   12 of them
}

rule crimepack_jar3 : EK
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit JAR"
	hash0 = "40ed977adc009e1593afcb09d70888c4"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
	tag = "attack.initial"
    weight = 6
strings:
	$string0 = "payload.serPK"
	$string1 = "vE/JD[j"
	$string2 = "payload.ser["
	$string3 = "Exploit$2.classPK"
	$string4 = "Exploit$2.class"
	$string5 = "Ho((i/"
	$string6 = "META-INF/MANIFEST.MF"
	$string7 = "H5641Yk"
	$string8 = "Exploit$1.classPK"
	$string9 = "Payloader.classPK"
	$string10 = "%p6$MCS"
	$string11 = "Exploit$1$1.classPK"
condition:
	11 of them
}

rule eleonore_jar : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Eleonore Exploit Kit JAR"
   hash0 = "ad829f4315edf9c2611509f3720635d2"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "r.JM,IM"
   $string1 = "dev/s/DyesyasZ.classPK"
   $string2 = "k4kjRv"
   $string3 = "dev/s/LoaderX.class}V[t"
   $string4 = "dev/s/PK"
   $string5 = "Hsz6%y"
   $string6 = "META-INF/MANIFEST.MF"
   $string7 = "dev/PK"
   $string8 = "dev/s/AdgredY.class"
   $string9 = "dev/s/DyesyasZ.class"
   $string10 = "dev/s/LoaderX.classPK"
   $string11 = "eS0L5d"
   $string12 = "8E{4ON"
condition:
   12 of them
}

rule eleonore_jar2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Eleonore Exploit Kit JAR"
   hash0 = "94e99de80c357d01e64abf7dc5bd0ebd"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
   $string1 = "wPVvVyz"
   $string2 = "JavaFX.class"
   $string3 = "{%D@'\\"
   $string4 = "JavaFXColor.class"
   $string5 = "bWxEBI}Y"
   $string6 = "$(2}UoD"
   $string7 = "j%4muR"
   $string8 = "vqKBZi"
   $string9 = "l6gs8;"
   $string10 = "JavaFXTrueColor.classeSKo"
   $string11 = "ZyYQx "
   $string12 = "META-INF/"
   $string13 = "JavaFX.classPK"
   $string14 = ";Ie8{A"
condition:
   14 of them
}

rule eleonore_jar3 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Eleonore Exploit Kit JAR"
   hash0 = "f65f3b9b809ebf221e73502480ab6ea7"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "16lNYF2V"
   $string1 = "META-INF/MANIFEST.MFPK"
   $string2 = "ghsdr/Jewredd.classPK"
   $string3 = "ghsdr/Gedsrdc.class"
   $string4 = "e[<n55"
   $string5 = "ghsdr/Gedsrdc.classPK"
   $string6 = "META-INF/"
   $string7 = "na}pyO"
   $string8 = "9A1.F\\"
   $string9 = "ghsdr/Kocer.class"
   $string10 = "MXGXO8"
   $string11 = "ghsdr/Kocer.classPK"
   $string12 = "ghsdr/Jewredd.class"
condition:
   12 of them
}

rule crimepack_jar : EK
{
meta:
	author = "Josh Berry"
	date = "2016-06-26"
	description = "CrimePack Exploit Kit JAR"
	hash0 = "d48e70d538225bc1807842ac13a8e188"
	sample_filetype = "unknown"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
	tag = "attack.initial"
    weight = 6
strings:
	$string0 = "r.JM,IM"
	$string1 = "cpak/Crimepack$1.classPK"
	$string2 = "cpak/KAVS.classPK"
	$string3 = "cpak/KAVS.classmQ"
	$string4 = "cpak/Crimepack$1.classmP[O"
	$string5 = "META-INF/MANIFEST.MF"
	$string6 = "META-INF/MANIFEST.MFPK"
condition:
	6 of them
}

rule bleedinglife2_jar2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit JAR"
   hash0 = "2bc0619f9a0c483f3fd6bce88148a7ab"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "META-INF/MANIFEST.MFPK"
   $string1 = "RequiredJavaComponent.classPK"
   $string2 = "META-INF/JAVA.SFm"
   $string3 = "RequiredJavaComponent.class"
   $string4 = "META-INF/MANIFEST.MF"
   $string5 = "META-INF/JAVA.DSAPK"
   $string6 = "META-INF/JAVA.SFPK"
   $string7 = "5EVTwkx"
   $string8 = "META-INF/JAVA.DSA3hb"
   $string9 = "y\\Dw -"
condition:
   9 of them
}

rule bleedinglife2_java_2010_0842_exploit : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "BleedingLife2 Exploit Kit JAVA"
   hash0 = "b14ee91a3da82f5acc78abd10078752e"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "META-INF/MANIFEST.MFManifest-Version: 1.0"
   $string1 = "ToolsDemo.classPK"
   $string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
   $string3 = "Created-By: 1.6.0_22 (Sun Microsystems Inc.)"
   $string4 = "META-INF/PK"
   $string5 = "ToolsDemo.class"
   $string6 = "META-INF/services/PK"
   $string7 = "ToolsDemoSubClass.classPK"
   $string8 = "META-INF/MANIFEST.MFPK"
   $string9 = "ToolsDemoSubClass.classeN"
condition:
   9 of them
}

rule phoenix_jar : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit JAR"
   hash0 = "a8a18219b02d30f44799415ff19c518e"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "r.JM,IM"
   $string1 = "qX$8$a"
   $string2 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProvider5"
   $string3 = "a.classPK"
   $string4 = "6;\\Q]Q"
   $string5 = "h[s] X"
   $string6 = "ToolsDemoSubClass.classPK"
   $string7 = "a.class"
   $string8 = "META-INF/MANIFEST.MFPK"
   $string9 = "ToolsDemoSubClass.classeO"
   $string10 = "META-INF/services/javax.sound.midi.spi.MidiDeviceProviderPK"
condition:
   10 of them
}

rule phoenix_jar2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit JAR"
   hash0 = "989c5b5eaddf48010e62343d7a4db6f4"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "a66d578f084.classeQ"
   $string1 = "a4cb9b1a8a5.class"
   $string2 = ")szNu\\MutK"
   $string3 = "qCCwBU"
   $string4 = "META-INF/MANIFEST.MF"
   $string5 = "QR,GOX"
   $string6 = "ab5601d4848.classmT"
   $string7 = "a6a7a760c0e["
   $string8 = "2ZUK[L"
   $string9 = "2VT(Au5"
   $string10 = "a6a7a760c0ePK"
   $string11 = "aa79d1019d8.class"
   $string12 = "aa79d1019d8.classPK"
   $string13 = "META-INF/MANIFEST.MFPK"
   $string14 = "ab5601d4848.classPK"
condition:
   14 of them
}

rule phoenix_jar3 : EK Jar
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Phoenix Exploit Kit JAR"
   hash0 = "c5655c496949f8071e41ea9ac011cab2"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "'> >$>"
   $string1 = "bpac/PK"
   $string2 = "bpac/purok$1.classmP]K"
   $string3 = "bpac/KAVS.classmQ"
   $string4 = "'n n$n"
   $string5 = "bpac/purok$1.classPK"
   $string6 = "$.4aX,Gt<"
   $string7 = "bpac/KAVS.classPK"
   $string8 = "bpac/b.classPK"
   $string9 = "bpac/b.class"
condition:
   9 of them
}

rule sakura_jar : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Sakura Exploit Kit Detection"
   hash0 = "a566ba2e3f260c90e01366e8b0d724eb"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "Rotok.classPK"
   $string1 = "nnnolg"
   $string2 = "X$Z'\\4^=aEbIdUmiprsxt}v<" wide
   $string3 = "()Ljava/util/Set;"
   $string4 = "(Ljava/lang/String;)V"
   $string5 = "Ljava/lang/Exception;"
   $string6 = "oooy32"
   $string7 = "Too.java"
   $string8 = "bbfwkd"
   $string9 = "Ljava/lang/Process;"
   $string10 = "getParameter"
   $string11 = "length"
   $string12 = "Simio.java"
   $string13 = "Ljavax/swing/JList;"
   $string14 = "-(Ljava/lang/String;)Ljava/lang/StringBuilder;"
   $string15 = "Ljava/io/InputStream;"
   $string16 = "vfnnnrof.exnnnroe"
   $string17 = "Olsnnfw"
condition:
   17 of them
}

rule sakura_jar2 : EK jar
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Sakura Exploit Kit Detection"
   hash0 = "d21b4e2056e5ef9f9432302f445bcbe1"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "getProperty"
   $string1 = "java/io/FileNotFoundException"
   $string2 = "LLolp;"
   $string3 = "cjhgreshhnuf "
   $string4 = "StackMapTable"
   $string5 = "onfwwa"
   $string6 = "(C)Ljava/lang/StringBuilder;"
   $string7 = "replace"
   $string8 = "LEsia$fffgss;"
   $string9 = "<clinit>"
   $string10 = "()Ljava/io/InputStream;"
   $string11 = "openConnection"
   $string12 = " gjhgreshhnijhgreshhrtSjhgreshhot.sjhgreshhihjhgreshht;)"
   $string13 = "Oi.class"
   $string14 = " rjhgreshhorjhgreshhre rajhgreshhv"
   $string15 = "java/lang/String"
   $string16 = "java/net/URL"
   $string17 = "Created-By: 1.7.0-b147 (Oracle Corporation)"
condition:
   17 of them
}

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

