//deobfusc js: https://github.com/CapacitorSet/box-js

rule angler_js : EK
{
	meta:
		author = "Josh Berry"
		date = "2016-06-26"
		description = "Angler Exploit Kit JS"
		hash0 = "482d6c24a824103f0bcd37fa59e19452"
		sample_filetype = "js-html"
		yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
		weight = 6
		tag = "attack.initial"
	strings:
		$string0 = "    2654435769,   Be"
		$string1 = "DFOMIqka "
		$string2 = ",  Zydr$>>16"
		$string3 = "DFOMIqka( 'OPPj_phuPuiwzDFo')"
		$string4 = "U0BNJWZ9J0vM43TnlNZcWnZjZSelQZlb1HGTTllZTm19emc0dlsYF13GvhQJmTZmbVMxallMdhWW948YWi t    P  b50GW"
		$string5 = "    auSt;"
		$string6 = " eval    (NDbMFR "
		$string7 = "jWUwYDZhNVyMI2TzykEYjWk0MDM5MA%ZQ1TD1gEMzj         3  D       ',"
		$string8 = "('fE').substr    (2    ,    1 "
		$string9 = ",  -1 "
		$string10 = "    )  );Zydr$  [ 1]"
		$string11 = " 11;PsKnARPQuNNZMP<9;PsKnARPQuNNZMP"
		$string12 = "new   Array  (2),  Ykz"
		$string13 = "<script> "
		$string14 = ");    CYxin "
		$string15 = "Zydr$    [    1]"
		$string16 = "var tKTGVbw,auSt, vnEihY, gftiUIdV, XnHs, UGlMHG, KWlqCKLfCV;"
		$string17 = "reXKyQsob1reXKyQsob3 "
	condition:
		17 of them
}

rule eleonore_js : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Eleonore Exploit Kit JS"
   hash0 = "08f8488f1122f2388a0fd65976b9becd"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "var de"
   $string1 = "sdjk];"
   $string2 = "return dfshk;"
   $string3 = "function jkshdk(){"
   $string4 = "'val';"
   $string5 = "var sdjk"
   $string6 = "return fsdjkl;"
   $string7 = " window[d"
   $string8 = "var fsdjkl"
   $string9 = "function jklsdjfk() {"
   $string10 = "function rewiry(yiyr,fjkhd){"
   $string11 = " sdjd "
condition:
   11 of them
}

rule eleonore_js2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Eleonore Exploit Kit JS"
   hash0 = "2f5ace22e886972a8dccc6aa5deb1e79"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "var dfshk "
   $string1 = "arrow_next_down"
   $string2 = "return eval('yiyr.replac'"
   $string3 = "arrow_next_over"
   $string4 = "arrow_prev_over"
   $string5 = "xcCSSWeekdayBlock"
   $string6 = "xcCSSHeadBlock"
   $string7 = "xcCSSDaySpecial"
   $string8 = "xcCSSDay"
   $string9 = " window[df "
   $string10 = "day_special"
   $string11 = "var df"
   $string12 = "function jklsdjfk() {"
   $string13 = " sdjd "
   $string14 = "'e(/kljf hdfk sdf/g,fjkhd);');"
   $string15 = "arrow_next"
condition:
   15 of them
}

rule eleonore_js3 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Eleonore Exploit Kit JS"
   hash0 = "9dcb8cd8d4f418324f83d914ab4d4650"
   sample_filetype = "js-html"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   weight = 6
   tag = "attack.initial"
strings:
   $string0 = "@mozilla.org/file/directory_service;1"
   $string1 = "var exe "
   $string2 = "var file "
   $string3 = "foStream.write(data, data.length);"
   $string4 = "  var file_data "
   $string5 = "return "
   $string6 = " Components.classes["
   $string7 = "url : "
   $string8 = "].createInstance(Components.interfaces.nsILocalFile);"
   $string9 = "  var bstream "
   $string10 = " bstream.readBytes(size); "
   $string11 = "@mozilla.org/supports-string;1"
   $string12 = "  var channel "
   $string13 = "tmp.exe"
   $string14 = "  if (channel instanceof Components.interfaces.nsIHttpChannel "
   $string15 = "@mozilla.org/network/io-service;1"
   $string16 = " bstream.available()) { "
   $string17 = "].getService(Components.interfaces.nsIIOService); "
condition:
   17 of them
}

rule jjEncode
{
   meta:
      description = "Obfuscated with jjencode"
      ref = "http://blog.xanda.org/2015/06/10/yara-rule-for-jjencode/"
      author = "adnan.shukor@gmail.com"
      date = "10-June-2015"
      version = "1"
      weight = 6
      tag = "attack.defense_evasion"
   strings:
      $jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword 
   condition:
      check_js_bool and $jjencode
}

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
		description = "Script call ActiveX Object"
		author = "Lionel PRAT"
        	version = "0.2"
		weight = 5
	    	tag = "attack.defense_evasion"
	strings:
		$activ0 = "ActiveXObject" nocase
		$activ1 = "ActiveX" nocase
	condition:
	    check_js_bool and any of ($activ*)
}

rule JS_Wscript {
	meta:
		description = "Script call Wscript Object"
		author = "Lionel PRAT"
                version = "0.2"
		weight = 4
	        tag = "attack.defense_evasion"
	strings:
		$s1 = "Wscript" nocase
	condition:
	    check_js_bool and $s1
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
