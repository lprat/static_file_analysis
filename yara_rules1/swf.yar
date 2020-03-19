//https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/net/package-detail.html
//https://arxiv.org/pdf/1710.10225.pdf
//Decompile SWF:
//	https://github.com/jindrapetrik/jpexs-decompiler/releases/tag/version11.2.0
//	ffdec -onerror ignore -config autoDeobfuscate=1,parallelSpeedUp=0 -export script "/tmp/decomp/" /tmp/tmpX6Y1W0/clamav-4a1ffc2aef0ea9b1d0550149e12b29db.tmp

rule URLLoaderCommand_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "URLLoaderCommand call in SWF"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
    strings:
        $url = "URLLoaderCommand"
	condition:
		FileType matches /CL_TYPE_SWF/ and $url
}

rule UseNetwork_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "SWF attributes: Use network"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
	condition:
		FileType matches /CL_TYPE_SWF/ and swf_attributes_use_network_bool
}

rule ActionScript3_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "SWF attributes: ActionScript 3.0"
		check_level2 = "check_clsid_bool,check_command_bool,check_winapi_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
	condition:
		FileType matches /CL_TYPE_SWF/ and swf_attributes_actionscript_30_bool
}

rule Metadata_in_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "SWF attributes: has metadata"
	condition:
		FileType matches /CL_TYPE_SWF/ and swf_attributes_has_metadata_bool
}


rule SWF_display {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Flash file use flash.display package for load code in remote or section binary(loadBytes/load)"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/display/package-detail.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash = "flash.display" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and $flash
}

rule SWF_utils {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "Flash file use flash.utils package (potential use for obfuscation)"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/utils/package-detail.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash = "flash.utils" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and $flash
}

rule SWF_utils_obf {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "Flash file use flash.utils.Endian for obfuscation"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/utils/Endian.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash0 = "flash.utils" nocase wide ascii
		$flash1 = "ByteArray" nocase wide ascii
		$func0 = "UnsignedByte" nocase wide ascii
		$func1 = "Endian" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and any of ($flash*) and any of ($func*)
}

rule SWF_utils_mem {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Flash file use flash.utils.ByteArray package for potential manipulate memory"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/utils/ByteArray.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash0 = "flash.utils" nocase wide ascii
		$flash1 = "ByteArray" nocase wide ascii
		$func0 = "writeByte" nocase wide ascii
		$func1 = "readByte" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and any of ($flash*) and any of ($func*)
}


rule SWF_sys {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "Flash file use flash.system package"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/system/package-detail.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash = "flash.system" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and $flash
}

rule SWF_fs {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "Flash file use flash.filesystem package"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/filesystem/package-detail.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash = "flash.filesystem" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and $flash
}

rule SWF_crypto {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Flash file use flash.crypto package"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/crypto/package-detail.html"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash = "flash.crypto" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and $flash
}

rule SWF_net {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Flash file use flash.net package"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/net/package-detail.html#methodSummary"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		$flash = "flash.net" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and $flash
}

rule SWF_embed {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 8
		description = "Flash file embed binary data (Potential Exploit CVE)"
		reference = "https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/net/package-detail.html#methodSummary"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
		//file after
		$binary0 = {FF 15 ?? ?? ?? ?? ?? 00 00 00 00 00} // 00 ff 15 9e 0c 00 00 01 00 00  00 00 00 => 9e 0c == size of data embed (0xc9e) || 01 == data file numero 1
		$binary1 = /\x00.\x15.\x00\x00\x00\x00\x00.{1,30}\x00.\x15.\x00\x00\x00\x00\x00/  // 00 ca 15 03 00 00  00 00 00 => 9e 0c == size of data embed (0xc9e) || 01 == data file numero 1 // more false positive
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and any of ($binary*)
}

rule File_contains_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Suspect flash file embed from another File (PARENT)"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and FileParentType matches /->/ and not FileParentType matches /->CL_TYPE_SWF/
}


rule Flash_CVE_2015_5119_APT3 : Exploit {
    meta:
        description = "Exploit Sample CVE-2015-5119"
        author = "Florian Roth"
        score = 70
        date = "2015-08-01"
        tag = "attack.initial"
		weight = 6
    strings:
        $s0 = "HT_exploit" fullword ascii
        $s1 = "HT_Exploit" fullword ascii
        $s2 = "flash_exploit_" ascii
        $s3 = "exp1_fla/MainTimeline" ascii fullword
        $s4 = "exp2_fla/MainTimeline" ascii fullword
        $s5 = "_shellcode_32" fullword ascii
        $s6 = "todo: unknown 32-bit target" fullword ascii 
    condition:
        uint16(0) == 0x5746 and 1 of them
}

rule angler_flash : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Angler Exploit Kit FLASH"
   hash0 = "8081397c30b53119716c374dd58fc653"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "(9OOSp"
   $string1 = "r$g@ 0'[A"
   $string2 = ";R-1qTP"
   $string3 = "xwBtR4"
   $string4 = "YbVjxp"
   $string5 = "ddgXkF"
   $string6 = ")n'URF"
   $string7 = "vAzq@W"
   $string8 = "rOkX$6m<"
   $string9 = "@@DB}q "
   $string10 = "TiKV'iV"
   $string11 = "538x;B"
   $string12 = "9pEM{d"
   $string13 = ".SIy/O"
   $string14 = "ER<Gu,"
condition:
   14 of them
}

rule angler_flash2 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Angler Exploit Kit FLASH"
   hash0 = "23812c5a1d33c9ce61b0882f860d79d6"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "4yOOUj"
   $string1 = "CSvI4e"
   $string2 = "'fwaEnkI"
   $string3 = "'y4m%X"
   $string4 = "eOc)a,"
   $string5 = "'0{Q5<"
   $string6 = "1BdX;P"
   $string7 = "D _J)C"
   $string8 = "-epZ.E"
   $string9 = "QpRkP."
   $string10 = "<o/]atel"
   $string11 = "@B.,X<"
   $string12 = "5r[c)U"
   $string13 = "52R7F'"
   $string14 = "NZ[FV'P"
condition:
   14 of them
}

rule angler_flash4 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Angler Exploit Kit FLASH"
   hash0 = "dbb3f5e90c05602d92e5d6e12f8c1421"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "_u;cwD;"
   $string1 = "lhNp74"
   $string2 = "Y0GQ%v"
   $string3 = "qjqCb,nx"
   $string4 = "vn{l{Wl"
   $string5 = "5j5jz5"
   $string6 = "a3EWwhM"
   $string7 = "hVJb/4Aut"
   $string8 = ",lm4v,"
   $string9 = ",6MekS"
   $string10 = "YM.mxzO"
   $string11 = ";6 -$E"
   $string12 = "QA%: fy"
   $string13 = "<@{qvR"
   $string14 = "b9'$'6l"
   $string15 = ",x:pQ@-"
   $string16 = "2Dyyr9"
condition:
   16 of them
}

rule angler_flash5 : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Angler Exploit Kit FLASH"
   hash0 = "9f809272e59ee9ecd71093035b31eec6"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "0k%2{u"
   $string1 = "\\Pb@(R"
   $string2 = "ys)dVI"
   $string3 = "tk4_y["
   $string4 = "LM2Grx"
   $string5 = "n}s5fb"
   $string6 = "jT Nx<hKO"
   $string7 = "5xL>>}"
   $string8 = "S%,1{b"
   $string9 = "C'3g7j"
   $string10 = "}gfoh]"
   $string11 = ",KFVQb"
   $string12 = "LA;{Dx"
condition:
   12 of them
}

rule angler_flash_uncompressed : EK
{
meta:
   author = "Josh Berry"
   date = "2016-06-26"
   description = "Angler Exploit Kit FLASH"
   hash0 = "2543855d992b2f9a576f974c2630d851"
   sample_filetype = "unknown"
   yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
   tag = "attack.initial"
   weight = 6
strings:
   $string0 = "DisplayObjectContainer"
   $string1 = "Xtime2"
   $string2 = "(HMRTQ"
   $string3 = "flash.events:EventDispatcher$flash.display:DisplayObjectContainer"
   $string4 = "_e_-___-__"
   $string5 = "ZviJbf"
   $string6 = "random-"
   $string7 = "_e_-_-_-_"
   $string8 = "_e_------"
   $string9 = "817677162"
   $string10 = "_e_-__-"
   $string11 = "-[vNnZZ"
   $string12 = "5:unpad: Invalid padding value. expected ["
   $string13 = "writeByte/"
   $string14 = "enumerateFonts"
   $string15 = "_e_---___"
   $string16 = "_e_-_-"
   $string17 = "f(fOJ4"
condition:
   17 of them
}

rule SWF_file_cve20184878 {
	meta:
		description = "Detects FLASH CVE-2018-4878"
		vuln_type = "Remote Code Execution"
		vuln_impact = "Use-after-free"
		affected_versions = "Adobe Flash 28.0.0.137 and earlier versions"
		mitigation0 = "Implement Protected View for Office documents"
		mitigation1 = "Disable Adobe Flash"
		weaponization = "Embedded in Microsoft Office first payloads"
		actor = "Purported North Korean actors"
		reference = "hxxps://www[.]krcert[.]or[.kr/data/secNoticeView.do?bulletin_writing_sequence=26998"
		report = "https://www.flashpoint-intel.com/blog/targeted-attacks-south-korean-entities/"
		author = "Vitali Kremez, Flashpoint"
		version = "1.1"
		tag = "attack.initial"
		weight = 6
	strings:
		// EMBEDDED FLASH OBJECT BIN HEADER
		$header = "rdf:RDF" wide ascii
		// OBJECT APPLICATION TYPE TITLE
		$title = "Adobe Flex" wide ascii
		// PDB PATH 
		$pdb = "F:\\work\\flash\\obfuscation\\loadswf\\src" wide ascii
		// LOADER STRINGS
		$s0 = "URLRequest" wide ascii
		$s1 = "URLLoader" wide ascii
		$s2 = "loadswf" wide ascii
		$s3 = "myUrlReqest" wide ascii
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
	condition:
		((FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and FileParentType matches /->/ and not FileParentType matches /->CL_TYPE_SWF/) and all of ($header*) and all of ($title*) and 3 of ($s*) or all of ($pdb*) and all of ($header*) and 1 of ($s*)	
}

rule SWF_file {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/ReFirmLabs/binwalk/blob/master/src/binwalk/magic/animation"
		description = "Uncompressed Adobe Flash SWF file"
		var_match = "swf_file_bool"
		check_level2 = "check_clsid_bool,check_command_bool,check_winapi_bool"
	strings:
		$magic = {46 57 53} //FWS
		$str0 = "shockwave-flash" nocase wide ascii
	condition:
		$magic in (0..1024) and any of ($str*)
}

rule SWF_doswf {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 6
		reference = "http://www.malware-traffic-analysis.net/2019/03/16/index.html"
		description = "SWF file with cypher content use doswf.com"
	strings:
	    $magic = {46 57 53} //FWS
	    $str0 = "shockwave-flash" nocase wide ascii
		$doswf0 = "doswf.com" nocase wide ascii
		$doswf1 = "flash swf encrypt" nocase wide ascii
		$doswf2 = "Encrypted by DoSWF" nocase wide ascii
		$doswf3 = "_doswf_" nocase wide ascii
	condition:
		(FileType matches /CL_TYPE_SWF/ or ($magic in (0..1024) and any of ($str*))) and any of ($doswf*)
}
