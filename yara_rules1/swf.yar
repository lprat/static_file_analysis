//https://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/net/package-detail.html
//https://arxiv.org/pdf/1710.10225.pdf
//Decompile SWF:
//	https://github.com/jindrapetrik/jpexs-decompiler/releases/tag/version11.2.0
//	ffdec -onerror ignore -config autoDeobfuscate=1,parallelSpeedUp=0 -export script "/tmp/decomp/" /tmp/tmpX6Y1W0/clamav-4a1ffc2aef0ea9b1d0550149e12b29db.tmp

rule URLLoaderCommand_SWF {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
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
		weight = 4
		description = "Flash file use flash.display package"
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
		//$binary1 = {00 ?? 15 ?? 00 00 00 00 00} // 00 ca 15 03 00 00  00 00 00 => 9e 0c == size of data embed (0xc9e) || 01 == data file numero 1 // more false positive
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
