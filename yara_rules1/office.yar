rule Contains_VBE_File {
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect a VBE file inside a byte sequence"
        method = "Find string starting with #@~^ and ending with ^#~@"
        weight = 2
    strings:
        $vbe = /#@~\^.+\^#~@/
    condition:
        $vbe
}

rule XMLHTTP_Vba_OFFICE {
	meta:
		description = "Macro use XMLHTTP"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "eb680f46c268e6eac359b574538de569"
		var_match = "vba_xmlhttp_bool"
	strings:
		$o1 = "XMLHTTP" nocase
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and $o1
}

rule Activemime_MHTML {
	meta:
		description = "Activemime file in MHTML"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		var_match = "mhtml_activemime_bool"
    strings:
		$header = { 41 63 74 69 76 65 4d 69 6d 65 }
	condition:
	    $header at 0
}


rule Autorun_VBA_OFFICE
{
	meta:
		description = "Macro autorun"
		author = "Origin oledump modified by Lionel PRAT"
        version = "0.1"
		weight = 4
		var_match = "vba_autorun_bool"
		check_level2 = "check_vbscript_bool,check_clsid_bool"
    strings:
        $a = "AutoExec" nocase fullword
        $b = "AutoOpen" nocase fullword
        $c = "DocumentOpen" nocase fullword
        $d = "AutoExit" nocase fullword
        $e = "AutoClose" nocase fullword
        $f = "Document_Close" nocase fullword
        $g = "DocumentBeforeClose" nocase fullword
        $h = "Document_Open" nocase fullword
        $i = "Document_BeforeClose" nocase fullword
        $j = "Auto_Open" nocase fullword
        $k = "Workbook_Open" nocase fullword
        $l = "Workbook_Activate" nocase fullword
        $m = "Auto_Close" nocase fullword
        $n = "Workbook_Close" nocase fullword
    condition:
        FileParentType matches /->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/ and any of ($*)
}

rule Auto_OLE_OFFICE
{
	meta:
		description = "OLE automation"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		var_match = "vba_autorun_bool"
		reference = "286c334b4c13952cfb3fd03e97e59b00"
    strings:
        $a = "stdole2.tlb" nocase fullword
    condition:
        FileParentType matches /->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/ and $a
}

rule OLE_EMBEDDED_OFFICE
{
	meta:
		description = "MS Forms Embedded object"
		desc_plus = "STOLE2.TLB stands for Standard Object Linking Embedding version 2 . Table Library.  This is one of four files used by Windows for the Automation files (formerly OLE Automation (Object Linking Embedding)).  You have used the OLE functions every time you have cut and pasted anything or captured the entire contents of a form, letter picture and then move it."
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "286c334b4c13952cfb3fd03e97e59b00"
    strings:
        $a = "Microsoft Forms 2.0 Form" nocase fullword
        $b = "Embedded Object" nocase fullword
    condition:
        FileParentType matches /->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD/ and $a and $b
}

rule Contains_VBA_macro_code
{
	meta:
		author = "evild3ad"
		description = "Detect a MS Office document with embedded VBA macro code"
		date = "2016-01-09"
		filetype = "Office documents"
		weight = 4

	strings:
		$officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$zipmagic = "PK"

		$97str1 = "_VBA_PROJECT_CUR" wide
		$97str2 = "VBAProject"
		$97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F } // Attribute VB_

		$xmlstr1 = "vbaProject.bin"
		$xmlstr2 = "vbaData.xml"

	condition:
		($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*))
}

rule Office_AutoOpen_Macro {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		author = "Florian Roth"
		date = "2015-05-28"
		weight = 6
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		(
			uint32be(0) == 0xd0cf11e0 or 	// DOC, PPT, XLS
			uint32be(0) == 0x504b0304		// DOCX, PPTX, XLSX (PKZIP)
		)
		and all of ($s*) and filesize < 300000
}

rule Office_as_MHTML {
	meta:
		description = "Detects an Microsoft Office saved as a MHTML file (false positives are possible but rare; many matches on CVE-2012-0158)"
		author = "Florian Roth"
		date = "2015-05-28"
		weight = 6
		reference = "https://www.trustwave.com/Resources/SpiderLabs-Blog/Malicious-Macros-Evades-Detection-by-Using-Unusual-File-Format/"
		hash1 = "8391d6992bc037a891d2e91fd474b91bd821fe6cb9cfc62d1ee9a013b18eca80"
		hash2 = "1ff3573fe995f35e70597c75d163bdd9bed86e2238867b328ccca2a5906c4eef"
		hash3 = "d44a76120a505a9655f0224c6660932120ef2b72fee4642bab62ede136499590"
		hash4 = "5b8019d339907ab948a413d2be4bdb3e5fdabb320f5edc726dc60b4c70e74c84"
	strings:
		$s1 = "Content-Transfer-Encoding: base64" ascii fullword
		$s2 = "Content-Type: application/x-mso" ascii fullword

		$x1 = "QWN0aXZlTWltZQA" ascii 	// Base64 encoded 'ActiveMime'
		$x2 = "0M8R4KGxGuE" ascii 		// Base64 encoded office header D0CF11E0A1B11AE1..
	condition:
		uint32be(0) == 0x4d494d45 // "MIME" header
		and all of ($s*) and 1 of ($x*)
}

rule CreateObject_Vba_OFFICE {
	meta:
		description = "Macro suspect CreateObject() with variable name and macro AutoOpen"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "eb680f46c268e6eac359b574538de569"
	strings:
		$o1 = /(^|\s+)CreateObject\([a-zA-Z0-9_-][^)]\)/
        $a1 = "AutoExec" nocase fullword
        $a2 = "AutoOpen" nocase fullword
        $a3 = "DocumentOpen" nocase fullword
        $a4 = "AutoExit" nocase fullword
        $a5 = "AutoClose" nocase fullword
        $a6 = "Document_Close" nocase fullword
        $a7 = "DocumentBeforeClose" nocase fullword
        $a8 = "Document_Open" nocase fullword
        $a9 = "Document_BeforeClose" nocase fullword
        $a10 = "Auto_Open" nocase fullword
        $a11 = "Workbook_Open" nocase fullword
        $a12 = "Workbook_Activate" nocase fullword
        $a13 = "Auto_Close" nocase fullword
        $a14 = "Workbook_Close" nocase fullword
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and $o1 and (any of ($a*) or vba_autorun_bool)
}

rule script_Office {
	meta:
		description = "Download macro script on URL"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://github.com/temesgeny/ppsx-file-generator"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$o1 = "oleObject" nocase
		$o2 = /Target=(\"|\')script\:(http|ftp)/ nocase
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and $o1 and $o2
}

rule ppaction_Office {
	meta:
		description = "Office use ppaction"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "3bff3e4fec2b6030c89e792c05f049fc"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$o1 = /action=(\"|\')ppaction\:/ nocase
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and $o1
}

rule Suspect_DDE_OFFICE {
	meta:
		description = "Office with DDEAUTO (exploit for run command)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/"
		check_level2 = "check_command_bool,check_clsid_bool,check_registry_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$dde = ">DDEAUTO " nocase
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and $dde
}

rule Suspect_SOAPWSDL_OFFICE {
	meta:
		description = "Suspects call wml web service in OFFICE DOCUMENTS"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		reference = "https://github.com/Voulnet/CVE-2017-8759-Exploit-sample" 
		check_level2 = "check_entropy_bool,check_command_bool,check_clsid_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$a1 = "GetObject" nocase
		$a2 = "soap:wsdl" nocase
		$a3 = "://"
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and all of ($a*)
}

rule Encrypted_OFFICE_conf {
        meta:
			description = "OFFICE DOCUMENT encrypted conf"
            author = "Lionel PRAT"
			version = "0.1"
			weight = 7
            reference = "http://lists.clamav.net/pipermail/clamav-users/2017-November/005358.html"
			tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
		strings:
			$bad0 = "<encryption" nocase
			$bad1 = "<keyData" nocase
			$bad2 = "cipherAlgorithm=" nocase
			$bad3 = "hashAlgorithm=" nocase
			$bad4 = "encryptedHmacKey=" nocase
        condition:
             ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and 2 of ($bad*)
}

rule Encrypted_OFFICE {
        meta:
			description = "Suspect encrypted OFFICE DOCUMENTS"
            author = "Lionel PRAT"
			version = "0.1"
			weight = 7
            reference = "https://isc.sans.edu/forums/diary/Malspam+pushing+ransomware+using+two+layers+of+password+protection+to+avoid+detection/23573/"
			tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
        condition:
            Streams matches /encrypt/
}

rule OFFICE_file_int {
	meta:
		description = "OFFICE DOCUMENT interne"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 0
		var_match = "office_file_bool"
        check_level2 = "check_entropy_bool,check_command_bool,check_clsid_bool,check_registry_bool,check_winapi_bool"
	condition:
	    (office_file_bool and FileParentType matches /->CL_TYPE_ZIP$/) or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/
}

rule OFFICE_file_char {
	meta:
		description = "OFFICE DOCUMENT contains char < 10"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
		var_match = "office_file_bool"
	condition:
	    SummaryInfo_CharCount_int > 0 and SummaryInfo_CharCount_int < 10
}

rule OFFICE_author {
	meta:
		description = "OFFICE DOCUMENT with author suspect"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	condition:
	    CoreProperties_Author_Value matches /[bcdfghjklmnpqrstvwxz]{4,}/i or CoreProperties_Author_Value matches /[aeuoiy]{4,}/i or CoreProperties_LastAuthor_Value matches /[bcdfghjklmnpqrstvwxz]{4,}/i or CoreProperties_LastAuthor_Value matches /[aeuoiy]{4,}/i
}

rule OFFICE_word {
	meta:
		description = "OFFICE DOCUMENT with 0 word"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	condition:
	    ExtendedProperties_Words_Value matches /[^0-9]0[^0-9]/ or ExtendedProperties_Characters_Value matches /[^0-9]0[^0-9]/
}

rule OFFICE_canary {
	meta:
		description = "Office with potential TOken canary"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://canarytokens.com/"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$canary0 = /Relationship.*\s+Target=(\")?(http|ftp)(s)?\:\/\/.*\s+TargetMode=(\")?External/ nocase wide ascii
		$canary1 = /INCLUDEPICTURE\s+\"(http|ftp)(s)?\:\/\// nocase wide ascii
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and any of ($canary*)
}

rule OFFICE_file_page {
	meta:
		description = "OFFICE DOCUMENT contains only one page"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		var_match = "office_file_bool"
	condition:
	    (uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileType matches /CL_TYPE_ZIP|CL_TYPE_MSOLE|CL_TYPE_OLE|CL_TYPE_OOXML|CL_TYPE_MSWORD|CL_TYPE_MSXL/) and SummaryInfo_pagecount_int == 1
}

rule OFFICE_file {
	meta:
		description = "OFFICE DOCUMENT"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 1
		var_match = "office_file_bool"
	condition:
	    (uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileType matches /CL_TYPE_MSOLE|CL_TYPE_OLE|CL_TYPE_OOXML|CL_TYPE_MSWORD|CL_TYPE_MSXL/) and (not CDBNAME matches /\.zip$|\.jar$/)
}

rule Suspect_MSDT_OFFICE {
	meta:
		description = "Office with scheme MS-MSDT (exploit for run command)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		reference = "https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/"
		check_level2 = "check_command_bool,check_clsid_bool,check_registry_bool"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution"
	strings:
		$msdt = "ms-msdt" nocase
	condition:
	    ( uint32be(0) == 0xd0cf11e0 or uint32be(0) == 0x504b0304 or FileParentType matches /->CL_TYPE_ZIP$|->CL_TYPE_MSOLE|->CL_TYPE_OLE|->CL_TYPE_OOXML|->CL_TYPE_MHTML|->CL_TYPE_MSWORD|->CL_TYPE_MSXL/) and $msdt
}
