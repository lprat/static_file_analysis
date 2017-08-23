rule OpenAction_In_PDF {
   meta:
      description = "Detects OpenAction in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 0
      var_match = "pdf_oaction_bool"
   strings:
      $a = /\/AA|\/OpenAction/
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $a
}

rule Action_In_PDF {
   meta:
      description = "Detects Action in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 0
      var_match = "pdf_action_bool"
   strings:
      $a = /\/Action/
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $a
}

rule Javascript_In_PDF {
   meta:
      description = "Detects Javascript in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 0
      var_match = "pdf_javascript_bool"
   strings:
      $a = /\/JavaScript |\/JS /
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and ($a or PDFStats_JavascriptObjects matches /[0-9]+/)
}

rule ASCIIDecode_In_PDF {
   meta:
      description = "Detects ASCII Decode in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 0
      var_match = "pdf_asciidecode_bool"
   strings:
      $a = /\/ASCIIHexDecode|\/ASCII85Decode/
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $a
}

rule oldversion_In_PDF {
   meta:
      description = "Old version PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 0
      var_match = "pdf_oldver12_bool"
   strings:
      $ver = /%PDF-1\.[3-9]/
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and not $ver
}

rule js_wrong_version_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                ($magic at 0 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $js and (not $ver or pdf_oldver12_bool)
}

rule embed_wrong_version_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                ($magic at 0 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $embed and (not $ver or pdf_oldver12_bool)
}

rule XDP_In_PDF {
   meta:
      description = "file XDP in PDF"
      author = "Lionel PRAT"
      reference = "Basic rule PDF"
      version = "0.1"
      weight = 2
      var_match = "pdf_xdp_bool"
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and FileType matches /CL_TYPE_XDP/
}

rule suspicious_js_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion) - modified by Lionel PRAT"
		version = "0.1"
		description = "Suspicious JS in PDF metadata"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction|\/AA/
		$attrib1 = /\/JavaScript |\/JS /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		$js3 = /(^|\n)[a-zA-Z_$][0-9a-zA-Z_$]{0,100}=[^;]{200,}/
		
	condition:
		($magic in (0..1024) or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and ((all of ($attrib*)) or (pdf_oaction_bool and pdf_javascript_bool)) and 2 of ($js*)
}

rule invalide_structure_PDF {
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		description = "Invalide structure PDF"
		weight = 5
		var_match = "pdf_invalid_struct_bool"
        strings:
                $magic = { 25 50 44 46 }
				// Required for a valid PDF
                $reg0 = /trailer\r?\n?.*\/Size.*\r?\n?\.*/
                $reg1 = /\/Root.*\r?\n?.*startxref\r?\n?.*\r?\n?%%EOF/
        condition:
                $magic in (0..1024) and not $reg0 and not $reg1
}

rule clam_invalide_structure_PDF {
	meta:
		author = "Lionel PRAT"
		description = "clamav check Invalide structure PDF"
		weight = 5
		version = "0.1"
		var_match = "pdf_invalid_struct_bool"
        condition:
                (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and (PDFStats_NoXREF_bool or PDFStats_BadTrailer_bool or PDFStats_NoEOF_bool or PDFStats_BadVersion_bool or PDFStats_BadHeaderPosition_bool)
}
                     
rule XFA_withJS_in_PDF {
   meta:
      description = "Detects Potential XFA with JS in PDF"
      author = "Lionel PRAT"
      reference = "EK Blackhole PDF exploit"
      version = "0.1"
      weight = 4
      var_match = "pdf_xfajs_bool"
   strings:
      $a = /\/XFA|http:\/\/www\.xfa\.org\/schema\//
      $b = "x-javascript" nocase
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $a and ($b or pdf_javascript_bool or pdf_oaction_bool)
}

rule XFA_in_PDF {
   meta:
      description = "Detects Potential XFA with JS in PDF"
      author = "Lionel PRAT"
      reference = "EK Blackhole PDF exploit"
      version = "0.1"
      weight = 3
      var_match = "pdf_xfa_bool"
   strings:
      $a = /\/XFA|http:\/\/www\.xfa\.org\/schema\//
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $a
}

rule URI_on_OPENACTION_in_PDF {
   meta:
      description = "Detects Potential URI on OPENACTION in PDF"
      author = "Lionel PRAT"
      reference = "TokenCanary.pdf"
      version = "0.1"
      weight = 2
      var_match = "pdf_uri_bool"
   strings:
      $a = /\/S\s*\/URI\s*\/URI\s*\(/
      $b = /\OpenAction/
   condition:
      (uint32(0) == 0x46445025 or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and $a and ($b or pdf_oaction_bool)
}
                     
rule shellcode_metadata_PDF {
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "Potential shellcode in PDF metadata"
                weight = 5
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic in (0..1024) and 1 of ($reg*)
}

rule potential_exploit_PDF{
	meta:
		author = "Glenn Edwards (@hiddenillusion) - modified by Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Potential exploit in PDF metadata"
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript |\/JS /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		($magic in (0..1024) or FileParentType matches /->CL_TYPE_PDF$/ or FileType matches /CL_TYPE_PDF/) and ((2 of ($attrib*)) or (pdf_asciidecode_bool and pdf_javascript_bool)) or (($action0 or pdf_action_bool) and #shell > 10 and 1 of ($cond*)) or (($action1 or pdf_action_bool) and $cond0 and $nop)
}

rule dangerous_embed_file_PDF{
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 8
		description = "Dangerous embed file in PDF"
		
	condition:
		FileParentType matches /->CL_TYPE_PDF$/ and FileType matches /CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_ELF|CL_TYPE_MACHO|CL_TYPE_OLE2|CL_TYPE_MSOLE2|CL_TYPE_MSCAB|CL_TYPE_RTF|CL_TYPE_ZIP|CL_TYPE_OOXML|CL_TYPE_AUTOIT|CL_TYPE_JAVA|CL_TYPE_SWF/
}

rule suspect_embed_file_PDF{
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "suspect embed file in PDF"
		
	condition:
		FileParentType matches /->CL_TYPE_PDF$/ and not FileType matches /CL_TYPE_TEXT|CL_TYPE_BINARY_DATA|CL_TYPE_UNKNOWN|CL_TYPE_ASCII|CL_TYPE_UTF/
}


