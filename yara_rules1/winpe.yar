//PE extension:  .cpl, .exe, .dll, .ocx, .sys, .scr, .drv, .efi, .pif

import "math"
import "pe"

rule Suspicious_Numbers_Section_API_PE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious number of section"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 6
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.number_of_sections < 2 or pe.number_of_sections > 8)
}

rule Suspicious_checksum_PE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious checksum PE"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.checksum == pe.calculate_checksum())
}

rule Suspicious_export_PE
{
    meta:
        author = "Lionel PRAT"
        description = "PE export function(s)"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.number_of_exports > 0)
}

rule Suspicious_Section_Name_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious name in section PE"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		for any j in (0..pe.number_of_sections - 1): (not pe.sections[j].name matches /\.data|\.text|\.code|\.reloc|\.idata|\.edata|\.rdata|\.bss|\.rsrc/)
}

rule Suspicious_Section_size_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Suspicious rawdata length 0 and virtual size > 0 in section PE"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		for any j in (0..pe.number_of_sections - 1): (pe.sections[j].raw_data_size == 0 and pe.sections[j].virtual_size > 0)
}

rule Suspicious_date_compilation_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Suspicious date compilation 7 day before now"
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.timestamp > now_7_int)
}

rule  Suspicious_dateRes_compilation_winPE
{
    meta:
        reference = "http://malbabble.blogspot.com/2015/08/pe-time-stamps-and-yara.html"
        description = "Suspicious date compilation"
		weight = 4
	condition:
		pe.resource_timestamp != 0 and
		pe.resource_timestamp < pe.timestamp
}
			
rule Entropy_Packed_Win_PE
{
	meta: 
		description = "Very high or very low entropy means that file is compressed or encrypted since truly random data is not common"
		weight = 6
		tag = "attack.defense_evasion"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(math.entropy(0, filesize) >= 7.0 or math.entropy(0, filesize) <= 1)
}

rule Entropy_Section_Win_PE
{
	meta: 
	    reference = "https://github.com/DFIRnotes/rules/blob/master/pe_upx.yara"
		description = "Very high or very low entropy means that section is compressed or encrypted since truly random data is not common"
		weight = 5
		tag = "attack.defense_evasion"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		for any j in (0..pe.number_of_sections - 1): (
			math.entropy(pe.sections[j].raw_data_offset, pe.sections[j].raw_data_size) >= 6
		)
}

rule Notcontains_InternalOrOriginal_Name_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Pe not contains internalname or originalfilename" // NOT WORK! if version_info not exist, the pe.version_info don't put boolean response
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		((not pe.version_info["InternalName"] matches /\S+/) or (not pe.version_info["OriginalFilename"] matches /\S+/))
}
rule Win_PE_winnet
{
    meta:
        author = "Lionel PRAT"
        description = "Pe file call WINNET.dll" 
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and pe.imports ("wininet.dll") 
}

rule dotnet
{
    meta:
        description = "Potential Dotnet code - you can decompile with ilspy"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 1
        reference = "book .NET IL Assembler page 68"
    strings:
        $dotnetMagic = "BSJB" ascii
    condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/) and $dotnetMagic
}

rule exe_pyinst
{
    meta:
        description = "Potential Python executable (use pyinstxtractor or binwalk)"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 1
        reference = "https://sourceforge.net/projects/pyinstallerextractor/"
    strings:
        $pythonMagic = "MEI\x0c\x0b\x0a\x0b\x0e" ascii
    condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/) and $pythonMagic
}

rule py2exe
{
    meta:
        description = "Potential Python executable (use unpy2exe)"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 1
        reference = "https://github.com/matiasb/unpy2exe/blob/master/unpy2exe.py"
    strings:
        $pyinstaller = "MEI\x0c\x0b\x0a\x0b\x0e" ascii
        $pythonMagix = "\x03\xf3\x0d\x0a" ascii
        $pythonMagic1 = "\x99N\x0d\x0a" ascii
        $pythonMagic2 = "\xfc\xc4\x0d\x0a" ascii
        $pythonMagic3 = "\x87\xc6\x0d\x0a" ascii
        $pythonMagic4 = "*\xeb\x0d\x0a" ascii
        $pythonMagic5 = "-\xed\x0d\x0a" ascii
        $pythonMagic6 = ";\xf2\x0d\x0a" ascii
        $pythonMagic7 = "m\xf2\x0d\x0a" ascii
        $pythonMagic8 = "\xb3\xf2\x0d\x0a" ascii
        $pythonMagic9 = "\xd1\xf2\x0d\x0a" ascii
        $pythonMagic10 = "\xef\xf2\x0d\x0a" ascii
        $pythonMagic11 = "\xb8\x0b\x0d\x0a" ascii
        $pythonMagic12 = "E\x0c\x0d\x0a" ascii
        $pythonMagic13 = "X\x0c\x0d\x0a" ascii
        $pythonMagic14 = "v\x0c\x0d\x0a" ascii
        $pythonMagic15 = "\xb2\x0c\x0d\x0a" ascii
        $pythonMagic16 = "\x16\x0d\x0d\x0a" ascii
        $pythonMagic17 = " \x0d\x0d\x0a" ascii
        $pythonMagic18 = ">\x0d\x0d\x0a" ascii
    condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/) and (any of ($pythonMagic*) or ($pythonMagix and not $pyinstaller))
}

rule autoit
{
    meta:
        description = "Potential autoit executable"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 4
        reference = "https://github.com/Cisco-Talos/clamav-devel/blob/c68f996e6a6f252be5210634f4429a6f1bd8e3f5/libclamav/filetypes_int.h"
    strings:
        $autoit = "\xa3\x48\x4b\xbe\x98\x6c\x4a\xa9\x99\x4c\x53\x0a\x86\xd6\x48\x7d\x41\x55\x33\x21\x45\x41\x30" ascii
    condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/) and $autoit
}        

rule Win_Packer_UPX
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer UPX" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
		$upx = "upX" wide ascii
		$upx0 = "UPX0" wide ascii
		$upx1 = "UPX1" wide ascii
		$upx2 = "UPX2" wide ascii
		$upxx = "UPX!" wide ascii
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and (1 of ($upx0, $upx1, $upx2)) or ($upxx or $upx)
}

rule Win_Packer_ASPACK
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer ASPack" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
		$aspack = ".aspack"
        $asdata = ".adata"
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and $aspack and $asdata
}

rule Win_Packer_FSG
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer FSG" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $ep1 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
        $ep2 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }
        $ep3 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
        $ep4 = { EB 01 ?? EB 02 ?? ?? ?? 80 ?? ?? 00 }
        $ep5 = { BE ?? ?? ?? 00 BF ?? ?? ?? 00 BB ?? ?? ?? 00 53 BB ?? ?? ?? 00 B2 80 }
        $ep6 = { EB 02 CD 20 03 ?? 8D ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? EB 02 }
        $ep7 = { EB 02 CD 20 ?? CF ?? ?? 80 ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 }
        $ep8 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 }
        $ep9 = { 01 00 4E 33 01 10 02 00 00 60 01 00 00 04 00 00 00 32 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40}
        $ep10 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 } //v133 -> dulek peid
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and (any of ($ep*))
}

rule Win_Packer_Pecompact
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer PECompact" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $pec1 = {70656331}
        $pec2 = {70656332}
        $pec = "PECompact2"
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and (($pec1 at 0x01c8 and $pec2 at 0x01f0) or $pec)
}

rule Win_Packer_upack
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer Upack" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $ep = {0B 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 18 10 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 10 00 00 00 02 00 00}
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and $ep
}

rule Win_Packer_petite
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer PEtite" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $petite = ".petite"
        $petite2 = "petite"
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and ($petite or $petite2)
}

rule Win_Packer_mew
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer Mew" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $mew = "MEW"
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and $mew
}

rule Win_Packer_YZPack
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer YZPack" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $yz = ".yzpack"
        $yz2 = ".yzpack2"
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and ($yz or $yz2)
}

rule Win_Packer_MPRESS
{
    meta:
        author = "https://github.com/unipacker/unipacker"
        description = "Packer MPRESS" 
        version = "0.1"
        reference = "https://github.com/unipacker/unipacker/blob/master/unipacker/packer_signatures.yar"
		weight = 1
	strings:
		$magic_class = { ca fe ba be }
        $mp = ".MPRESS1"
        $mp2 = ".MPRESS2"
    condition:
		(uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))) and ($mp or $mp2)
}

rule IsNET_EXE : PECheck
{
    meta:
        author = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
        description = "PE IsNET_EXE" 
        version = "0.1"
        reference = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		pe.imports ("mscoree.dll","_CorExeMain")
}

rule IsNET_DLL : PECheck
{
    meta:
        author = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
        description = "PE IsNET_DLL" 
        version = "0.1"
        reference = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		pe.imports ("mscoree.dll","_CorDllMain")
}

rule IsDLL : PECheck
{
    meta:
        author = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
        description = "PE IsDLL" 
        version = "0.1"
        reference = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000

}

rule IsConsole : PECheck
{
    meta:
        author = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
        description = "PE IsConsole" 
        version = "0.1"
        reference = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0003
}

rule IsWindowsGUI : PECheck
{
    meta:
        author = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
        description = "PE IsWindowsGUI" 
        version = "0.1"
        reference = "https://github.com/Yara-Rules/rules/blob/master/packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0002
}


rule HasOverlay : PECheck
{
	meta: 
		author="_pusher_"
		description = "Overlay Check"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//stupid check if last section is 0		
		//not (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x0 and

		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) < filesize
		
}

rule HasTaggantSignature : PECheck
{
	meta: 
		author="_pusher_"
		description = "TaggantSignature Check"
		date="2016-07"
		weight = 1
	strings:		
		$a0 = { 54 41 47 47 ?? ?? ?? ?? ?? ?? 00 00 ?? 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 09 30 07 06 05 2B 0E 03 02 1A 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 01 A0 82 ?? ?? 04 82 ?? ?? ?? 00 01 00 ?? ?? }
		//$c0 = { 06 09 2A 86 }
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//TAGG+4E==packerid
		//(uint32be(@a0+0x4E) == 0x0B51D132) and
		//(uint32be(@a0+0x12) == 0x006092a86) and
		//(uint32be(@a0+0x12)) == uint32be(@c0) and

		//uint32be(@a0+0x04) < (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) and
		$a0
}


rule HasDigitalSignature : PECheck
{
	meta: 
		author="_pusher_"
		description = "DigitalSignature Check"
		date="2016-07"
		weight = 1
	strings:		
		//size check is wildcarded
		$a0 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 68 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 5A 30 58 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
		$a1 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0B 30 09 06 05 2B 0E 03 02 1A 05 00 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 ?? 30 ?? 30 ?? 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 ?? 03 01 00 A0 ?? A2 ?? 80 00 30 21 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 }
		$a2 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0E 30 ?? 06 ?? ?? 86 48 86 F7 0D 02 05 05 00 30 67 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 59 30 57 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 20 30 0C 06 08 2A 86 48 86 F7 0D 02 05 05 00 04 }
		$a3 = { ?? ?? ?? ?? 00 02 02 00 30 82 ?? ?? 06 09 2A 86 48 86 F7 0D 01 07 02 A0 82 ?? ?? 30 82 ?? ?? 02 01 01 31 0F 30 ?? 06 ?? ?? 86 48 01 65 03 04 02 01 05 00 30 78 06 0A 2B 06 01 04 01 82 37 02 01 04 A0 6A 30 68 30 33 06 0A 2B 06 01 04 01 82 37 02 01 0F 30 25 03 01 00 A0 20 A2 1E 80 1C 00 3C 00 3C 00 3C 00 4F 00 62 00 73 00 6F 00 6C 00 65 00 74 00 65 00 3E 00 3E 00 3E 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 }
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in ( (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size)..filesize)) )
		//its not always like this:
		//and  uint32(@a0) == (filesize-(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size))
}

rule HasDebugData : PECheck
{
	meta: 
		author = "_pusher_"
		description = "DebugData Check"
		date="2016-07"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//orginal
		//((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
		//((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
		(IsPE32 or IsPE64) and
		((uint32(uint32(0x3C)+0xA8+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0) and (uint32be(uint32(0x3C)+0xAC+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0))
}

rule IsBeyondImageSize : PECheck
{
	meta: 
		author = "_pusher_"
		date = "2016-07"
		description = "Data Beyond ImageSize Check"
		weight = 4
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		for any i in (0..pe.number_of_sections-1):
		( 
		(pe.sections[i].virtual_address+pe.sections[i].virtual_size) > (uint32(uint32(0x3C)+0x50)) or
		(pe.sections[i].raw_data_offset+pe.sections[i].raw_data_size) > filesize
		)
}

rule ImportTableIsBad : PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ImportTable is bad"
		weight = 4
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 		//Import_Table_RVA+Import_Data_Size .. cannot be outside imagesize
		((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))     > (uint32(uint32(0x3C)+0x50)) 
		or
		(((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))  == 0x0)
		//or

		//doest work
		//pe.imports("", "")

		//need to check if this is ok.. 15:06 2016-08-12
		//uint32( uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+uint32(uint32(0x3C)+0x34)) == 0x408000
		//this works.. 
		//uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+uint32(uint32(0x3C)+0x34) == 0x408000
		
		//uint32be(uint32be(0x409000)) == 0x005A
		//pe.image_base
		//correct:

		//uint32(uint32(0x3C)+0x80)+pe.image_base == 0x408000

		//this works (file offset):
		//$a0 at 0x4000
		//this does not work rva:
		//$a0 at uint32(0x0408000)

		//(uint32(uint32(uint32(0x3C)+0x80)+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+pe.image_base) == 0x0)

		or
		//tiny PE files..
		(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) > filesize)

		//or
		//uint32(uint32(0x3C)+0x80) == 0x21000
   		//uint32(uint32(uint32(0x3C)+0x80)) == 0x0
		//pe.imports("", "")
		)				
}

rule ExportTableIsBad : PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ExportTable is bad"
		weight = 4
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 		//Export_Table_RVA+Export_Data_Size .. cannot be outside imagesize
		((uint32(uint32(0x3C)+0x78+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x7C+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))     > (uint32(uint32(0x3C)+0x50)) 
		)		
}


rule HasModified_DOS_Message : PECheck
{
	meta: 
		author = "_pusher_"
		description = "DOS Message Check"
		date="2016-07"
		weight = 3
	strings:	
		$a0 = "This program must be run under Win32" wide ascii nocase
		$a1 = "This program cannot be run in DOS mode" wide ascii nocase
		//UniLink
		$a2 = "This program requires Win32" wide ascii nocase
		$a3 = "This program must be run under Win64" wide ascii nocase
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and not
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule HasRichSignature : PECheck
{
	meta: 
		author = "_pusher_"
		description = "Rich Signature Check"
		date="2016-07"
		weight = 1
	strings:	
		$a0 = "Rich" ascii
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule IsGoLink
{
	meta:
		author="_pusher_"
		date = "2016-08"
		description="www.GoDevTool.com"
		weight = 1
	strings:
		$a0 = { 47 6F 4C 69 6E 6B }
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		$a0 at 0x40

}


rule borland_cpp {
	meta:
		author = "_pusher_"
		description = "Borland C++"
		date = "2015-08"
		version = "0.1"
		weight = 1
	strings:
		$c0 = { 59 5F 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c1 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 6A 00 E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c2 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
	condition:
		(
		//linker 2.25 and 5.00
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or
		((pe.linker_version.major == 5) and (pe.linker_version.minor == 0 ))
		) and
		any of them
}

rule borland_delphi {
	meta:
		author = "_pusher_"
		description = "Borland Delphi 2.0 - 7.0 / 2005 - 2007"
		date = "2016-03"
		version = "0.2"
		weight = 1
	strings:
		$c0 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? FF A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 }
		$c1 = { 53 8B D8 33 C0 A3 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 33 C0 A3 ?? ?? ?? ?? 8D 43 08 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		//some x64 version of delphi
		$c2 = { 53 48 83 EC 20 48 89 CB C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 48 33 C9 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 43 10 48 89 05 ?? ?? ?? ?? 48 8D 05 ?? FC FF FF 48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 D9 48 8D 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
		//unusual delphi version unknown version (unpackme- FSG 1.31 - dulek)
		$c3 = { 50 6A 00 E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 00 00 00 00 C7 42 0C 00 00 00 00 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
		//delphi2
		$c4 = { E8 ?? ?? ?? ?? 6A ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A ?? ?? ?? B8 ?? ?? ?? ?? C3 }
		//delphi3
		$c5 = { 50 6A 00 E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 55 8B EC 33 C0 }
		//delphi5
		$c6 = { 50 6A ?? E8 ?? ?? FF FF BA ?? ?? ?? ?? 52 89 05 ?? ?? ?? ?? 89 42 04 C7 42 08 ?? ?? ?? ?? C7 42 0C ?? ?? ?? ?? E8 ?? ?? ?? ?? 5A 58 E8 ?? ?? ?? ?? C3 }
	condition:
		any of them
		and
		(
		//if its not linker 2.25 its been modified (unpacked usually)
												//unknown x64 build of delphi
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or ((pe.linker_version.major == 8) and (pe.linker_version.minor == 0 ))
		//unpacked files usually have this linker:
		or ((pe.linker_version.major == 0) and (pe.linker_version.minor == 0 )) )
		//could check for dvclal.. maybe too much
}

rule free_pascal {
	meta:
		author = "_pusher_"
		description = "Free Pascal"
		date = "2015-08"
		version = "0.1"
		weight = 1
	strings:
		$c0 = { 55 89 E5 83 ?? ?? 89 5D FC B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 75 0C 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 }
		$c1 = { 55 89 E5 53 B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 80 3D ?? ?? ?? ?? 00 75 0C 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A3 ?? ?? ?? ?? B8 }
		$c2 = { 55 89 E5 83 EC 04 89 5D FC B8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? A0 ?? ?? ?? ?? 84 C0 75 05 E8 ?? ?? ?? ?? C7 05 }
	condition:
		any of them
}

rule borland_delphi_dll {
	meta:
		author = "_pusher_"
		description = "Borland Delphi DLL"
		date = "2015-08"
		version = "0.1"
		info = "one is at entrypoint"
		weight = 1
	strings:
		$c0 = { BA ?? ?? ?? ?? 83 7D 0C 01 75 ?? 50 52 C6 05 ?? ?? ?? ?? ?? 8B 4D 08 89 0D ?? ?? ?? ?? 89 4A 04 }
		$c1 = { 55 8B EC 83 C4 ?? B8 ?? ?? ?? ?? E8 ?? ?? FF FF E8 ?? ?? FF FF 8D 40 00 }
	condition:
		any of them
}

rule borland_component {
	meta:
		author = "_pusher_"
		description = "Borland Component"
		date = "2015-08"
		version = "0.1"
		weight = 1
	strings:
		$c0 = { E9 ?? ?? ?? FF 8D 40 00 }
	condition:
		$c0 at pe.entry_point
}

rule PureBasic : Neil Hodgson
{
      	meta:
		author="_pusher_"
		date="2016-07"
		description = "PureBasic"
		weight = 1
	strings:
		//make check for msvrt.dll
		$c0 = { 55 8B EC 6A 00 68 00 10 00 00 6A ?? FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 C7 05 ?? ?? ?? ?? 10 00 00 00 A1 ?? ?? ?? ?? 50 6A ?? 8B 0D ?? ?? ?? ?? 51 FF 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? 5D C3 CC CC CC CC CC CC CC CC CC }
		$c1 = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }
		$aa0 = "\x00MSVCRT.dll\x00" ascii
		$aa1 = "\x00CRTDLL.dll\x00" ascii
	condition:
		(for any of ($c0,$c1) : ( $ at pe.entry_point  )) and 
		(any of ($aa*) ) and
		((pe.linker_version.major == 2) and (pe.linker_version.minor == 50 ))
}

rule PureBasicDLL : Neil Hodgson
{
      meta:
		author="malware-lu"
		description = "PureBasic DLL"
		weight = 1
strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 ?? ?? ?? 10 E8 }

condition:
		$a0 at pe.entry_point
}

rule PureBasic4xDLL : Neil Hodgson
{
      meta:
		author="malware-lu"
		description = "PureBasic4 DLL"
		weight = 1
strings:
		$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

condition:
		$a0 at pe.entry_point
}

rule SkDUndetectabler : SkDrat {
	meta:
		author = "_pusher_"
		description = "SKDrat"
		weight = 4
	condition:
		(
		borland_delphi or //check All FSG or
		((pe.linker_version.major == 6) and (pe.linker_version.minor == 0 ))
		)
		and
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size < filesize) and
		//is overlay at offset 2A00,1A00,C00,745,739
		//pe.overlay & pe.overlay_size would have been prettier
		( 
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000739)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000745)  or
		//Uncompressed
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00000C00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00002A00)  or
		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size == 0x00001A00)
		)
		and
		//is xored MZ ?
		( 
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x6275 or
		uint16(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x4057
		)
}

/* usefull ? 18:53 2016-08-12
rule MicrosoftVisualCV80
{
      meta:
		author="malware-lu"
		description = "MS Visual c"
		weight = 1
strings:
		$a0 = { 6A 14 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? BB 94 00 00 00 53 6A 00 8B ?? ?? ?? ?? ?? FF D7 50 FF ?? ?? ?? ?? ?? 8B F0 85 F6 75 0A 6A 12 E8 ?? ?? ?? ?? 59 EB 18 89 1E 56 FF ?? ?? ?? ?? ?? 56 85 C0 75 14 50 FF D7 50 FF ?? ?? ?? ?? ?? B8 }
condition:
		$a0 at pe.entry_point
}
*/

rule Cygwin : Red Hat
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "Cygwin compiler"
		weight = 1
	strings:		
		$a0 = "cygwin1.dll" ascii nocase
		$aa1 = "cygwin_internal"
		$aa2 = "cygwin_detach_dll"
	condition:
		(
		(pe.linker_version.major == 2) and (pe.linker_version.minor == 56 ) or
		(pe.linker_version.major == 2) and (pe.linker_version.minor == 24 ) or
		(pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )
		)
		and
		($a0 and (any of ($aa*) ))
}

rule MinGW_1
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "MinGW compiler"
		weight = 1
	strings:		
		$a0 = "msvcrt.dll" ascii nocase
		$aa1 = "Mingw-w64 runtime failure:"
		$aa2 = "-LIBGCCW32-EH-3-SJLJ-GTHR-MINGW32" wide ascii nocase
		$aa3 = "_mingw32_init_mainargs"
		//too wild ?
		$aa4 = "mingw32"
		$aa5 = "-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" wide ascii nocase
		$aa6 = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32" wide ascii nocase
		$aa7 = "Mingw runtime failure:"
	condition:
		(
		(pe.linker_version.major == 2) and (pe.linker_version.minor == 56 ) or
		(pe.linker_version.major == 2) and ((pe.linker_version.minor >= 21) and (pe.linker_version.minor <= 25))
		)
		and
		($a0 and (any of ($aa*) ))
}

rule FASM : flat assembler {
//abit weak, needs more targets & testing
	meta:
		author = "_pusher_"
		date = "2016-01"
		description = "http://flatassembler.net"
		weight = 1
	//strings:
		//$c0 = { 55 89 E5 83 EC 1C 8D 45 E4 6A 1C 50 FF 75 08 FF 15 ?? ?? ?? ?? 8B 45 E8 C9 C2 04 00 }
	condition:
		(
		//linker 1.60..1.79
		(pe.linker_version.major == 1) and ((pe.linker_version.minor >= 60) and (pe.linker_version.minor < 80))
		) 
		//and $c0
}

rule AutoIt
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "www.autoitscript.com/site/autoit/"
		weight = 1
	strings:		
		$aa0 = "AutoIt has detected the stack has become corrupt.\n\nStack corruption typically occurs when either the wrong calling convention is used or when the function is called with the wrong number of arguments.\n\nAutoIt supports the __stdcall (WINAPI) and __cdecl calling conventions.  The __stdcall (WINAPI) convention is used by default but __cdecl can be used instead.  See the DllCall() documentation for details on changing the calling convention." wide ascii nocase
		$aa1 = "AutoIt Error" wide ascii nocase
		$aa2 = "Missing right bracket ')' in expression." wide ascii nocase
		$aa3 = "Missing operator in expression." wide ascii nocase
		$aa4 = "Unbalanced brackets in expression." wide ascii nocase
		$aa5 = "Error parsing function call." wide ascii nocase
	
		$aa6 = ">>>AUTOIT NO CMDEXECUTE<<<" wide ascii nocase
		$aa7 = "#requireadmin" wide ascii nocase
		$aa8 = "#OnAutoItStartRegister" wide ascii nocase
		$aa9 = "#notrayicon" wide ascii nocase
		$aa10 = "Cannot parse #include" wide ascii nocase
	condition:
		5 of ($aa*)
}


rule PellesC : Pelle Orinius
{
	meta:
		author = "_pusher_"
		date = "2016-08"
		description = "www.smorgasbordet.com/pellesc"
		weight = 1
	strings:		
		$aa0 = " -- terminating\x0D\x0A\x00 -- terminating\x0A\x00CRT: \x00unexpected error\x00" wide ascii nocase	
		$aa1 = "unhandled exception (main)\x00unhandled exception in thread\x00unable to create thread\x00unable to destroy semaphore\x00" wide ascii nocase
		$aa2 = "unable to wait on semaphore\x00unable to post semaphore\x00unable to init semaphore\x00unable to unlock mutex\x00unable to lock mutex\x00unable to init mutex\x00" wide ascii nocase
		$aa3 = "invalid stream lock number\x00corrupt per-thread data\x00out of memory\x00unable to init threads\x00unable to init HEAP" wide ascii nocase
	condition:
		3 of ($aa*) and
		(pe.linker_version.major == 2) and (pe.linker_version.minor == 50 )
}

rule QtFrameWork
{
      	meta:
		author="_pusher_"
		date="2016-08"
		description = "QtFrameWork"
		weight = 1
	strings:
		$aa0 = "\x00Qt5Core.dll\x00" ascii
		$aa1 = "\x00QtCore4.dll\x00" ascii
	condition:
		(any of ($aa*) )
}

rule Win_PE
{
    meta:
        author = "Lionel PRAT"
        description = "Pe file" 
        version = "0.1"
		weight = 1
		check_level2 = "check_winapi_bool,check_registry_bool,check_command_bool,check_clsid_bool,check_packer_bool,check_antidebug_bool,check_cap_bool,check_crypt_bool,check_peid_bool"
	strings:
		$magic_class = { ca fe ba be }
    condition:
		uint16(0) == 0x5A4D or (FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL|CL_TYPE_binary/ and not (CDBNAME matches /.*\.class$/i or $magic_class at 0))
}

