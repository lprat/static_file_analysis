rule RTF_obfusced {
   meta:
      description = "Detects RTF obfuscated"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 8
      version = "0.1"
   condition:
      uint32(0) == 0x74725c7b and uint16(4) != 0x3166
}


rule CVE20170199_RTF {
   meta:
      description = "Detects RTF with possible exploit CVE-2017-0199 Olelink"
      author = "Lionel PRAT"
      reference = "https://github.com/bhdresh/CVE-2017-0199"
      weight = 8      
      version = "0.1"
   strings:
      $linkinfo = { 4C 00 69 00 6E 00 6B 00 49 00 6E 00 66 00 6F }
   condition:
      ((uint32(0) == 0x74725c7b and uint16(4) == 0x3166) or FileParentType matches /->CL_TYPE_RTF$/ ) and $linkinfo
}

rule OLE_in_RTF {
   meta:
      description = "Detects Ole in RTF"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 5      
      version = "0.1"
   strings:
      $ole1 = { 4F 00  6C 00 65 }
      $ole2 = "ole" nocase
   condition:
      ((uint32(0) == 0x74725c7b and uint16(4) == 0x3166) or FileParentType matches /->CL_TYPE_RTF$/ ) and (any of ($ole*) or FileType matches /CL_TYPE_OLE/)
}
