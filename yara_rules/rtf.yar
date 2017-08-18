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

rule RTF_CVE_2017_0199 { // NOT work 
   meta:
      description = "Detects RTF with exploit CVE-2017-0199 Olelink -- NOT WORK"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 1       
      version = "0.1"
   strings:
      $clam = { 68 00 74 00  74 00 70 00 } // TODO 
   condition:
      uint32(0) == 0x74725c7b and uint16(4) == 0x3166 and $clam
}
