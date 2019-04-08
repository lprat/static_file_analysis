//TODO: https://github.com/embedi/CVE-2017-11882 

rule RTF_obfusced {
   meta:
      description = "Detects RTF obfuscated"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 8
      version = "0.1"
      var_match = "rtf_file_bool"
      check_level2 = "check_clsid_bool,check_command_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution,attack.defense_evasion"
   condition:
      (uint32(0) == 0x74725c7b and uint16(4) != 0x3166) or (PathFile matches /.*\.rtf$|.*\.doc?$/i and uint16(4) != 0x3166) or (CDBNAME matches /.*\.rtf$|.*\.doc?$/i and uint16(4) != 0x3166)
}

rule CVE201711882_RTF {
   meta:
      description = "Detects RTF with possible OLE exploit on equation.2"
      author = "Lionel PRAT"
      reference = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-11882"
      weight = 7
      version = "0.1"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      var_match = "rtf_file_bool"
      check_level2 = "check_clsid_bool,check_command_bool,check_winapi_bool"
   condition:
      ((uint32(0) == 0x74725c7b and uint16(4) == 0x3166) or rtf_file_bool) and (FileType matches /CL_TYPE_OLE/ or FileParentType matches /->CL_TYPE_RTF$/) and serr contains "rtf embedded object, description:equation.2"
}


rule CVE20170199_RTF {
   meta:
      description = "Detects RTF with possible exploit CVE-2017-0199 Olelink"
      author = "Lionel PRAT"
      reference = "https://github.com/bhdresh/CVE-2017-0199"
      weight = 8      
      version = "0.1"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      var_match = "rtf_file_bool"
      check_level2 = "check_clsid_bool,check_command_bool"
   strings:
      $linkinfo = { 4C 00 69 00 6E 00 6B 00 49 00 6E 00 66 00 6F }
   condition:
      ((uint32(0) == 0x74725c7b and uint16(4) == 0x3166) or FileType matches /CL_TYPE_RTF/ or PathFile matches /.*\.rtf$/i or CDBNAME matches /.*\.rtf$/i or FileParentType matches /->CL_TYPE_RTF$/) and $linkinfo
}

rule OLE_in_RTF {
   meta:
      description = "Detects Ole in RTF"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 5      
      version = "0.1"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      check_level2 = "check_clsid_bool,check_command_bool,check_entropy_bool,check_winapi_bool"
   condition:
      ((uint32(0) == 0x74725c7b and uint16(4) == 0x3166) or rtf_file_bool) and (FileType matches /CL_TYPE_OLE/ or FileParentType matches /->CL_TYPE_RTF$/)
}

rule RTF_embed {
   meta:
      description = "Rtf embed file/element"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 0
      version = "0.1"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      check_level2 = "check_entropy_bool"
   condition:
      FileParentType matches /->CL_TYPE_RTF$/
}

rule RTFfile {
   meta:
      description = "RTF file"
      author = "Lionel PRAT"
      reference = "Internal Research"
      weight = 1      
      version = "0.1"
      check_level2 = "check_clsid_bool"
      tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
      var_match = "rtf_file_bool"
   condition:
      (uint32(0) == 0x74725c7b and uint16(4) == 0x3166) or FileType matches /CL_TYPE_RTF/ or PathFile matches /.*\.rtf$/i or CDBNAME matches /.*\.rtf$/i
}
