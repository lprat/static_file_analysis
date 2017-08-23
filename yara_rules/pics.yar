rule Embedded_EXE_Cloaking {
        meta:
                description = "Detects an embedded executable in a non-executable file"
                author = "Florian Roth"
                date = "2015/02/27"
                weight = 9
        strings:
                $noex_png = { 89 50 4E 47 }
                $noex_pdf = { 25 50 44 46 }
                $noex_rtf = { 7B 5C 72 74 66 31 }
                $noex_jpg = { FF D8 FF E0 }
                $noex_gif = { 47 49 46 38 }
                $mz  = { 4D 5A }
                $a1 = "This program cannot be run in DOS mode"
                $a2 = "This program must be run under Win32"
        condition:
                (
                        ( $noex_png at 0 ) or
                        ( $noex_pdf at 0 ) or
                        ( $noex_rtf at 0 ) or
                        ( $noex_jpg at 0 ) or
                        ( $noex_gif at 0 )
                )
                and
                for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule Cloaked_as_JPG {
   meta:
      description = "Detects a cloaked file as JPG"
      author = "Florian Roth (eval section from Didier Stevens)"
      date = "2015/02/29"
      weight = 6
   strings:
      $fp1 = "<!DOCTYPE" ascii
   condition:
      uint16be(0x00) != 0xFFD8 and
      extension matches /\.jpg/i and
      filetype != "GIF" and
      /* and
      not filepath contains "ASP.NET" */
      not $fp1 in (0..30) and
      not uint32be(0) == 0x89504E47 /* PNG Header */
}

rule GIFCloaked_Webshell {
    meta:
        description = "Detects a webshell that cloakes itself with GIF header(s) - Based on Dark Security Team Webshell"
        author = "Florian Roth"
        hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
        weight = 8
    strings:
        $s0 = "input type"
        $s1 = "<%eval request"
        $s2 = "<%eval(Request.Item["
        $s3 = "LANGUAGE='VBScript'"
    condition:
        uint32be(0x00) == 0x47494638 // GIF Header
        and ( 1 of ($s*) )
}
