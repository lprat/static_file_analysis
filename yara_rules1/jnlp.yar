rule Jnlp_file {
	meta:
		description = "Java Network Launching Protocol File (.jnlp)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/new-headaches-how-the-pawn-storm-zero-day-evaded-javas-click-to-play-protection/"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194"
	strings:
	    $jnlp0 = "/jnlp" nocase
	    $jnlp1 = "<jnlp" nocase
	    $ref0 = "codebase=" nocase
	    $ref1 = "jar href=" nocase
	    $uri = "://" nocase
	condition:
	    $uri and (any of ($jnlp*) or PathFile matches /.*\.jnlp$/i or CDBNAME matches /.*\.jnlp$/i) and any of ($ref*)
}
