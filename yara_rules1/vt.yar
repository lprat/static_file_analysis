rule VT_cve {
	meta:
		description = "Virus Total detect CVE use"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		tag = "attack.initial_access,attack.t1189"
	condition:
	    vt_detected matches /CVE[_\-]*[0-9]+/
}

rule VT_high {
	meta:
		description = "Virus Total detect malware"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 8
		tag = "attack.execution"
	condition:
	    vt_positives_int > 10
}

rule VT_low {
	meta:
		description = "Virus Total detect potential malware"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		tag = "attack.execution"
	condition:
	    vt_positives_int > 2 and vt_positives_int < 10
}
