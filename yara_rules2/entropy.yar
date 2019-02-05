import "math"

rule entropy_low_risk {
	meta: 
        author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "File with low entropy (potential compressed)"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution,attack.defense_evasion"
	condition:
		check_entropy_bool and math.entropy(0, filesize) <= 1
}

rule entropy_high_risk {
	meta: 
        author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "File with high entropy (Packed, encrypted, ...)"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution,attack.defense_evasion"
	condition:
		check_entropy_bool and math.entropy(0, filesize) >= 7.0
}

rule entropy_middle_risk {
	meta: 
        author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "File with middle entropy (Potential: Packed, encrypted, ...)"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution,attack.defense_evasion"
	condition:
		check_entropy_bool and math.entropy(0, filesize) >= 6.0 and math.entropy(0, filesize) < 7.0
}
