rule ZIP_crypt_dangerous {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 7
		description = "ZIP file CRYPTED with dangerous files"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.t1223,attack.execution,attack.defense_evasion"
	condition:
		zip_crypt_bool and EMBED_FILES matches /\.saz(\',|\'\])|\.application(\',|\'\])|\.chm(\',|\'\])|\.appref-ms(\',|\'\])|\.cmdline(\',|\'\])|\.jnlp(\',|\'\])|\.exe(\',|\'\])|\.gadget(\',|\'\])|\.dll(\',|\'\])|\.lnk(\',|\'\])|\.pif(\',|\'\])|\.com(\',|\'\])|\.sfx(\',|\'\])|\.bat(\',|\'\])|\.cmd(\',|\'\])|\.scr(\',|\'\])|\.sys(\',|\'\])|\.hta(\',|\'\])|\.cpl(\',|\'\])|\.msc(\',|\'\])|\.inf(\',|\'\])|\.scf(\',|\'\])|\.reg(\',|\'\])|\.jar(\',|\'\])|\.vb\S+(\',|\'\])|\.js\S+(\',|\'\])|\.ws\.+(\',|\'\])|\.ps\w+(\',|\'\])|\.ms\w+(\',|\'\])|\.jar(\',|\'\])|\.url(\',|\'\])|\.rtf(\',|\'\])|\.ppt\S+(\',|\'\])|\.xls\S+(\',|\'\])|\.doc\S+(\',|\'\])|\.pdf(\',|\'\])|\.zip(\',|\'\])|\.rar(\',|\'\])|\.tmp(\',|\'\])|\.py\S+(\',|\'\])|\.dotm(\',|\'\])|\.xltm(\',|\'\])|\.xlam(\',|\'\])|\.potm(\',|\'\])|\.ppam(\',|\'\])|\.ppsm(\',|\'\])|\.sldm(\',|\'\])/i
}

rule ZIP_crypted {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "ZIP file with password (crypted)"
		tag = "attack.defense_evasion"
	condition:
		zip_crypt_bool
}
