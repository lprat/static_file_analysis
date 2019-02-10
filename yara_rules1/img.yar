rule IMG_url {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		description = "Image visual contains URI"
		tag = "attack.defense_evasion"
	condition:
		image2text matches /(http|ftp|https):\/\/\S+/
}

rule IMG_addr_coin {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "Image visual contains potential Bitcoin address"
		tag = "attack.defense_evasion"
	condition:
		image2text matches /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
}

rule IMG_phishing {
	meta:
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		description = "Image visual contains potential malicious message"
		tag = "attack.defense_evasion"
	condition:
		image2text matches /hacke|Bitcoin|webcam|antivirus|securit|Format|victim|video|contact|virus|trojan|crypt|password|passe|passwd|login|user/i
}
