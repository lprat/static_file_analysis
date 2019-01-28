rule ClickOnce_appref_file {
	meta:
		description = "ClickOnce Appref-ms File"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 6
		reference = "https://dzone.com/articles/how-run-clickonce-application"
		tag = "attack.initial_access,attack.t1189,attack.t1192,attack.t1193,attack.t1194,attack.execution"
	strings:
	    $uri0 = "ftp://" nocase
	    $uri1 = "https://" nocase
	    $uri2 = "http://" nocase
	    $ClickOnce0 = ".application#" nocase
	    $ClickOnce1 = "Culture=" nocase
	    $ClickOnce2 = "PublicKeyToken=" nocase
	    $ClickOnce3 = "processorArchitecture=" nocase
	    
	condition:
	    any of ($uri*) and 2 of ($ClickOnce*)
}


