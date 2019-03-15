rule java_obfusc {
	meta:
		description = "Java code obfuscated"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 7
	    tag = "attack.defense_evasion"
	strings:
		$obf0 = /[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf1 = /[aeuoiy]{4,}/ nocase
		$obf2 = /class \S*[bcdfghjklmnpqrstvwxz]{4,}/ nocase
		$obf3 = /class \S*[aeuoiy]{4,}/ nocase
		$obf4 = /\S*[bcdfghjklmnpqrstvwxz]{4,}\S*\(/ nocase
		$obf5 = /\S*[aeuoiy]{4,}\S*\(/ nocase
		$obf6 = /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/ nocase // base 64
		$obf7 = ".invoke(" nocase
		$obf8 = "invoke.getClass(" nocase
		$obf9 = ".getMethod(" nocase
		$obf10 = ".getClass()" nocase
		$obf11 = "java.lang.invoke.MethodHandle" nocase 
		$obf12 = "java.lang.reflect.InvocationHandler" nocase	
		$obf13= "java.applet.Applet" nocase
	condition:
	    (check_java_bool and 4 of ($obf*)) or ((decompiledjava matches /\.invoke\(/i or decompiledjava matches /java\.lang\.invoke\.MethodHandle|java\.lang\.reflect\.InvocationHandler/i) and (decompiledjava matches /class \S*[bcdfghjklmnpqrstvwxz]{4,}|class \S*[aeuoiy]{4,}|\S*[bcdfghjklmnpqrstvwxz]{4,}\S*\(|\S*[aeuoiy]{4,}\S*\(/i or decompiledjava matches /([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)/i))
}

rule java_embed {
	meta:
		description = "Java code potential embed applet/application"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.defense_evasion"
	strings:		
		$emb0 = "java.applet.Applet" nocase
		$emb1 = "javafx.application.Preloader"
	condition:
	    (check_java_bool and any of ($emb*)) or decompiledjava matches /java\.applet\.Applet|javafx\.application\.Preloader/i
}

rule java_io {
	meta:
		description = "Java IO File"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
	    tag = "attack.collect"
	strings:		
		$imp = "java.io.File" nocase
	condition:
	    (check_java_bool and $imp) or decompiledjava contains "java.io.File"
}

rule java_net {
	meta:
		description = "Java use network"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
	    tag = "attack.command_control"
	strings:		
		$imp0 = "java.net.URL" nocase
		$imp1 = "org.apache.http." nocase
		$imp2 = "java.net.URI" nocase
	condition:
	    (check_java_bool and any of ($imp*)) or decompiledjava matches /java\.net\.URL|org\.apache\.http\.|java\.net\.URI/i
}

rule java_net2 {
	meta:
		description = "Java use network for get file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.command_control,attack.defense_evasion"
	strings:		
		$imp0 = "javafx.application.HostServices" nocase
		$imp1 = "org.apache.http." nocase
		$imp2 = "java.net.URISyntaxException" nocase
	condition:
	    (check_java_bool and any of ($imp*)) or decompiledjava matches /javafx\.application\.HostServices|org\.apache\.http\.|java\.net\.URISyntaxException/i
}

rule java_crypt {
	meta:
		description = "Java use crypto"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.command_control"
	strings:		
		$imp0 = "javax.crypto" nocase
		$imp1 = "java.security.Key" nocase
		$imp2 = "java.net.URISyntaxException" nocase
		$imp3 = "org.apache.http." nocase
		
	condition:
	    (check_java_bool and any of ($imp*)) or decompiledjava matches /javax\.crypto|java\.security\.Key|java\.net\.URISyntaxException|org\.apache\.http\./i
}

rule java_eval {
	meta:
		description = "Java use eval"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
	    tag = "attack.command_control"
	strings:		
		$imp = "javax.script.ScriptEngine" nocase	
	condition:
	    (check_java_bool and $imp) or decompiledjava contains "javax.script.ScriptEngine"
}

