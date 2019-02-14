rule win_api_keylogger {
	meta:
		description = "Call windows API potential for activity Keylogger"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf;https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/"
		ids = "win_api"
	    tag = "attack.collection,attack.credential_access,attack.t1056"
	strings:
		$api1 = "ShowWindow" nocase ascii wide
		$api2 = "GetAsyncKeyState" nocase ascii wide
		$api3 = "SetWindowsHookEx" nocase ascii wide
		$api4 = "RegisterHotKey" nocase ascii wide
		$api5 = "GetMessage" nocase ascii wide
		$api6 = "UnhookWindowsHookEx" nocase ascii wide
		$api7 = "AttachThreadInput" nocase ascii wide
		$api8 = "GetForegroundWindow" nocase ascii wide
		$api9 = "GetKeyState" nocase ascii wide
		$api10 = "MapVirtualKey" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_screen {
	meta:
		description = "Call windows API potential for activity screen capture"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.collection,attack.t1113"
	strings:
		$api0 = "GetDC" nocase ascii wide
		$api1 = "GetWindowDC" nocase ascii wide
		$api2 = "CreateCompatibleDC" nocase ascii wide
		$api3 = "CreateCompatibleBitmap" nocase ascii wide
		$api4 = "SelectObject" nocase ascii wide
		$api5 = "BitBlt" nocase ascii wide
		$api6 = "WriteFile" nocase ascii wide
		$api7 = "GetClipboardData" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_antidebug {
	meta:
		description = "Call windows API potential for antidebugging"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "IsDebuggerPresent" nocase ascii wide
		$api1 = "CheckRemoteDebuggerPresent" nocase ascii wide
		$api2 = "OutputDebugString" nocase ascii wide
		$api3 = "FindWindow" nocase ascii wide
		$api4 = "GetStartupInfo" nocase ascii wide
		$api5 = "NtQueryInformationProcess" nocase ascii wide
		$api6 = "GetTickCount" nocase ascii wide //based time
		$api7 = "CountClipboardFormats" nocase ascii wide //clipboard empty?
		$api8 = "GetForeGroundWindow" nocase ascii wide
		$api9 = "ZwQueryInformation" nocase ascii wide
		$api10 = "QueryPerformanceCounter" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_clsid {
	meta:
		description = "Call windows API for create OLE/COM Obj (clsid)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_api"
	    tag = "attack.execution"
	strings:
		$api0 = "CoCreateInstance" nocase ascii wide
		$api1 = "OleInitialize" nocase ascii wide
	condition:
	    check_winapi_bool and all of ($api*)
}

rule win_api_unpack {
	meta:
		description = "Call windows API for potential unpack"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api1 = "VirtualAlloc" nocase ascii wide
		$api2 = "VirtualProtect" nocase ascii wide
	condition:
	    check_winapi_bool and all of ($api*)
}

rule win_api_injection {
	meta:
		description = "Call windows API potential for activity injection DLL/process/memory"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.defense_evasion,attack.privilege_escalation,attack.t1055,attack.t1181"
	strings:
		$api0 = "OpenProcess" nocase ascii wide
		$api1 = "VirtualAllocEx" nocase ascii wide
		$api2 = "WriteProcessMemory" nocase ascii wide
		$api3 = "CreateRemoteThread" nocase ascii wide
		$api4 = "GetWindowLong" nocase ascii wide
		$api5 = "SetWindowLong" nocase ascii wide
		$api6 = "SendNotifyMessage" nocase ascii wide
		$api7 = "SuspendThread" nocase ascii wide
		$api8 = "SetThreadContext" nocase ascii wide
		$api9 = "ResumeThread" nocase ascii wide
		$api10 = "QueueUserAPC" nocase ascii wide
		$api11 = "NtQueueApcThread" nocase ascii wide
		$api12 = "VirtualProtectEx" nocase ascii wide
		$api13 = "GetModuleHandle" nocase ascii wide
		$api14 = "AdjustTokenPrivileges" nocase ascii wide
		$api15 = "EnumProcesses" nocase ascii wide
		$api16 = "EnumProcessModules" nocase ascii wide
		$api17 = "GetThreadContext" nocase ascii wide
		$api18 = "MapViewOfFile" nocase ascii wide
		$api19 = "Module32First" nocase ascii wide
		$api20 = "Module32Next" nocase ascii wide
		$api21 = "Process32First" nocase ascii wide
		$api22 = "Process32Next" nocase ascii wide
		$api23 = "CreateToolhelp32Snapshot" nocase ascii wide
		$api24 = "Thread32First" nocase ascii wide
		$api25 = "Thread32Next" nocase ascii wide
		$api26 = "GetEIP" nocase ascii wide
		$api27 = "BroadcastSystemMessage" nocase ascii wide
	condition:
	    check_winapi_bool and 2 of ($api*)
}

rule win_api_gml {
	meta:
		description = "Call windows API potential for activity get module loaded in current process"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "GetModuleFilename" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_cert {
	meta:
		description = "Call windows API potential for activity on certificates stored"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.collection"
	strings:
		$api0 = "CertOpenSystemStore" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_nint {
	meta:
		description = "Call windows API potential for activity get info interface network"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.collection"
	strings:
		$api0 = "GetAdaptersInfo" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_resolv {
	meta:
		description = "Call windows API potential for resolve host"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.exfiltration,attack.c2c"
	strings:
		$api0 = "Gethostbyname" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_addr {
	meta:
		description = "Call windows API potential for string to adresse inet"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.exfiltration,attack.c2c"
	strings:
		$api0 = "inet_addr" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_promiscous {
	meta:
		description = "Call windows API for potential put promiscous mode on network interface"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution,attack.c2c,attack.t1102"
	strings:
		$api0 = "WSAIoctl" nocase ascii wide
		$api1 = "ioctlsocket" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_download {
	meta:
		description = "Call windows API potential for activity download"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution,attack.c2c,attack.t1102"
	strings:
		$api0 = "URLDownloadToFile" nocase ascii wide
		$api1 = "InternetOpenUrl" nocase ascii wide
		$api2 = "InternetReadFile" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_internet {
	meta:
		description = "Call windows API potential for activity network"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.exfiltration,attack.c2c"
	strings:
		$api0 = "ConnectNamedPipe" nocase ascii wide
		$api1 = /[^A-Z0-9]Connect[^A-Z0-9]/ nocase ascii wide
		$api2 = "InternetOpen" nocase ascii wide
		$api3 = "WSAStartup" nocase ascii wide
		$api4 = "WinHttpOpen" nocase ascii wide
		$api5 = "HttpOpenRequest" nocase ascii wide
		$api6 = "HttpSendRequest" nocase ascii wide
		$api7 = "HttpAddRequestHeaders" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_upload {
	meta:
		description = "Call windows API potential for activity upload"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.exfiltration"
	strings:
		$api0 = "InternetWriteFile" nocase ascii wide
		$api1 = "TransactNamedPipe" nocase ascii wide
		$api2 = "FtpPutFile" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_bind {
	meta:
		description = "Call windows API potential for activity listen on port network"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.c2c"
	strings:
		$api0 = "Accept" nocase ascii wide
		$api1 = /[^A-Z0-9]bind[^A-Z0-9]/ nocase ascii wide //fix false positive just check "bind"
	condition:
	    check_winapi_bool and all of ($api*)
}

rule win_api_service {
	meta:
		description = "Call windows API potential for activity create service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution, attack.persistence,attack.t1050"
	strings:
		$api0 = "CreateService" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_servicec {
	meta:
		description = "Call windows API potential for activity change service configuration"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution, attack.persistence,attack.t1031"
	strings:
		$api0 = "StartService" nocase ascii wide
		$api1 = "ChangeServiceConfig" nocase ascii wide
		$api2 = "ControlService" nocase ascii wide
		$api3 = "OpenSCManager" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_drop {
	meta:
		description = "Call windows API potential for activity dropper (store string/configuration/malicious file)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution,attack.collection,attack.exfiltration,attack.defense_evasion"
	strings:
		$api0 = "FindResource" nocase ascii wide
		$api1 = "LoadResource" nocase ascii wide
		$api2 = "SizeOfResource" nocase ascii wide
		$api3 = "LockResource" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_regw {
	meta:
		description = "Call windows API potential for activity on registry (write)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.execution,attack.c2c,attack.t1183,attack.t1209,attack.t1182,attack.t1103"
	strings:
		$api0 = "RegCreateKeyEx" nocase ascii wide
		$api1 = "RegSetValueEx" nocase ascii wide
		$api2 = "RegSetValue," nocase ascii wide
		$api3 = "RegSetValue" nocase ascii wide
		$api4 = "RtlCreateRegistryKey" nocase ascii wide
		$api5 = "RtlWriteRegistryValue" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_regr {
	meta:
		description = "Call windows API potential for activity on registry (read)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.execution,attack.c2c,attack.t1183,attack.t1209,attack.t1182,attack.t1103"
	strings:
		$api0 = "RegOpenKey" nocase ascii wide
		$api1 = "RegOpenKeyEx" nocase ascii wide
		$api2 = "RegQueryValue" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_hotkey {
	meta:
		description = "Call windows API potential for activity change key combination (CTRL+X)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.execution,attack.persistence"
	strings:
		$api0 = "RegisterHotKey" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_iocreate {
	meta:
		description = "Call windows API potential for activity on I/O create"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.exfiltration"
	strings:
		$api0 = "Createfile" nocase ascii wide
		$api1 = "CreatePipe" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_iocreatep {
	meta:
		description = "Call windows API potential for activity on I/O create named pipe"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.exfiltration"
	strings:
		$api0 = "CreateFileMapping" nocase ascii wide
		$api1 = "PeekNamedPipe" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_ioopen {
	meta:
		description = "Call windows API potential for activity on I/O open"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.collection"
	strings:
		$api0 = "OpenFile" nocase ascii wide
		$api1 = "OpenFileMapping" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_iowrite {
	meta:
		description = "Call windows API potential for activity on I/O write"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.exfiltration"
	strings:
		$api0 = "WriteFile" nocase ascii wide
		$api1 = "WriteConsole" nocase ascii wide
		$api2 = "WriteFileEx" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_comserv {
	meta:
		description = "Export windows API potential implements a COM server"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		ids = "win_api"
	    tag = "attack.exfiltration"
	strings:
		$api0 = "DllCanUnloadNow" nocase ascii wide
		$api1 = "DllGetClassObject" nocase ascii wide
		$api2 = "DllInstall" nocase ascii wide
		$api3 = "DllRegisterServer" nocase ascii wide
		$api4 = "DllUnregisterServer" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_ioread {
	meta:
		description = "Call windows API potential for activity on I/O read"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.collection"
	strings:
		$api0 = "ReadFile" nocase ascii wide
		$api1 = "ReadFileEx" nocase ascii wide
		$api2 = "ReadConsole" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_iofind {
	meta:
		description = "Call windows API potential for activity on I/O find (enum filesystem)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.collection"
	strings:
		$api0 = "FindFirstFile," nocase ascii wide
		$api1 = "FindNextFile" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_ioacces {
	meta:
		description = "Call windows API potential for activity on I/O acces"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "SetFileAttributes," nocase ascii wide
		$api1 = "SetConsoleMode" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_loadlib {
	meta:
		description = "Call windows API potential for activity load library"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api1 = "FreeLibrary" nocase ascii wide
		$api2 = "LoadLibrary" nocase ascii wide
		$api3 = "LoadLibraryEx" nocase ascii wide
		$api4 = "LoadPackagedLibrary" nocase ascii wide
		$api5 = "GetModuleHandle" nocase ascii wide
		$api6 = "LdrLoadDll" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_getinfo {
	meta:
		description = "Call windows API potential for activity get system info (antidebug/antianalysis)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf,https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "GetSystemDirectory" nocase ascii wide
		$api1 = "GetSystemTime" nocase ascii wide // time
		$api2 = "Gethostname" nocase ascii wide // local hostname
		$api3 = "GetSystemDefaultLangId" nocase ascii wide // lang windows setting
		$api4 = "GetVersionEx" nocase ascii wide // Windows is currently running
		$api5 = "IsWoW64Process" nocase ascii wide // check if 64b or 32b system
		$api6 = "GetCommandLine" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_logon {
	meta:
		description = "Call windows API potential for enum logon session"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.credential_access"
	strings:
		$api0 = "LsaEnumerateLogonSessions" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_mutex {
	meta:
		description = "Call windows API potential for activity mutex"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution"
	strings:
		$api0 = "CreateMutex" nocase ascii wide
		$api1 = "OpenMutex" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_dllimp {
	meta:
		description = "Call windows API potential for import function in a DLL"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.execution"
	strings:
		$api0 = "GetProcAddress" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_iodevice {
	meta:
		description = "Call windows API potential for activity IO Device (pass information between user space and kernel space)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.execution,attack.collection"
	strings:
		$api0 = "DeviceIoControl" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_temp {
	meta:
		description = "Call windows API potential for get global path (temp/windows)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 2
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.execution"
	strings:
		$api0 = "GetTempPath" nocase ascii wide
		$api1 = "GetWindowsDirectory" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_dep {
	meta:
		description = "Call windows API potential for activity change DEP protection"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref,https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.execution,attack.defense_evasion"
	strings:
		$api0 = "EnableExecuteProtectionSupport" nocase ascii wide
		$api1 = "NtSetInformationProcess" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_admin {
	meta:
		description = "Call windows API potential for check if current user has admin priv"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "IsNTAdmin" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_crypt {
	meta:
		description = "Call windows API potential for activity crypt function"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-1/#gref"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "CryptAcquireContext" nocase ascii wide
		$api1 = "EncryptMessage" nocase ascii wide
		$api2 = "DecryptMessage" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_callprocess {
	meta:
		description = "Call windows API potential for activity call process"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "http://www-users.math.umn.edu/~math-sa-sara0050/space16/slides/space2016121708-06.pdf"
		ids = "win_api"
	    tag = "attack.execution,attack.persistence,attack.t1053,attack.privilege_escalation"
	strings:
		$api0 = "WinExec" nocase ascii wide
		$api1 = "ShellExecute" nocase ascii wide
		$api2 = "CreateProcess" nocase ascii wide
		$api3 = "CallWindowProc" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_shedule {
	meta:
		description = "Call windows API potential for shedule task"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.execution"
	strings:
		$api0 = "NetScheduleJobAdd" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_share {
	meta:
		description = "Call windows API potential for enum network shares"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.discovery"
	strings:
		$api0 = "NetShareEnum" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_hidden {
	meta:
		description = "Potential hook NtQueryDirectoryFile for hidden file"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.discovery"
	strings:
		$api = "NtQueryDirectoryFile" nocase ascii wide 
		$hook = "SetWindowsHookEx" nocase ascii wide 
	condition:
	    check_winapi_bool and $api and $hook
}

rule win_api_mem {
	meta:
		description = "Call windows API potential for read in memory of another process"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.collection"
	strings:
		$api0 = "ReadProcessMemory" nocase ascii wide
		$api1 = "Toolhelp32ReadProcessMemory" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_filetime {
	meta:
		description = "Call windows API potential for change file time"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "SetFileTime" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_sam {
	meta:
		description = "Call windows API Security Account Manager (SAM)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.collection,attack.credential_access"
	strings:
		$api0 = "SamIConnect" nocase ascii wide
		$api1 = "SamIGetPrivateData" nocase ascii wide
		$api2 = "SamQueryInformationUse" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_hook {
	meta:
		description = "Call windows API Hook function"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.execution,attack.collection"
	strings:
		$api0 = "SetWindowsHookEx" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_wfp {
	meta:
		description = "Call windows API to desactive Windows File Protection (WFP)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "SfcTerminateWatcherThread" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_p_as_s {
	meta:
		description = "Call windows API to run process as service"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.defense_evasion,attack.execution"
	strings:
		$api0 = "StartServiceCtrlDispatcher" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}


rule win_api_u2a {
	meta:
		description = "Call windows API to unicode to ascii (obfuscate)"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://resources.infosecinstitute.com/windows-functions-in-malware-analysis-cheat-sheet-part-2/#article"
		ids = "win_api"
	    tag = "attack.defense_evasion"
	strings:
		$api0 = "WideCharToMultiByte" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}

rule win_api_ole {
	meta:
		description = "Call windows API to potential load OLE"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 3
		reference = "https://blog.malwarebytes.com/threat-analysis/2017/10/analyzing-malware-by-api-calls/"
		ids = "win_api"
	    tag = "attack.defense_evasion,attack.execution"
	strings:
		$api0 = "CreateStreamOnHGlobal" nocase ascii wide
		$api1 = "OleLoad" nocase ascii wide
	condition:
	    check_winapi_bool and any of ($api*)
}
