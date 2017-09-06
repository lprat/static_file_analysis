/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

/* 
  github.com/dfirnotes/rules
  Version 0.0.0
*/
import "math"
import "pe"

rule IsBeyondImageSize_PECheck
{
	meta: 
		author = "_pusher_"
		date = "2016-07"
		description = "Data Beyond ImageSize Check"
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		for any i in (0..pe.number_of_sections-1):
		( 
		(pe.sections[i].virtual_address+pe.sections[i].virtual_size) > (uint32(uint32(0x3C)+0x50)) or
		(pe.sections[i].raw_data_offset+pe.sections[i].raw_data_size) > filesize
		)
}

rule ImportTableIsBad_PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ImportTable Check"
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 		//Import_Table_RVA+Import_Data_Size .. cannot be outside imagesize
		((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))     > (uint32(uint32(0x3C)+0x50)) 
		or
		(((uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x84+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))  == 0x0)
		//or

		//doest work
		//pe.imports("", "")

		//need to check if this is ok.. 15:06 2016-08-12
		//uint32( uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+uint32(uint32(0x3C)+0x34)) == 0x408000
		//this works.. 
		//uint32(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+uint32(uint32(0x3C)+0x34) == 0x408000
		
		//uint32be(uint32be(0x409000)) == 0x005A
		//pe.image_base
		//correct:

		//uint32(uint32(0x3C)+0x80)+pe.image_base == 0x408000

		//this works (file offset):
		//$a0 at 0x4000
		//this does not work rva:
		//$a0 at uint32(0x0408000)

		//(uint32(uint32(uint32(0x3C)+0x80)+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))+pe.image_base) == 0x0)

		or
		//tiny PE files..
		(uint32(0x3C)+0x80+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) > filesize)

		//or
		//uint32(uint32(0x3C)+0x80) == 0x21000
   		//uint32(uint32(uint32(0x3C)+0x80)) == 0x0
		//pe.imports("", "")
		)				
}

rule ExportTableIsBad_PECheck
{
	meta: 
		author = "_pusher_ & mrexodia"
		date = "2016-07"
		description = "ExportTable Check"
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(IsPE32 or IsPE64) and
		( 		//Export_Table_RVA+Export_Data_Size .. cannot be outside imagesize
		((uint32(uint32(0x3C)+0x78+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) )) + (uint32(uint32(0x3C)+0x7C+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5))))     > (uint32(uint32(0x3C)+0x50)) 
		)		
}


rule HasModified_DOS_Message_PECheck
{
	meta: 
		author = "_pusher_"
		description = "DOS Message Check"
		date="2016-07"
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		weight = 1
	strings:	
		$a0 = "This program must be run under Win32" wide ascii nocase
		$a1 = "This program cannot be run in DOS mode" wide ascii nocase
		//UniLink
		$a2 = "This program requires Win32" wide ascii nocase
		$a3 = "This program must be run under Win64" wide ascii nocase
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and not
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule HasRichSignature_PECheck
{
	meta: 
		author = "_pusher_"
		description = "Rich Signature Check"
		date="2016-07"
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		weight = 1
	strings:	
		$a0 = "Rich" ascii
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}


rule IsPE32_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: 32b"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x010B
}

rule IsPE64_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: 64b"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x020B
}

rule IsNET_EXE_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: Net exe"
		weight = 1
	condition:
		pe.imports ("mscoree.dll","_CorExeMain")
}

rule IsNET_DLL_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: Net Dll"
		weight = 1
	condition:
		pe.imports ("mscoree.dll","_CorDllMain")
}

rule IsDLL_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: Dll"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000

}

rule IsConsole_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: Console"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0003
}

rule IsWindowsGUI_PECheck
{
	meta:
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		description = "Information Win PE: GUI"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0002
}

rule HasDebugData_PECheck
{
	meta: 
		author = "_pusher_"
		description = "DebugData Check"
		date="2016-07"
		reference = "https://github.com/Yara-Rules/rules/blob/d1da9c002d1d00045f53ea1502cfcc7dd43c115e/Packers/packer_compiler_signatures.yar"
		weight = 1
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//orginal
		//((uint32(uint32(0x3C)+0xA8) >0x0) and (uint32be(uint32(0x3C)+0xAC) >0x0))
		//((uint16(uint32(0x3C)+0x18) & 0x200) >> 5) x64/x32
		(IsPE32 or IsPE64) and
		((uint32(uint32(0x3C)+0xA8+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0) and (uint32be(uint32(0x3C)+0xAC+((uint16(uint32(0x3C)+0x18) & 0x200) >> 5)) >0x0))
}
rule Str_Win32_Winsock2_Library_PE
{

    meta:
        author = "@adricnet"
        description = "Match Winsock 2 API library declaration"
        method = "String match"
		weight = 4
    strings:
        $ws2_lib = "Ws2_32.dll" nocase
        $wsock2_lib = "WSock32.dll" nocase

    condition:
    (any of ($ws2_lib, $wsock2_lib))
}

rule Str_Win32_Wininet_Library_PE
{
    
    meta:
        author = "@adricnet"
        description = "Match Windows Inet API library declaration"
        method = "String match"
		weight = 4
    strings:
        $wininet_lib = "WININET.dll" nocase
    
    condition:
    (all of ($wininet*))
}

rule Str_Win32_Internet_API_PE
{
   
    meta:
        author = "@adricnet"
        description = "Match Windows Inet API call"
        method = "String match, trim the As"
		weight = 4
    strings:
        $wininet_call_closeh = "InternetCloseHandle"
        $wininet_call_readf = "InternetReadFile"
        $wininet_call_connect = "InternetConnect"
        $wininet_call_open = "InternetOpen"

    condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and (any of ($wininet_call*))
}

rule Str_Win32_Http_API_PE
{
    meta:
        author = "@adricnet"
        description = "Match Windows Http API call"
        method = "String match, trim the As"
		weight = 4
    strings:
        $wininet_call_httpr = "HttpSendRequest"
        $wininet_call_httpq = "HttpQueryInfo"
        $wininet_call_httpo = "HttpOpenRequest"
     condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and (any of ($wininet_call_http*))
}

rule Suspicious_Win32_API_PE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious Windows API call"
        reference = "https://github.com/SiamH/YaraRules/blob/master/Yara.py, https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    strings:
        $api_call_0 = /accept|AddCredentials|bind|CertDeleteCertificateFromStore|CheckRemoteDebuggerPresent|CloseHandle|closesocket|connect|ConnectNamedPipe|CopyFile|CreateFile|CreateProcess|CreateToolhelp32Snapshot|CreateFileMapping|CreateRemoteThread|CreateDirectory|CreateService|CreateThread|CryptEncrypt|DeleteFile|DeviceIoControl|DisconnectNamedPipe|DNSQuery|EnumProcesses|ExitProcess|ExitThread|FindWindow|FindResource|FindFirstFile|FindNextFile|FltRegisterFilter|FtpGetFile|FtpOpenFile|GetCommandLine|GetComputerName|GetCurrentProcess|GetThreadContext|GetDriveType|GetFileSize|GetFileAttributes|GetHostByAddr|GetHostByName|GetHostName|GetModuleHandle|GetModuleFileName|GetProcAddress|GetStartupInfo|GetSystemDirectory|GetTempFileName|GetTempPath|GetTickCount|GetUpdateRect|GetUpdateRgn|GetUserNameA|GetUrlCacheEntryInfo|GetVersionEx|GetWindowsDirectory|GetWindowThreadProcessId|HttpSendRequest|HttpQueryInfo|IcmpSendEcho|IsBadReadPtr|IsBadWritePtr|IsDebuggerPresent|InternetCloseHandle|InternetConnect|InternetCrackUrl|InternetQueryDataAvailable|InternetGetConnectedState|InternetOpen|InternetQueryDataAvailable|InternetQueryOption|InternetReadFile|InternetWriteFile|LdrLoadDll|LoadLibrary|LoadLibraryA|LockResource|listen|MapViewOfFile|OutputDebugString|OpenFileMapping|OpenProcess|Process32First|Process32Next|recv|ReadFile|RegCloseKey|RegCreateKey|RegDeleteKey|RegDeleteValue|RegEnumKey|RegOpenKey|ReadProcessMemory|send|sendto|SetFilePointer|SetKeyboardState|SetWindowsHook|ShellExecute|Sleep|socket|StartService|TerminateProcess|UnhandledExceptionFilter|URLDownload|VirtualAlloc|VirtualFree|VirtualProtect|VirtualAllocEx|WinExec|WriteProcessMemory|WriteFile|WSASend|WSASocket|WSAStartup|ZwQueryInformation/ 
        $api_call_1 = "OpenProcess" // "Opens a handle to another process running on the system. This handle can be used to read and write to the other process memory or to inject code into the other process.",
        $api_call_2 = "VirtualAllocEx" // "A memory-allocation routine that can allocate memory in a remote process. Malware sometimes uses VirtualAllocEx as part of process injection",
        $api_call_3 = "WriteProcessMemory" // "Used to write data to a remote process. Malware uses WriteProcessMemory as part of process injection.",
        $api_call_4 = "CreateRemoteThread" // "Used to start a thread in a remote process (one other than the calling process). Launchers and stealth malware use CreateRemoteThread to inject code into a different process.",
        $api_call_5 = "ReadProcessMemory" // "Used to read the memory of a remote process.",
        $api_call_6 = "CreateProcess" // "Creates and launches a new process. If malware creates a new process, you will need to analyze the new process as well.",
        $api_call_7 = "WinExec" // "Used to execute another program. If malware creates a new process, you will need to analyze the new process as well.",
        $api_call_8 = "ShellExecute" // "Used to execute another program. If malware creates a new process, you will need to analyze the new process as well.",
        $api_call_9 = "HttpSendRequest" // "Suggest that the PE file uses HTTP",
        $api_call_10 = "InternetReadFile" // "Reads data from a previously opened URL.",
        $api_call_11 = "InternetWriteFile" // "Writes data to a previously opened URL.",
        $api_call_12 = "InternetConnect" // "PE file uses to establish connection",
        $api_call_13 = "CreateService" // "Creates a service that can be started at boot time. Malware uses CreateService for persistence, stealth, or to load kernel drivers.",
        $api_call_14 = "StartService" // "Starting a service",
        $api_call_15 = "accept" // "Used to listen for incoming connections. This function indicates that the program will listen for incoming connections on a socket.",
        $api_call_16 = "AdjustTokenPrivileges" // "Used to enable or disable specific access privileges. Malware that performs process injection often calls this function to gain additional permissions.",
        $api_call_17 = "VirtualProtectEx" // "Changes the protection on a region of memory. Malware may use this function to change a read-only section of memory to an executable.",
        $api_call_18 = "SetWindowsHookEx" // "Sets a hook function to be called whenever a certain event is called. Commonly used with keyloggers and spyware, this function also provides an easy way to load a DLL into all GUI processes on the system. This function is sometimes added by the compiler.",
        $api_call_19 = "SfcTerminateWatcherThread" // "Used to disable Windows file protection and modify files that otherwise would be protected. SfcFileException can also be used in this capacity.",
        $api_call_20 = "FtpPutFile" // "A high-level function for uploading a file to a remote FTP server.",
        $api_call_21 = "EnumProcesses" // "Used to enumerate through running processes on the system. Malware often enumerates through processes to find a process to inject into.",
        $api_call_22 = "connect" // "Used to connect to a remote socket. Malware often uses low-level functionality to connect to a command-and-control server.",
        $api_call_23 = "GetAdaptersInfo" // "Used to obtain information about the network adapters on the system. Backdoors sometimes call GetAdaptersInfo as part of a survey to gather information about infected machines. In some cases, it’s used to gather MAC addresses to check for VMware as part of anti-virtual machine techniques.",
        $api_call_24 = "GetAsyncKeyState" // "Used to determine whether a particular key is being pressed. Malware sometimes uses this function to implement a keylogger.",
        $api_call_25 = "GetKeyState" // "Used by keyloggers to obtain the status of a particular key on the keyboard.",
        $api_call_26 = "InternetOpen" // "Initializes the high-level Internet access functions from WinINet, such as InternetOpenUrl and InternetReadFile . Searching for InternetOpen is a good way to find the start of Internet access functionality. One of the parameters to InternetOpen is the User-Agent, which can sometimes make a good network-based signature.",
        $api_call_27 = "AttachThreadInput" // "Attaches the input processing for one thread to another so that the second thread receives input events such as keyboard and mouse events. Keyloggers and other spyware use this function.",
        $api_call_28 = "BitBlt" // "Used to copy graphic data from one device to another. Spyware sometimes uses this function to capture screenshots. This function is often added by the compiler as part of library code.",
        $api_call_29 = "CallNextHookEx" // "Used within code that is hooking an event set by SetWindowsHookEx. CallNextHookEx calls the next hook in the chain. Analyze the function calling CallNextHookEx to determine the purpose of a hook set by SetWindowsHookEx.",
        $api_call_30 = "CertOpenSystemStore" // "Used to access the certificates stored on the local system.",
        $api_call_31 = "CheckRemoteDebuggerPresent" // "Checks to see if a specific process (including your own) is being debugged. This function is sometimes used as part of an anti-debugging technique.",
        $api_call_32 = "CoCreateInstance" // "Creates a COM object. COM objects provide a wide variety of functionality. The class identifier (CLSID) will tell you which file contains the code that implements the COM object. See Chapter 7 for an in-depth explanation of COM.",
        $api_call_33 = "ConnectNamedPipe" // "Used to create a server pipe for interprocess communication that will wait for a client pipe to connect. Backdoors and reverse shells sometimes use ConnectNamedPipe to simplify connectivity to a command-and-control server.",
        $api_call_34 = "ControlService" // "Used to start, stop, modify, or send a signal to a running service. If malware is using its own malicious service, you’ll need to analyze the code that implements the service in order to determine the purpose of the call.",
        $api_call_35 = "CreateFile" // "Creates a new file or opens an existing file.",
        $api_call_36 = "CreateFileMapping" // "Creates a handle to a file mapping that loads a file into memory and makes it accessible via memory addresses. Launchers, loaders, and injectors use this function to read and modify PE files.",
        $api_call_37 = "CreateMutex" // "Creates a mutual exclusion object that can be used by malware to ensure that only a single instance of the malware is running on a system at any given time. Malware often uses fixed names for mutexes, which can be good host-based indicators to detect additional installations of the malware.",
        $api_call_38 = "CreateToolhelp32Snapshot" // "Used to create a snapshot of processes, heaps, threads, and modules. Malware often uses this function as part of code that iterates through processes or threads.",
        $api_call_39 = "CryptAcquireContext" // "Often the first function used by malware to initialize the use of Windows encryption. There are many other functions associated with encryption, most of which start with Crypt.",
        $api_call_40 = "DeviceIoControl" // "Sends a control message from user space to a device driver. DeviceIoControl is popular with kernel malware because it is an easy, flexible way to pass information between user space and kernel space.",
        $api_call_41 = "DllCanUnloadNow" // "An exported function that indicates that the program implements a COM server.",
        $api_call_42 = "DllGetClassObject" // "An exported function that indicates that the program implements a COM server.",
        $api_call_43 = "DllInstall" // "An exported function that indicates that the program implements a COM server.",
        $api_call_44 = "DllRegisterServer" // "An exported function that indicates that the program implements a COM server.",
        $api_call_45 = "DllUnregisterServer" // "An exported function that indicates that the program implements a COM server.",
        $api_call_46 = "EnableExecuteProtectionSupport" // "An undocumented API function used to modify the Data Execution Protection (DEP) settings of the host, making it more susceptible to attack.",
        $api_call_47 = "EnumProcessModules" // "Used to enumerate the loaded modules (executables and DLLs) for a given process. Malware enumerates through modules when doing injection.",
        $api_call_48 = "FindFirstFile" // "Used to search through a directory and enumerate the filesystem."
        $api_call_48b = "FindNextFile" // "Used to search through a directory and enumerate the filesystem."
        $api_call_49 = "FindResource" // "Used to find a resource in an executable or loaded DLL. Malware some- times uses resources to store strings, configuration information, or other malicious files. If you see this function used, check for a .rsrc section in the malware’s PE header.",
        $api_call_50 = "GetDC" // "Returns a handle to a device context for a window or the whole screen. Spyware that takes screen captures often uses this function.",
        $api_call_51 = "GetForegroundWindow" // "Returns a handle to the window currently in the foreground of the desktop. Keyloggers commonly use this function to determine in which window the user is entering his keystrokes.",
        $api_call_52 = "gethostname" // "Retrieves the hostname of the computer. Backdoors sometimes use gethostname as part of a survey of the victim machine.",
        $api_call_53 = "gethostbyname" // "Used to perform a DNS lookup on a particular hostname prior to making an IP connection to a remote host. Hostnames that serve as command- and-control servers often make good network-based signatures.",
        $api_call_54 = "GetModuleFilename" // "Returns the filename of a module that is loaded in the current process. Malware can use this function to modify or copy files in the currently running process.",
        $api_call_55 = "GetModuleHandle" // "Used to obtain a handle to an already loaded module. Malware may use GetModuleHandle to locate and modify code in a loaded module or to search for a good location to inject code.",
        $api_call_56 = "GetProcAddress" // "Retrieves the address of a function in a DLL loaded into memory. Used to import functions from other DLLs in addition to the functions imported in the PE file header.",
        $api_call_57 = "GetStartupInfo" // "Retrieves a structure containing details about how the current process was configured to run, such as where the standard handles are directed.",
        $api_call_58 = "GetSystemDefaultLangId" // "Returns the default language settings for the system. This can be used to customize displays and filenames, as part of a survey of an infected victim, or by “patriotic” malware that affects only systems from certain regions.",
        $api_call_59 = "GetTempPath" // "Returns the temporary file path. If you see malware call this function, check whether it reads or writes any files in the temporary file path.",
        $api_call_60 = "GetThreadContext" // "Returns the context structure of a given thread. The context for a thread stores all the thread information, such as the register values and current state.",
        $api_call_61 = "GetTickCount" // "Retrieves the number of milliseconds since bootup. This function is sometimes used to gather timing information as an anti-debugging technique. GetTickCount is often added by the compiler and is included in many executables, so simply seeing it as an imported function provides little information.",
        $api_call_62 = "GetVersionEx" // "Returns information about which version of Windows is currently running. This can be used as part of a victim survey or to select between different offsets for undocumented structures that have changed between different versions of Windows.",
        $api_call_63 = "GetWindowsDirectory" // "Returns the file path to the Windows directory (usually C //\Windows). Malware sometimes uses this call to determine into which directory to install additional malicious programs.",
        $api_call_64 = "inet_addr" // "Converts an IP address string like 127.0.0.1 so that it can be used by func- tions such as connect . The string specified can sometimes be used as a network-based signature.",
        $api_call_65 = "InternetOpenUrl" // "Opens a specific URL for a connection using FTP, HTTP, or HTTPS. URLs, if fixed, can often be good network-based signatures.",
        $api_call_66 = "IsDebuggerPresent" // "Checks to see if the current process is being debugged, often as part oan anti-debugging technique. This function is often added by the compiler and is included in many executables, so simply seeing it as an imported function provides little information.",
        $api_call_67 = "IsNTAdmin" // "Checks if the user has administrator privileges.",
        $api_call_68 = "IsWoW64Process" // "Used by a 32-bit process to determine if it is running on a 64-bit operating system.",
        $api_call_69 = "LdrLoadDll" // "Low-level function to load a DLL into a process, just like LoadLibrary . Normal programs use LoadLibrary , and the presence of this import may indicate a program that is attempting to be stealthy.",
        $api_call_70 = "LoadLibrary" // "Loads a DLL into a process that may not have been loaded when the program started. Imported by nearly every Win32 program.",
        $api_call_71 = "LoadResource" // "Loads a resource from a PE file into memory. Malware sometimes uses resources to store strings, configuration information, or other malicious files",
        $api_call_72 = "LsaEnumerateLogonSessions" // "Enumerates through logon sessions on the current system, which can be used as part of a credential stealer.",
        $api_call_73 = "MapViewOfFile" // "Maps a file into memory and makes the contents of the file accessible via memory addresses. Launchers, loaders, and injectors use this function to read and modify PE files. By using MapViewOfFile , the malware can avoid using WriteFile to modify the contents of a file.",
        $api_call_74 = "MapVirtualKey" // "Translates a virtual-key code into a character value. It is often used by keylogging malware.",
        $api_call_75 = "MmGetSystemRoutineAddress" // "Similar to GetProcAddress but used by kernel code. This function retrieves the address of a function from another module, but it can only get addresses from ntoskrnl.exe and hal.dll.",
        $api_call_76 = "Module32First" // "Used to enumerate through modules loaded into a process. Injectors use this function to determine where to inject code.",
        $api_call_77 = "Module32Next" // "Used to enumerate through modules loaded into a process. Injectors use this function to determine where to inject code.",
        $api_call_78 = "NetScheduleJobAdd" // "Submits a request for a program to be run at a specified date and time. Malware can use NetScheduleJobAdd to run a different program. As a malware analyst, you’ll need to locate and analyze the program that will be run in the future.",
        $api_call_79 = "NetShareEnum" // "Used to enumerate network shares.",
        $api_call_80 = "NtQueryDirectoryFile" // "Returns information about files in a directory. Rootkits commonly hook this function in order to hide files.",
        $api_call_81 = "NtQueryInformationProcess" // "Returns various information about a specified process. This function is sometimes used as an anti-debugging technique because it can return the same information as CheckRemoteDebuggerPresent .",
        $api_call_82 = "NtSetInformationProcess" // "Can be used to change the privilege level of a program or to bypass Data Execution Prevention (DEP).",
        $api_call_83 = "OleInitialize" // "Used to initialize the COM library. Programs that use COM objects must call OleInitialize prior to calling any other COM functions.",
        $api_call_84 = "OpenMutex" // "Opens a handle to a mutual exclusion object that can be used by malware to ensure that only a single instance of malware is running on a system at any given time. Malware often uses fixed names for mutexes, which can be good host-based indicators.",
        $api_call_85 = "OpenSCManager" // "Opens a handle to the service control manager. Any program that installs, modifies, or controls a service must call this function before any other service-manipulation function.",
        $api_call_86 = "OutputDebugString" // "Outputs a string to a debugger if one is attached. This can be used as an anti-debugging technique.",
        $api_call_87 = "PeekNamedPipe" // "Used to copy data from a named pipe without removing data from the pipe. This function is popular with reverse shells.",
        $api_call_88 = "Process32First" // "Used to begin enumerating processes from a previous call to CreateToolhelp32Snapshot . Malware often enumerates through processes to find a process to inject into.",
        $api_call_89 = "Process32Next" // "Used to begin enumerating processes from a previous call to CreateToolhelp32Snapshot . Malware often enumerates through processes to find a process to inject into.",
        $api_call_90 = "QueryPerformanceCounter" // "Used to retrieve the value of the hardware-based performance counter. This function is sometimes using to gather timing information as part of an anti-debugging technique. It is often added by the compiler and is included in many executables, so simply seeing it as an imported function provides little information.",
        $api_call_91 = "QueueUserAPC" // "Used to execute code for a different thread. Malware sometimes uses QueueUserAPC to inject code into another process.",
        $api_call_92 = "recv" // "Receives data from a remote machine. Malware often uses this function to receive data from a remote command-and-control server.",
        $api_call_93 = "RegisterHotKey" // "Used to register a handler to be notified anytime a user enters a particular key combination (like CTRL - ALT -J), regardless of which window is active when the user presses the key combination. This function is some- times used by spyware that remains hidden from the user until the key combination is pressed.",
        $api_call_94 = "RegOpenKey" // "Opens a handle to a registry key for reading and editing. Registry keys are sometimes written as a way for software to achieve persistence on a host. The registry also contains a whole host of operating system and application setting information.",
        $api_call_95 = "ResumeThread" // "Resumes a previously suspended thread. ResumeThread is used as part of several injection techniques.",
        $api_call_96 = "RtlCreateRegistryKey" // "Used to create a registry from kernel-mode code.",
        $api_call_97 = "RtlWriteRegistryValue" // "Used to write a value to the registry from kernel-mode code.",
        $api_call_98 = "SamIConnect" // "Connects to the Security Account Manager (SAM) in order to make future calls that access credential information. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords.",
        $api_call_99 = "SamIGetPrivateData" // "Queries the private information about a specific user from the Security Account Manager (SAM) database. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords.",
        $api_call_100 = "SamQueryInformationUse" // "Queries information about a specific user in the Security Account Manager (SAM) database. Hash-dumping programs access the SAM database in order to retrieve the hash of users’ login passwords.",
        $api_call_101 = "send" // "Sends data to a remote machine. Malware often uses this function to send data to a remote command-and-control server.",
        $api_call_102 = "SetFileTime" // "Modifies the creation, access, or last modified time of a file. Malware often uses this function to conceal malicious activity.",
        $api_call_103 = "SetThreadContext" // "Used to modify the context of a given thread. Some injection techniques use SetThreadContext.",
        $api_call_104 = "StartServiceCtrlDispatcher" // "Used by a service to connect the main thread of the process to the service control manager. Any process that runs as a service must call this function within 30 seconds of startup. Locating this function in malware tells you that the function should be run as a service.",
        $api_call_105 = "SuspendThread" // "Suspends a thread so that it stops running. Malware will sometimes suspend a thread in order to modify it by performing code injection.",
        $api_call_106 = "system" // "Function to run another program provided by some C runtime libraries. On Windows, this function serves as a wrapper function to CreateProcess.",
        $api_call_107 = "Thread32First" // "Used to iterate through the threads of a process. Injectors use these functions to find an appropriate thread to inject into.",
        $api_call_108 = "Thread32Next" // "Used to iterate through the threads of a process. Injectors use these functions to find an appropriate thread to inject into.",
        $api_call_109 = "Toolhelp32ReadProcessMemory" // "Used to read the memory of a remote process.",
        $api_call_110 = "URLDownloadToFile" // "A high-level call to download a file from a web server and save it to disk. This function is popular with downloaders because it implements all the functionality of a downloader in one function call.",
        $api_call_111 = "WideCharToMultiByte" // "Used to convert a Unicode string into an ASCII string.",
        $api_call_112 = "Wow64DisableWow64FsRedirection" // "Disables file redirection that occurs in 32-bit files loaded on a 64-bit system. If a 32-bit application writes to C //\Windows\System32 after calling this function, then it will write to the real C //\Windows\System32 instead of being redirected to C //\Windows\SysWOW64.",
        $api_call_113 = "WSAStartup" // "Used to initialize low-level network functionality. Finding calls to WSAStartup can often be an easy way to locate the start of network-related functionality."
        $api_call_114 = "RtlDecompressBuffer"
        $api_call_115 = "EncryptMessage"
        $api_call_116 = "DecryptMessage"
     condition:
        (uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and (any of ($api_call_*))
}
rule Suspicious_Numbers_Section_API_PE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious number of section"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 6
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.number_of_sections < 2 or pe.number_of_sections > 8)
}

rule Suspicious_checksum_PE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious checksum PE"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.checksum == pe.calculate_checksum())
}

rule Suspicious_export_PE
{
    meta:
        author = "Lionel PRAT"
        description = "PE export function(s)"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.number_of_exports > 0)
}

rule Suspicious_Section_Name_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Match suspicious name in section PE"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		for any j in (0..pe.number_of_sections - 1): (not pe.sections[j].name matches /\.data|\.text|\.code|\.reloc|\.idata|\.edata|\.rdata|\.bss|\.rsrc/)
}

rule Suspicious_Section_size_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Suspicious rawdata length 0 and virtual size > 0 in section PE"
        reference = "https://github.com/secrary/SSMA/blob/master/src/check_file.py"
        version = "0.1"
		weight = 5
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		for any j in (0..pe.number_of_sections - 1): (pe.sections[j].raw_data_size == 0 and pe.sections[j].virtual_size > 0)
}

rule Suspicious_date_compilation_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Suspicious date compilation 7 day before now"
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		(pe.timestamp > now_7_int)
}

rule  Suspicious_dateRes_compilation_winPE
{
    meta:
        reference = "http://malbabble.blogspot.com/2015/08/pe-time-stamps-and-yara.html"
        description = "Suspicious date compilation"
		weight = 4
	condition:
		pe.resource_timestamp != 0 and
		pe.resource_timestamp < pe.timestamp
}
			
rule Entropy_Packed_Win_PE
{
	meta: 
		description = "Very high or very low entropy means that file is compressed or encrypted since truly random data is not common"
		weight = 6
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(math.entropy(0, filesize) >= 7.0 or math.entropy(0, filesize) <= 1)
}

rule Entropy_Section_Win_PE
{
	meta: 
	    reference = "https://github.com/DFIRnotes/rules/blob/master/pe_upx.yara"
		description = "Very high or very low entropy means that section is compressed or encrypted since truly random data is not common"
		weight = 5
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		for any j in (0..pe.number_of_sections - 1): (
			math.entropy(pe.sections[j].raw_data_offset, pe.sections[j].raw_data_size) >= 6
		)
}

rule Notcontains_InternalOrOriginal_Name_winPE
{
    meta:
        author = "Lionel PRAT"
        description = "Pe not conatins internalname or originalfilename" // NOT WORK! if version_info not exist, the pe.version_info don't put boolean response
        version = "0.1"
		weight = 4
    condition:
		(uint16(0) == 0x5A4D or FileType matches /CL_TYPE_AUTOIT|CL_TYPE_MSCAB|CL_TYPE_MSEXE|CL_TYPE_MS-EXE|CL_TYPE_MS-DLL/) and 
		((not pe.version_info["InternalName"] matches /\S+/) or (not pe.version_info["OriginalFilename"] matches /\S+/))
}
