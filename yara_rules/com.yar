//https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf
//https://github.com/cuckoosandbox/cuckoo/blob/master/cuckoo/private/guids.txt
//https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py
//https://support.microsoft.com/en-hk/help/4032364/how-to-control-the-blocking-of-ole-com-components-in-microsoft-office
//http://www.nirsoft.net/utils/axhelper.html

rule COM_obj_HHCtrl {
	meta:
		description = "COM obj HHCtrl call for potential execute arbitrary code"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1223"
	strings:
		$clsid0 = "ADB880A6-D8FF-11CF-9377-00AA003B7A11" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MMC {
	meta:
		description = "COM obj MMC Plugable Internet Protocol call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1189"
	strings:
		$clsid0 = "B0395DA5-6A15-4E44-9F36-9A9DC7A2F341" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_WMDMCESP {
	meta:
		description = "COM obj WMDMCESP"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf"
	    tag = "attack.execution,attack.t1189"
	strings:
		$clsid0 = "067B4B81-B1EC-489f-B111-940EBDC44EBE" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MsComCtl {
	meta:
		description = "COM obj MsComCtl call for potential exploit CVE-2012-1856"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
	    tag = "attack.execution,attack.t1189"
	strings:
		$clsid0 = "1EFB6596-857C-11D1-B16A-00C0F0283628" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_EmptyField {
	meta:
		description = "COM obj EmptyField"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/system.guid.empty.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000000-0000-0000-0000-000000000000" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IUnknown {
	meta:
		description = "COM obj IID_IUnknown"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/ms680509.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000000-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IClassFactory {
	meta:
		description = "COM obj IClassFactory"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iclassfactory.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000001-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IMarshal {
	meta:
		description = "COM obj IID_IMarshal"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/dd542707.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000003-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IPersistStream {
	meta:
		description = "COM obj IPersistStream"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.ipersiststream.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000109-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IPersistFile {
	meta:
		description = "COM obj IPersistFile"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/system.runtime.interopservices.comtypes.ipersistfile.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "0000010b-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IOleObject {
	meta:
		description = "COM obj IOleObject"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.ioleobject.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000112-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IParseDisplayName {
	meta:
		description = "COM obj IParseDisplayName"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iparsedisplayname.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "0000011a-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IGlobalInterfaceTable {
	meta:
		description = "COM obj IID_IGlobalInterfaceTable"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/nl-nl/ms679756"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000146-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLEStream {
	meta:
		description = "COM obj OLEStream"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ee379697.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000303-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ItemMoniker {
	meta:
		description = "COM obj ItemMoniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://doxygen.reactos.org/d4/dfd/ole32__objidl_8idl_source.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000304-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IGlobalInterfaceTable {
	meta:
		description = "COM obj IGlobalInterfaceTable"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://doxygen.reactos.org/d4/dfd/ole32__objidl_8idl_source.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000323-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_ActivationPropertiesIn {
	meta:
		description = "COM obj CLSID_ActivationPropertiesIn"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc226820.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000338-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_ActivationPropertiesOut {
	meta:
		description = "COM obj CLSID_ActivationPropertiesOut"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc226820.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000339-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID {
	meta:
		description = "COM obj CLSID"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://support.microsoft.com/en-us/kb/288706"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000542-0000-0010-8000-00aa006d2ea4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ADODB_Stream {
	meta:
		description = "COM obj ADODB.Stream"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://support.microsoft.com/en-us/kb/870669"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000566-0000-0010-8000-00aa006d2ea4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_PSDispatch {
	meta:
		description = "COM obj PSDispatch"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.mazecomputer.com/sxs/help/proxy.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020420-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_ShellLink {
	meta:
		description = "COM obj CLSID_ShellLink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://stackoverflow.com/questions/14712408/jna-cocreateinstance"
		tag = "attack.execution"
	strings:
		$clsid0 = "00021401-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellFolder {
	meta:
		description = "COM obj IShellFolder"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://pinvoke.net/default.aspx/Interfaces/IShellFolder.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "000214e6-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellLinkA {
	meta:
		description = "COM obj IShellLinkA"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "000214ee-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellLinkW {
	meta:
		description = "COM obj IShellLinkW"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "000214f9-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IQueryInfo {
	meta:
		description = "COM obj IQueryInfo"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "00021500-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_InprocServer32 {
	meta:
		description = "COM obj InprocServer32"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://computer-programming-forum.com/16-visual-basic/364d93d0f6ee4195.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "0002e005-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_ICatInformation {
	meta:
		description = "COM obj IID_ICatInformation"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://technet.microsoft.com/nl-nl/ms686642"
		tag = "attack.execution"
	strings:
		$clsid0 = "0002e013-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AppID {
	meta:
		description = "COM obj AppID"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://kb4sp.wordpress.com/2011/06/30/fixing-the-dcom-error-the-application-specific-permission-settings-do-not-grant-local-activation-permission-for-the-com-server-application-with-clsid/"
		tag = "attack.execution"
	strings:
		$clsid0 = "000c101c-0000-0000-c000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_AutoComplete {
	meta:
		description = "COM obj Microsoft_AutoComplete"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-00bb2763-6a77-11d0-a535-00c04fd7d062"
		tag = "attack.execution"
	strings:
		$clsid0 = "00bb2763-6a77-11d0-a535-00c04fd7d062" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_History_AutoComplete_List {
	meta:
		description = "COM obj Microsoft_History_AutoComplete_List"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-00bb2764-6a77-11d0-a535-00c04fd7d062"
		tag = "attack.execution"
	strings:
		$clsid0 = "00bb2765-6a77-11d0-a535-00c04fd7d062" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWinHttpRequest {
	meta:
		description = "COM obj IWinHttpRequest"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-interface-016fe2ec-b2c8-45f8-b23b-39e53a75396b"
		tag = "attack.execution"
	strings:
		$clsid0 = "016fe2ec-b2c8-45f8-b23b-39e53a75396b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Address {
	meta:
		description = "COM obj &Address"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/CLSID/256-browseui_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "01e04581-4eee-11d0-bfe9-00aa005b4383" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AMtoolbar {
	meta:
		description = "COM obj AMtoolbar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.checkfilename.com/view-details/Jukebox-Pro/RespageIndex/0/sTab/2/"
		tag = "attack.execution"
	strings:
		$clsid0 = "0368bff0-9870-11d0-94ab-0080c74c7e95" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ISearchRoot {
	meta:
		description = "COM obj ISearchRoot"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://sourceforge.net/p/jedi-apilib/mailman/jedi-apilib-wscl-svn/?viewmonth=200902&viewday=11"
		tag = "attack.execution"
	strings:
		$clsid0 = "04c18ccf-1f57-4cbd-88cc-3900f5195ce3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_Setup_exe {
	meta:
		description = "COM obj GFN_Setup.exe"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/SETUP/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "04d3d264-4a22-11d2-acc7-00c04f8eeba1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AllowedControls {
	meta:
		description = "COM obj AllowedControls"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://technet.microsoft.com/nl-nl/library/Cc786827(v=WS.10).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "05589fa1-c356-11ce-bf01-00aa0055595a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Scriptlet_Constructor {
	meta:
		description = "COM obj Scriptlet.Constructor"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-06290bd1-48aa-11d2-8432-006008c3fbfc"
		tag = "attack.execution"
	strings:
		$clsid0 = "06290bd1-48aa-11d2-8432-006008c3fbfc" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ActiveXVulnerability {
	meta:
		description = "COM obj ActiveXVulnerability"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.securityfocus.com/bid/598/exploit"
		tag = "attack.execution"
	strings:
		$clsid0 = "06290bd5-48aa-11d2-8432-006008c3fbfc" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellFolder2_QueryInterface_Unimplemented_interface {
	meta:
		description = "COM obj IShellFolder2_QueryInterface_Unimplemented_interface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://www.winehq.org/pipermail/wine-users/2010-May/072093.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "062e1261-a60e-11d0-82c2-00c04fd5ae38" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AcroIEHlprObj {
	meta:
		description = "COM obj AcroIEHlprObj"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/CLSID/32558-AcroIEhelper_ocx_ACROIE_1_DLL_AcroIEhelper_dll_ACROIE_1_OCX.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "06849e9f-c8d7-4d59-b87d-784b7d6be0b3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_URL_Shortcut_PropSetStorage_Mapping {
	meta:
		description = "COM obj URL_Shortcut_PropSetStorage_Mapping"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://tredosoft.com/files/IE7s/newIE7.reg"
		tag = "attack.execution"
	strings:
		$clsid0 = "06eee834-461c-42c2-8dcf-1502b527b1f9" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Homegroup_Network {
	meta:
		description = "COM obj Homegroup_Network"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-0700f42f-eee3-443a-9899-166f16286796"
		tag = "attack.execution"
	strings:
		$clsid0 = "0700f42f-eee3-443a-9899-166f16286796" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CActiveIMM_Create {
	meta:
		description = "COM obj CActiveIMM_Create"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ubuntuforums.org/archive/index.php/t-869952.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "08c0e040-62d1-11d1-9326-0060b067b86e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_StdFont {
	meta:
		description = "COM obj StdFont"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://social.msdn.microsoft.com/Forums/vstudio/en-US/f7c9d4d2-dbfa-44bd-a804-9f2fa1d27093/vs6-to-vs2010-font"
		tag = "attack.execution"
	strings:
		$clsid0 = "0be35203-8f91-11ce-9de3-00aa004bb851" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_StdPict {
	meta:
		description = "COM obj CLSID_StdPict"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/O16/2069-OPW_25900_cab.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "0be35204-8f91-11ce-9de3-00aa004bb851" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellIconOverlayIdentifier {
	meta:
		description = "COM obj IShellIconOverlayIdentifier"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/dwmkerr/sharpshell/blob/master/SharpShell/SharpShell/Interop/IShellIconOverlayIdentifier.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "0c6c4200-c589-11d0-999a-00c04fd655e1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IErrorLookup {
	meta:
		description = "COM obj IID_IErrorLookup"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://sourceforge.net/p/zeoslib/code-0/3534/tree//branches/testing-7.3/src/plain/ZOleDB.pas?barediff=500986a671b75b2b8b001f0f:3533"
		tag = "attack.execution"
	strings:
		$clsid0 = "0c733a66-2a1c-11ce-ade5-00aa0044773d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_FileSystemObject {
	meta:
		description = "COM obj FileSystemObject"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-0d43fe01-f093-11cf-8940-00a0c9054228"
		tag = "attack.execution"
	strings:
		$clsid0 = "0d43fe01-f093-11cf-8940-00a0c9054228" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Links {
	meta:
		description = "COM obj &Links"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/CLSID/72019-browseui_dll_shell32_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "0e5cbf21-d15f-11d0-8301-00aa005b4383" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DXSurface {
	meta:
		description = "COM obj DXSurface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-0e890f83-5f79-11d1-9043-00c04fd9189d"
		tag = "attack.execution"
	strings:
		$clsid0 = "0e890f83-5f79-11d1-9043-00c04fd9189d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_gencomp29 {
	meta:
		description = "COM obj gencomp29"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://uni-smr.ac.ru/archive/dev/cc++/ms/vs2010_en/VCExpress/vs_setup.pdi"
		tag = "attack.execution"
	strings:
		$clsid0 = "12cda52c-7a8f-4785-8a22-53c87393fee0" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shell {
	meta:
		description = "COM obj Shell"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/bb776890(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "13709620-c279-11ce-a49e-444553540000" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_winmgmts {
	meta:
		description = "COM obj winmgmts"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://technet.microsoft.com/en-us/library/ee198932.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "172bddf8-ceea-11d1-8b05-00600806d9b6" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UBoxProSetup_exe {
	meta:
		description = "COM obj UBoxProSetup.exe"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://malwr.com/analysis/YjRmZmVkMGI5MDYwNDM0NDkwOWM2YjYwYzNhNmM5Mjc/"
		tag = "attack.execution"
	strings:
		$clsid0 = "18789660-1317-11d3-a4ec-00c04f5e0ba5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_TROJ_AGENT_0000176_TOMA {
	meta:
		description = "COM obj TROJ_AGENT_0000176.TOMA"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/troj_agent_0000176.toma"
		tag = "attack.execution"
	strings:
		$clsid0 = "18df081c-e8ad-4283-a596-fa578c2ebdc3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_COMPage {
	meta:
		description = "COM obj COMPage"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://social.msdn.microsoft.com/Forums/en-US/6ae7127f-95e1-44d0-af7a-3d086fcbe42f/unexpected-reboots-in-admin-setup-of-vs2005-team-edition-for-sw-developers?forum=vssetup"
		tag = "attack.execution"
	strings:
		$clsid0 = "1920cc5d-5be5-45d4-9c1c-3513d334c71c" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IErrorInfo {
	meta:
		description = "COM obj IErrorInfo"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/phuslu/pyMSAA/blob/master/comtypes/errorinfo.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "1cf2b120-547d-101b-8e65-08002b2bd119" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Memory_Mapped_Cache_Mgr {
	meta:
		description = "COM obj Memory_Mapped_Cache_Mgr"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-1f486a52-3cb1-48fd-8f50-b8dc300d9f9d"
		tag = "attack.execution"
	strings:
		$clsid0 = "1f486a52-3cb1-48fd-8f50-b8dc300d9f9d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_WinHttpRequest {
	meta:
		description = "COM obj WinHttpRequest"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-2087c2f4-2cef-4953-a8ab-66779b670495"
		tag = "attack.execution"
	strings:
		$clsid0 = "2087c2f4-2cef-4953-a8ab-66779b670495" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IErrorInfo2 {
	meta:
		description = "COM obj IErrorInfo"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		tag = "attack.execution"
	strings:
		$clsid0 = "22b07b33-8bfb-49d4-9b90-0938370c9019" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CD_Info_Manager {
	meta:
		description = "COM obj CD_Info_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "24a501ba-90a1-11d2-af05-00c04f797fb8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_HTML_Document {
	meta:
		description = "COM obj HTML_Document"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://blogs.msdn.com/b/askie/archive/2012/09/12/how-to-determine-the-clsid-of-an-activex-control.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "25336920-03f9-11cf-8fd0-00aa00686f13" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDXTaskManager_Interface {
	meta:
		description = "COM obj IDXTaskManager_Interface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/DShowIDL/dxtrans.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "254dbbc1-f922-11d0-883a-3c8b00c10000" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IMultiLanguage {
	meta:
		description = "COM obj IMultiLanguage"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://code.google.com/p/subtitleedit/source/browse/trunk/src/Logic/DetectEncoding/Multilang/IMultiLanguage.cs?r=17"
		tag = "attack.execution"
	strings:
		$clsid0 = "275c23e1-3747-11d0-9fea-00aa003f8646" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Multi_Language_Support {
	meta:
		description = "COM obj Multi_Language_Support"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-275c23e2-3747-11d0-9fea-00aa003f8646"
		tag = "attack.execution"
	strings:
		$clsid0 = "275c23e2-3747-11d0-9fea-00aa003f8646" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IXMLDOMDocument {
	meta:
		description = "COM obj IXMLDOMDocument"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.office.interop.infopath.semitrust.ixmldomdocument.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "2933bf81-7b36-11d2-b20e-00c04f983e60" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IXMLDOMDocument2 {
	meta:
		description = "COM obj IXMLDOMDocument2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-interface-2933bf95-7b36-11d2-b20e-00c04f983e60"
		tag = "attack.execution"
	strings:
		$clsid0 = "2933bf95-7b36-11d2-b20e-00c04f983e60" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_HNetCfg_FwMgr {
	meta:
		description = "COM obj HNetCfg.FwMgr"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-304ce942-6e39-40d8-943a-b913c40c9cd4"
		tag = "attack.execution"
	strings:
		$clsid0 = "304ce942-6e39-40d8-943a-b913c40c9cd4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_HTML_About_Pluggable_Protocol {
	meta:
		description = "COM obj Microsoft_HTML_About_Pluggable_Protocol"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3050f406-98b5-11cf-bb82-00aa00bdce0b"
		tag = "attack.execution"
	strings:
		$clsid0 = "3050f406-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ElementBehaviorFactory {
	meta:
		description = "COM obj ElementBehaviorFactory"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/lutzroeder/Writer/blob/master/Source/Html/NativeMethods.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "3050f429-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_PeerFactory_Class {
	meta:
		description = "COM obj PeerFactory_Class"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3050f4cf-98b5-11cf-bb82-00aa00bdce0b"
		tag = "attack.execution"
	strings:
		$clsid0 = "3050f4cf-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Trident_HTMLEditor {
	meta:
		description = "COM obj Trident_HTMLEditor"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3050f4f5-98b5-11cf-bb82-00aa00bdce0b"
		tag = "attack.execution"
	strings:
		$clsid0 = "3050f4f5-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IHTMLEditor {
	meta:
		description = "COM obj IHTMLEditor"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		tag = "attack.execution"
	strings:
		$clsid0 = "3050f7fa-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ISearchRoot2 {
	meta:
		description = "COM obj ISearchRoot"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/searchapi.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "30766bd2-ea1c-4f28-bf27-0b44e2f68db7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDXTransform_Interface {
	meta:
		description = "COM obj IDXTransform_Interface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/DShowIDL/dxtrans.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "30a5fb78-e11f-11d1-9064-00c04fd9189d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CoMapMIMEToCLSID_Class {
	meta:
		description = "COM obj CoMapMIMEToCLSID_Class"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-30c3b080-30fb-11d0-b724-00aa006c1a01"
		tag = "attack.execution"
	strings:
		$clsid0 = "30c3b080-30fb-11d0-b724-00aa006c1a01" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_SysTray {
	meta:
		description = "COM obj SysTray"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/CLSID/61109-stobject_dll_dllwsco_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "35cec8a3-2be6-11d2-8773-92e220524153" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DXTFilter {
	meta:
		description = "COM obj DXTFilter"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-385a91bc-1e8a-4e4a-a7a6-f4fc1e6ca1bd"
		tag = "attack.execution"
	strings:
		$clsid0 = "385a91bc-1e8a-4e4a-a7a6-f4fc1e6ca1bd" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemPath {
	meta:
		description = "COM obj IWbemPath"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/angelcolmenares/pash/blob/master/External/System.Management/System.Management/IWbemPath.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "3bc15af2-736c-477e-9e51-238af8667dcc" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_Url_History_Service {
	meta:
		description = "COM obj Microsoft_Url_History_Service"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3c374a40-bae4-11cf-bf7d-00aa006946ee"
		tag = "attack.execution"
	strings:
		$clsid0 = "3c374a40-bae4-11cf-bf7d-00aa006946ee" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IUrlHistoryStg {
	meta:
		description = "COM obj IUrlHistoryStg"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.experts-exchange.com/Programming/Languages/Pascal/Delphi/Q_22520713.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "3c374a41-bae4-11cf-bf7d-00aa006946ee" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shell_Extensions_for_Sharing {
	meta:
		description = "COM obj Shell_Extensions_for_Sharing"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-40dd6e20-7c17-11ce-a804-00aa003ca9f6"
		tag = "attack.execution"
	strings:
		$clsid0 = "40dd6e20-7c17-11ce-a804-00aa003ca9f6" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IconHandler {
	meta:
		description = "COM obj IconHandler"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowssecrets.com/forums/showthread.php/135115-Icons-for-Firefox-missing-in-Windows-Explorer"
		tag = "attack.execution"
	strings:
		$clsid0 = "42042206-2d85-11d3-8cff-005004838597" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MruPidlList {
	meta:
		description = "COM obj MruPidlList"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://nakedsecurity.sophos.com/2012/06/06/zeroaccess-rootkit-usermode/"
		tag = "attack.execution"
	strings:
		$clsid0 = "42aedc87-2188-41fd-b9a3-0c966feabec1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Browseui_Preloader {
	meta:
		description = "COM obj Browseui_Preloader"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/O22/68-SYSDIR_browseui_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "438755c2-a8ba-11d1-b96b-00a0c90312e1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemContext {
	meta:
		description = "COM obj IWbemContext"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc250946.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "44aca674-e8fc-11d0-a07c-00c04fb68820" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Urlmon {
	meta:
		description = "COM obj Urlmon"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://whiteboard.nektra.com/internet-explorer-7-favorites-doesn-t-work-classfactory-cannot-supply-requested-class"
		tag = "attack.execution"
	strings:
		$clsid0 = "4516cee1-97da-4030-a444-2d8e296b96b6" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_WbemLocator {
	meta:
		description = "COM obj CLSID_WbemLocator"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://forums.winamp.com/showthread.php?t=309949"
		tag = "attack.execution"
	strings:
		$clsid0 = "4590f811-1d3a-11d0-891f-00aa004b2e24" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemClassObject {
	meta:
		description = "COM obj IWbemClassObject"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc250726.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "4590f812-1d3a-11d0-891f-00aa004b2e24" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemClassObject2 {
	meta:
		description = "COM obj IWbemClassObject"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc250726.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "4590f812-1d3a-11d0-891f-00aa004b2e24" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_NumMethods {
	meta:
		description = "COM obj NumMethods"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.fixdllfile.com/Dutch/fvevol.sys.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "465a756d-45ad-4305-85fd-d3321650f3b7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IApplicationResolver {
	meta:
		description = "COM obj IApplicationResolver"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://a-whiter.livejournal.com/1266.html?thread=1522"
		tag = "attack.execution"
	strings:
		$clsid0 = "46a6eeff-908e-4dc6-92a6-64be9177b41c" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_Forms_2_0_MultiPage {
	meta:
		description = "COM obj Microsoft_Forms_2.0_MultiPage"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://www.wikispaces.com/file/view/cc_20100727_220557.reg"
		tag = "attack.execution"
	strings:
		$clsid0 = "46e31370-3f7a-11ce-bed6-00aa00611080" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_InterfaceID {
	meta:
		description = "COM obj InterfaceID"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/arank/cs181-practical2/blob/master/train/1e1cc235291c576f6e5f480fcfd444Ad7671b338d.None.xml"
		tag = "attack.execution"
	strings:
		$clsid0 = "47851649-a2ef-4e67-baec-c6a153ac72ec" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CoGetClassObject {
	meta:
		description = "COM obj CoGetClassObject"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://appdb.winehq.org/objectManager.php?sClass=version&iId=5826&iTestingId=15991"
		tag = "attack.execution"
	strings:
		$clsid0 = "4955dd33-b159-11d0-8fcf-00aa006bcc59" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DatabaseSession {
	meta:
		description = "COM obj CLSID_DatabaseSession"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-4a16043f-676d-11d2-994e-00c04fa309d4"
		tag = "attack.execution"
	strings:
		$clsid0 = "4a16043f-676d-11d2-994e-00c04fa309d4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IDatabaseSession {
	meta:
		description = "COM obj IID_IDatabaseSession"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/bb931215(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "4a160440-676d-11d2-994e-00c04fa309d4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DXTaskManager {
	meta:
		description = "COM obj DXTaskManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-4cb26c03-ff93-11d0-817e-0000f87557db"
		tag = "attack.execution"
	strings:
		$clsid0 = "4cb26c03-ff93-11d0-817e-0000f87557db" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IMXWriter {
	meta:
		description = "COM obj IMXWriter"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://read.pudn.com/downloads3/sourcecode/windows/6437/soap/Samples/Echo/Service/Rpc/CppSrv/ReleaseUMinDependency/msxml3.tlh__.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "4d7ff4ba-1565-4ea8-94e1-6e724a46f98d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ISniffStream {
	meta:
		description = "COM obj ISniffStream"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.icpdas.com/pub/beta_version/VHM/wince600/at91sam9g45m10ek_armv4i/cesysgen/sdk/inc/imgutil.h"
		tag = "attack.execution"
	strings:
		$clsid0 = "4ef17940-30e0-11d0-b724-00aa006c1a01" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DirectDrawEx_Object {
	meta:
		description = "COM obj DirectDrawEx_Object"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.uma.es/Drivers/TVIDEO/ATI/128RAGE/WIN9X/DIRECTX6/DIRECTX/DDRAW.INF"
		tag = "attack.execution"
	strings:
		$clsid0 = "4fd2a832-86c8-11d0-8fca-00c04fd9189d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDirectDrawFactory {
	meta:
		description = "COM obj IDirectDrawFactory"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://users.jyu.fi/~vesal/kurssit/winohj/htyot/h00/panniva/DAnim.pas"
		tag = "attack.execution"
	strings:
		$clsid0 = "4fd2a833-86c8-11d0-8fca-00c04fd9189d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CActiveIMMAppEx_Trident {
	meta:
		description = "COM obj CActiveIMMAppEx_Trident"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-50d5107a-d278-4871-8989-f4ceaaf59cfc"
		tag = "attack.execution"
	strings:
		$clsid0 = "50d5107a-d278-4871-8989-f4ceaaf59cfc" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IXMLDOMSchemaCollection2 {
	meta:
		description = "COM obj IXMLDOMSchemaCollection2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-interface-50ea08b0-dd1b-4664-9a50-c2f40f4bd79a"
		tag = "attack.execution"
	strings:
		$clsid0 = "50ea08b0-dd1b-4664-9a50-c2f40f4bd79a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Welcome_Page {
	meta:
		description = "COM obj Welcome_Page"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://uni-smr.ac.ru/archive/dev/cc++/ms/vs2010_en/VCExpress/setup.sdb"
		tag = "attack.execution"
	strings:
		$clsid0 = "52d42507-0e98-463a-83de-1fee13073ecc" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MruLongList {
	meta:
		description = "COM obj MruLongList"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-53bd6b4e-3780-4693-afc3-7161c2f3ee9c"
		tag = "attack.execution"
	strings:
		$clsid0 = "53bd6b4e-3780-4693-afc3-7161c2f3ee9c" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Language_Bar {
	meta:
		description = "COM obj Language_Bar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-540d8a8b-1c3f-4e32-8132-530f6a502090"
		tag = "attack.execution"
	strings:
		$clsid0 = "540d8a8b-1c3f-4e32-8132-530f6a502090" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IReferenceClock {
	meta:
		description = "COM obj IReferenceClock"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://users.jyu.fi/~vesal/kurssit/winohj/htyot/h00/panniva/DShow.pas"
		tag = "attack.execution"
	strings:
		$clsid0 = "56a86897-0ad4-11ce-b03a-0020af0ba770" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IGraphBuilder {
	meta:
		description = "COM obj IID_IGraphBuilder"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://rapidq.phatcode.net/examples/video/DirectShow_test.bas"
		tag = "attack.execution"
	strings:
		$clsid0 = "56a868a9-0ad4-11ce-b03a-0020af0ba770" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Task_Bar_Communication {
	meta:
		description = "COM obj Task_Bar_Communication"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-56fdf344-fd6d-11d0-958a-006097c9a090"
		tag = "attack.execution"
	strings:
		$clsid0 = "56fdf344-fd6d-11d0-958a-006097c9a090" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_REFIID {
	meta:
		description = "COM obj REFIID"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://q.cnblogs.com/q/55896/"
		tag = "attack.execution"
	strings:
		$clsid0 = "5762f2a7-4658-4c7a-a4ac-bdabfe154e0d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Menu_Band {
	meta:
		description = "COM obj Menu_Band"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-5b4dae26-b807-11d0-9815-00c04fd91972"
		tag = "attack.execution"
	strings:
		$clsid0 = "5b4dae26-b807-11d0-9815-00c04fd91972" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWiaDevMgr {
	meta:
		description = "COM obj IWiaDevMgr"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/tigersoldier/wine/blob/master/include/wia_lh.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "5eb2502a-8cf1-11d1-bf92-0060081ed811" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_Disk_Info_Manager {
	meta:
		description = "COM obj GFN_Disk_Info_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/SETUP/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "5f2c847d-96a6-11d2-af0a-00c04f797fb8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shared_Task_Scheduler {
	meta:
		description = "COM obj Shared_Task_Scheduler"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-603d3801-bd81-11d0-a3a5-00c04fd706ec"
		tag = "attack.execution"
	strings:
		$clsid0 = "603d3801-bd81-11d0-a3a5-00c04fd706ec" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDXTFilter {
	meta:
		description = "COM obj IDXTFilter"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		tag = "attack.execution"
	strings:
		$clsid0 = "6187e5a2-a445-4608-8fc0-be7a6c8db386" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Gradient {
	meta:
		description = "COM obj Gradient"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-623e2882-fc0e-11d1-9a77-0000f8756a10"
		tag = "attack.execution"
	strings:
		$clsid0 = "623e2882-fc0e-11d1-9a77-0000f8756a10" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Start_Menu_Cache {
	meta:
		description = "COM obj Start_Menu_Cache"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-660b90c8-73a9-4b58-8cae-355b7f55341b"
		tag = "attack.execution"
	strings:
		$clsid0 = "660b90c8-73a9-4b58-8cae-355b7f55341b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_Toolbar {
	meta:
		description = "COM obj CLSID_Toolbar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://dvlabs.tippingpoint.com/blog/2009/03/05/mindshare-labeling-uuids-from-type-information"
		tag = "attack.execution"
	strings:
		$clsid0 = "66833fe6-8583-11d1-b16a-00c0f0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_WBEM_Call_Context {
	meta:
		description = "COM obj Microsoft_WBEM_Call_Context"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-674b6698-ee92-11d0-ad71-00c04fd8fdff"
		tag = "attack.execution"
	strings:
		$clsid0 = "674b6698-ee92-11d0-ad71-00c04fd8fdff" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CopyHookHandlers {
	meta:
		description = "COM obj CopyHookHandlers"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://malwr.com/analysis/MWQyMjRiZWQwODU2NDM2NmIwOWZhNmQ1ZjQxNGFiMmY/"
		tag = "attack.execution"
	strings:
		$clsid0 = "67ea19a0-ccef-11d0-8024-00c04fd75d13" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CoSniffStream_Class {
	meta:
		description = "COM obj CoSniffStream_Class"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-6a01fda0-30df-11d0-b724-00aa006c1a01"
		tag = "attack.execution"
	strings:
		$clsid0 = "6a01fda0-30df-11d0-b724-00aa006c1a01" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ISystemDebugEventFire {
	meta:
		description = "COM obj ISystemDebugEventFire"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.cepes.pucrs.br/experiment/Sessions/Session%203/Task%202/Shopping%205/data/lrc_recregistry.dat"
		tag = "attack.execution"
	strings:
		$clsid0 = "6c736dc1-ab0d-11d0-a2ad-00a0c90f27e8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellTaskScheduler {
	meta:
		description = "COM obj IShellTaskScheduler"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://sourceforge.net/p/mingw-w64/mailman/mingw-w64-svn/thread/From_ktietz70@users.sourceforge.net_Fri_Sep_06_14%3A53%3A13_2013/"
		tag = "attack.execution"
	strings:
		$clsid0 = "6ccb7be0-6807-11d0-b810-00c04fd706ec" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IAccPropServices {
	meta:
		description = "COM obj IAccPropServices"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/nl-nl/library/accessibility.caccpropservices(v=vs.80).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "6e26e776-04f0-495d-80e4-3330352e3169" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IAcroIEHlprObj {
	meta:
		description = "COM obj IAcroIEHlprObj"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://smithii.com/files/plugins/acroread6.inf"
		tag = "attack.execution"
	strings:
		$clsid0 = "6e67bcc1-d776-44bb-9dc8-c09f542c3cb6" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_objExpArray {
	meta:
		description = "COM obj objExpArray"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.codeproject.com/Articles/13280/How-to-display-Windows-Explorer-objects-in-one-com"
		tag = "attack.execution"
	strings:
		$clsid0 = "7007acc7-3202-11d1-aad2-00805fc1270e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Network_Connections_Tray {
	meta:
		description = "COM obj Network_Connections_Tray"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7007accf-3202-11d1-aad2-00805fc1270e"
		tag = "attack.execution"
	strings:
		$clsid0 = "7007accf-3202-11d1-aad2-00805fc1270e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Windows_Script_Host_Shell_Object {
	meta:
		description = "COM obj Windows_Script_Host_Shell_Object"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-72c24dd5-d70a-438b-8a42-98424b88afb8"
		tag = "attack.execution"
	strings:
		$clsid0 = "72c24dd5-d70a-438b-8a42-98424b88afb8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Offline_Files {
	meta:
		description = "COM obj Offline_Files"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.feg.unesp.br/remocao_virus/linkfile_fix/linkfile_fix.reg"
		tag = "attack.execution"
	strings:
		$clsid0 = "750fdf0e-2a26-11d1-a3ea-080036587f03" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Property_System_Both_Class_Factory {
	meta:
		description = "COM obj Property_System_Both_Class_Factory"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-76765b11-3f95-4af2-ac9d-ea55d8994f1a"
		tag = "attack.execution"
	strings:
		$clsid0 = "76765b11-3f95-4af2-ac9d-ea55d8994f1a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_PostBootReminder_object {
	meta:
		description = "COM obj PostBootReminder_object"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7849596a-48ea-486e-8937-a2a3009f31a9"
		tag = "attack.execution"
	strings:
		$clsid0 = "7849596a-48ea-486e-8937-a2a3009f31a9" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IHlink {
	meta:
		description = "COM obj IID_IHlink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/dblock/dotnetinstaller/blob/master/ThirdParty/Microsoft/Visual%20Studio%208/VC/PlatformSDK/Include/HlGuids.h"
		tag = "attack.execution"
	strings:
		$clsid0 = "79eac9c3-baf9-11ce-8c82-00aa004ba90b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IAuthenticate {
	meta:
		description = "COM obj IID_IAuthenticate"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/graemeg/freepascal/blob/master/packages/winunits-base/src/urlmon.pp"
		tag = "attack.execution"
	strings:
		$clsid0 = "79eac9d0-baf9-11ce-8c82-00aa004ba90b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IInternetSecurityManager {
	meta:
		description = "COM obj IInternetSecurityManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.uii.csr.browser.web.iinternetsecuritymanager.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "79eac9ee-baf9-11ce-8c82-00aa004ba90b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IInternetZoneManager {
	meta:
		description = "COM obj IID_IInternetZoneManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://referencesource.microsoft.com/#System/net/System/Net/IntranetCredentialPolicy.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "79eac9ef-baf9-11ce-8c82-00aa004ba90b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IHomeGroup {
	meta:
		description = "COM obj IHomeGroup"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://sourceforge.net/p/mingw-w64/mingw-w64/ci/9e485077ead88db6f56412c5c23d9b14ebd384f2/tree/mingw-w64-headers/include/shobjidl.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "7a3bd1d9-35a9-4fb3-a467-f48cac35e2d0" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Security_Manager {
	meta:
		description = "COM obj Security_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7b8a2d94-0ac9-11d1-896c-00c04fb6bfc4"
		tag = "attack.execution"
	strings:
		$clsid0 = "7b8a2d94-0ac9-11d1-896c-00c04fb6bfc4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_URL_Zone_Manager {
	meta:
		description = "COM obj URL_Zone_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7b8a2d95-0ac9-11d1-896c-00c04fb6bfc4"
		tag = "attack.execution"
	strings:
		$clsid0 = "7b8a2d95-0ac9-11d1-896c-00c04fb6bfc4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemObjectSink {
	meta:
		description = "COM obj IWbemObjectSink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc250946.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "7c857801-7381-11cf-884d-00aa004b2e24" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_WSearch {
	meta:
		description = "COM obj WSearch"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://answers.microsoft.com/en-us/windows/forum/windows_xp-performance/dcom-got-error-attempting-to-start-the-service/8122ab95-40b4-42c3-a186-ece55b010b6e?db=5"
		tag = "attack.execution"
	strings:
		$clsid0 = "7d096c5f-ac08-4f1f-beb7-5c22c517ce39" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Fade_Task {
	meta:
		description = "COM obj Fade_Task"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7eb5fbe4-2100-49e6-8593-17e130122f91"
		tag = "attack.execution"
	strings:
		$clsid0 = "7eb5fbe4-2100-49e6-8593-17e130122f91" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DXTFilterFactory {
	meta:
		description = "COM obj DXTFilterFactory"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-81397204-f51a-4571-8d7b-dc030521aabd"
		tag = "attack.execution"
	strings:
		$clsid0 = "81397204-f51a-4571-8d7b-dc030521aabd" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IRunnableTask {
	meta:
		description = "COM obj IRunnableTask"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://stackoverflow.com/questions/16368215/how-to-add-reference-to-irunnabletask"
		tag = "attack.execution"
	strings:
		$clsid0 = "85788d00-6807-11d0-b810-00c04fd706ec" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IShellWindows {
	meta:
		description = "COM obj IID_IShellWindows"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc836570(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "85cb6900-4d95-11cf-960c-0080c7f4ee85" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Internet_Explorer {
	meta:
		description = "COM obj Internet_Explorer"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://hwiegman.home.xs4all.nl/clsid.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "871c5380-42a0-1069-a2ea-08002b30309d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ActiveX_Control {
	meta:
		description = "COM obj ActiveX_Control"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://stackoverflow.com/questions/8783863/activex-control-8856f961-340a-11d0-a96b-00c04fd705a2-cannot-be-instantiated-be"
		tag = "attack.execution"
	strings:
		$clsid0 = "8856f961-340a-11d0-a96b-00c04fd705a2" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument40 {
	meta:
		description = "COM obj CLSID_DOMDocument40"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://support.microsoft.com/en-us/kb/305019"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d969c0-f192-11d4-a65f-0040963251e5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument50 {
	meta:
		description = "COM obj CLSID_DOMDocument50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d969e5-f192-11d4-a65f-0040963251e5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_XMLSchemaCache50 {
	meta:
		description = "COM obj CLSID_XMLSchemaCache50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d969e7-f192-11d4-a65f-0040963251e5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_SAXXMLReader50 {
	meta:
		description = "COM obj CLSID_SAXXMLReader50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://technet.microsoft.com/nl-be/ms759214"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d969ec-8b8b-4c3d-859e-af6cd158be0f" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_MXXMLWriter50 {
	meta:
		description = "COM obj CLSID_MXXMLWriter50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d969ef-f192-11d4-a65f-0040963251e5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_MXNamespaceManager50 {
	meta:
		description = "COM obj CLSID_MXNamespaceManager50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d969f1-f192-11d4-a65f-0040963251e5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument60 {
	meta:
		description = "COM obj CLSID_DOMDocument60"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms764622(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "88d96a05-f192-11d4-a65f-0040963251e5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Adbanner {
	meta:
		description = "COM obj Adbanner"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://codeverge.com/grc.spyware/reg-key-question/1594414"
		tag = "attack.execution"
	strings:
		$clsid0 = "89643d21-7b2a-11d1-8271-00a0c91f9ca0" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DSStatusBar {
	meta:
		description = "COM obj CLSID_DSStatusBar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.bleepingcomputer.com/forums/t/315688/google-searches-redirected-backdoorwin32agentasem-found/"
		tag = "attack.execution"
	strings:
		$clsid0 = "8a3f59e1-4994-11d1-a40d-00600831f336" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_WMI {
	meta:
		description = "COM obj CLSID_WMI"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://answers.microsoft.com/en-us/windows/forum/windows_7-performance/the-server-8bc3f05e-d86b-11d0-a075-00c04fb68820/7500c1d2-b873-4e68-af8c-89fe7e848658"
		tag = "attack.execution"
	strings:
		$clsid0 = "8bc3f05e-d86b-11d0-a075-00c04fb68820" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Component_Categories_Cache_Daemon {
	meta:
		description = "COM obj Component_Categories_Cache_Daemon"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/O22/102-SYSDIR_browseui_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "8c7461ef-2b13-11d2-be35-3078302c2030" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_ImnAccountManager {
	meta:
		description = "COM obj CLSID_ImnAccountManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-8d4b04e1-1331-11d0-81b8-00c04fd85ab4"
		tag = "attack.execution"
	strings:
		$clsid0 = "8d4b04e1-1331-11d0-81b8-00c04fd85ab4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_User_Account_Control_Check_Service {
	meta:
		description = "COM obj User_Account_Control_Check_Service"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-900c0763-5cad-4a34-bc1f-40cd513679d5"
		tag = "attack.execution"
	strings:
		$clsid0 = "900c0763-5cad-4a34-bc1f-40cd513679d5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellUserAssist {
	meta:
		description = "COM obj IShellUserAssist"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://147.46.109.80:9090/town/projects.jsp?sort=1&file=C%3A%5CWindows%5Cdiagnostics%5Cscheduled%5CMaintenance%5CCL_Utility.ps1"
		tag = "attack.execution"
	strings:
		$clsid0 = "90d75131-43a6-4664-9af8-dcceb85a7462" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_Research {
	meta:
		description = "COM obj CLSID_Research"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/O9/215-REFIEBAR_DLL.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "92780b25-18cc-41c8-b9be-3c9c571a8263" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ShellWindows {
	meta:
		description = "COM obj ShellWindows"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.eightforums.com/performance-maintenance/36756-dcom-error-win-8-1-a.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "9ba05972-f6a8-11cf-a442-00a0c90a8f39" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_CID_Dependency_Manager {
	meta:
		description = "COM obj GFN_CID_Dependency_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "9d194cf1-7a6a-11d2-940e-00c04fa35008" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Windows_Health_Center_WSC_Interop {
	meta:
		description = "COM obj Windows_Health_Center_WSC_Interop"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.herdprotect.com/wscinterop.dll-63252873437a123f033a3c398a84db8311c7b9a9.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "9dac2c1e-7c5c-40eb-833b-323e85a1ce84" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_CID_SetupDB {
	meta:
		description = "COM obj GFN_CID_SetupDB"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "9de4fe99-5700-11d2-acc7-00c04f8eeba1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_CID_SetupLog {
	meta:
		description = "COM obj GFN_CID_SetupLog"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "9de4fe9a-5700-11d2-acc7-00c04f8eeba1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Options_Page {
	meta:
		description = "COM obj Options_Page"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		tag = "attack.execution"
	strings:
		$clsid0 = "9fe307c0-3646-11d3-a508-00c04f5e0ba5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_StiSvc {
	meta:
		description = "COM obj StiSvc"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://social.microsoft.com/Forums/en-US/ce35e6c0-047a-4508-be2d-30ec5816d291/dcom-got-an-error-attempting-to-start-the-service-stisvc"
		tag = "attack.execution"
	strings:
		$clsid0 = "a1f4e726-8cf1-11d1-bf92-0060081ed811" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IImageDecodeFilter {
	meta:
		description = "COM obj IImageDecodeFilter"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://read.pudn.com/downloads37/sourcecode/windows/120118/Microsoft%20Visual%20Studio/VC98/Include/OCMM.IDL__.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "a3ccedf3-2de2-11d0-86f4-00a0c913f750" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CoPNGFilter_Class {
	meta:
		description = "COM obj CoPNGFilter_Class"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowsexplored.com/2012/01/09/the-case-of-the-ie-hangs-and-missing-png-images-or-killing-two-birds-with-one-stone/"
		tag = "attack.execution"
	strings:
		$clsid0 = "a3ccedf7-2de2-11d0-86f4-00a0c913f750" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Network_List_Manager {
	meta:
		description = "COM obj Network_List_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://forums.sandboxie.com/phpBB3/viewtopic.php?p=84408"
		tag = "attack.execution"
	strings:
		$clsid0 = "a47979d2-c419-11d9-a5b4-001185ad2b89" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_CBaseBrowser {
	meta:
		description = "COM obj CLSID_CBaseBrowser"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://read.pudn.com/downloads3/sourcecode/windows/system/11495/shell/inc/shdguid.h__.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "a5e46e3a-8849-11d1-9d8c-00c04fc99d61" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_CID_VS_Baseline_Requirements {
	meta:
		description = "COM obj GFN_CID_VS_Baseline_Requirements"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "a67b1e72-f530-4d0f-bef3-b4cea450c1a3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DXTFilterCollection {
	meta:
		description = "COM obj DXTFilterCollection"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-a7ee7f34-3bd1-427f-9231-f941e9b7e1fe"
		tag = "attack.execution"
	strings:
		$clsid0 = "a7ee7f34-3bd1-427f-9231-f941e9b7e1fe" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IUserIdentityManager {
	meta:
		description = "COM obj IID_IUserIdentityManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/dblock/dotnetinstaller/blob/master/ThirdParty/Microsoft/Visual%20Studio%208/VC/PlatformSDK/Include/msident.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "a9ae6c90-1d1b-11d2-b21a-00c04fa357fa" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_UserIdentityManager {
	meta:
		description = "COM obj CLSID_UserIdentityManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/dblock/dotnetinstaller/blob/master/ThirdParty/Microsoft/Visual%20Studio%208/VC/PlatformSDK/Include/msident.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "a9ae6c91-1d1b-11d2-b21a-00c04fa357fa" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ISearchManager {
	meta:
		description = "COM obj ISearchManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://social.msdn.microsoft.com/Forums/vstudio/en-US/95804fa3-282b-4dfd-a0fc-da0ee0bf4189/where-is-searchguidsh?forum=windowsdesktopsearchdevelopment"
		tag = "attack.execution"
	strings:
		$clsid0 = "ab310581-ac80-11d1-8df3-00c04fb6ef69" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IResolveShellLink {
	meta:
		description = "COM obj IResolveShellLink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://www.winehq.org/pipermail/wine-cvs/2009-January/051255.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "ac60f6a0-0fd9-11d0-99cb-00c04fd64497" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_DXImageTransform_Microsoft_Alpha {
	meta:
		description = "COM obj DXImageTransform.Microsoft.Alpha"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://cryptome.org/0002/cslid-list-08.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "adc6cb82-424c-11d2-952a-00c04fa34f05" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IDelegateFolder {
	meta:
		description = "COM obj IID_IDelegateFolder"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.codeproject.com/Articles/1840/Namespace-Extensions-the-IDelegateFolder-mystery"
		tag = "attack.execution"
	strings:
		$clsid0 = "add8ba80-002b-11d0-8f0f-00c04fd7d062" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Server_XML_HTTP {
	meta:
		description = "COM obj Server_XML_HTTP"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-afba6b42-5692-48ea-8141-dc517dcf0ef1"
		tag = "attack.execution"
	strings:
		$clsid0 = "afba6b42-5692-48ea-8141-dc517dcf0ef1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_IFontCache {
	meta:
		description = "COM obj CLSID_IFontCache"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-b0d17fc2-7bc4-11d1-bdfa-00c04fa31009"
		tag = "attack.execution"
	strings:
		$clsid0 = "b0d17fc2-7bc4-11d1-bdfa-00c04fa31009" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IFontCache {
	meta:
		description = "COM obj IID_IFontCache"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/mimeole.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "b0d17fc4-7bc4-11d1-bdfa-00c04fa31009" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IClassFactory2 {
	meta:
		description = "COM obj IClassFactory2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iclassfactory2.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "b196b28f-bab4-101a-b69c-00aa00341d07" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDXSurface {
	meta:
		description = "COM obj IDXSurface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/DShowIDL/dxtrans.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "b39fd73f-e139-11d1-9065-00c04fd9189d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_VB_Script_Language {
	meta:
		description = "COM obj VB_Script_Language"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.sevenforums.com/general-discussion/162931-cant-find-vbscript-engine.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "b54f3741-5b07-11cf-a4b0-00aa004a55e8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetFwAuthorizedApplication {
	meta:
		description = "COM obj INetFwAuthorizedApplication"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.teamfoundation.common.inetfwauthorizedapplication(v=vs.120).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "b5e64ffa-c2c5-444e-a301-fb5e00018050" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CAccPropServicesClass {
	meta:
		description = "COM obj CAccPropServicesClass"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/accessibility.caccpropservicesclass(v=vs.110).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "b5f8350b-0548-48b1-a6ee-88bd00b4a5e7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IOleCommandTarget {
	meta:
		description = "COM obj IOleCommandTarget"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iolecommandtarget.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "b722bccb-4e68-101b-a2bc-00aa00404770" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_NT_AUTHORITY_NETWORK_SERVICE {
	meta:
		description = "COM obj NT_AUTHORITY_NETWORK_SERVICE"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://support.microsoft.com/en-us/kb/934704"
		tag = "attack.execution"
	strings:
		$clsid0 = "ba126ad1-2166-11d1-b1d0-00805fc1270e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Network_Connection_Manager {
	meta:
		description = "COM obj Network_Connection_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://answers.microsoft.com/en-us/windows/forum/windows_xp-performance/dcom-error-10010-very-slow-login-very-slow-desktop/4614ae6d-93cd-45e6-b66a-cbde1db13f90?db=5"
		tag = "attack.execution"
	strings:
		$clsid0 = "ba126ae5-2166-11d1-b1d0-00805fc1270e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IActiveScript {
	meta:
		description = "COM obj IActiveScript"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://stackoverflow.com/questions/4744105/parse-and-execute-js-by-c-sharp"
		tag = "attack.execution"
	strings:
		$clsid0 = "bb1a2ae1-a4f9-11cf-8f20-00805f2cd064" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Start_Page {
	meta:
		description = "COM obj Start_Page"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		tag = "attack.execution"
	strings:
		$clsid0 = "bb81d810-3f9b-11d3-a50c-00c04f5e0ba5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Install_Page {
	meta:
		description = "COM obj Install_Page"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		tag = "attack.execution"
	strings:
		$clsid0 = "bb81d811-3f9b-11d3-a50c-00c04f5e0ba5" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ListView {
	meta:
		description = "COM obj ListView"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.cgplusplus.com/online-reference/maxscript-reference/source/listview_activex_control.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "bdd1f04b-858b-11d1-b16a-00c0f0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_INetConnectionManager {
	meta:
		description = "COM obj IID_INetConnectionManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/NetCon.Idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "c08956a2-1cd3-11d1-b1c5-00805fc1270e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CActiveIMMAppEx {
	meta:
		description = "COM obj CActiveIMMAppEx"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c1ee01f2-b3b6-4a6a-9ddd-e988c088ec82"
		tag = "attack.execution"
	strings:
		$clsid0 = "c1ee01f2-b3b6-4a6a-9ddd-e988c088ec82" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ITaskbarList4 {
	meta:
		description = "COM obj ITaskbarList4"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://fossies.org/linux/monodevelop/src/addins/WindowsPlatform/WindowsAPICodePack/Shell/Interop/Taskbar/TaskbarCOMInterfaces.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "c43dc798-95d1-4bea-9030-bb99e2983a1a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IMimeAllocator {
	meta:
		description = "COM obj IMimeAllocator"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.virtualbox.org/svn/vbox/trunk/src/VBox/Devices/Graphics/shaderlib/wine/include/mimeole.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "c5588351-7f86-11d0-8252-00c04fd85ab4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_HomeGroupCtrl {
	meta:
		description = "COM obj CLSID_HomeGroupCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c605507b-9613-4756-9c07-e0d74321cb1e"
		tag = "attack.execution"
	strings:
		$clsid0 = "c605507b-9613-4756-9c07-e0d74321cb1e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_OLE_DB_Error_Collection_Service {
	meta:
		description = "COM obj Microsoft_OLE_DB_Error_Collection_Service"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c8b522cf-5cf3-11ce-ade5-00aa0044773d"
		tag = "attack.execution"
	strings:
		$clsid0 = "c8b522cf-5cf3-11ce-ade5-00aa0044773d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_User_Account_Control_Check_Provider {
	meta:
		description = "COM obj User_Account_Control_Check_Provider"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c8e6f269-b90a-4053-a3be-499afcec98c4"
		tag = "attack.execution"
	strings:
		$clsid0 = "c8e6f269-b90a-4053-a3be-499afcec98c4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IMXNamespaceManager {
	meta:
		description = "COM obj IID_IMXNamespaceManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://sourceforge.net/p/libxml2-pas/git/ci/3a8107acbdcacf53e20811adf76476cd2368ddb5/"
		tag = "attack.execution"
	strings:
		$clsid0 = "c90352f6-643c-4fbc-bb23-e996eb2d51fd" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_WerConCpl {
	meta:
		description = "COM obj WerConCpl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.herdprotect.com/werconcpl.dll-8e8df93fb599eedee7ac07da76c235ddcb6c6aee.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "ca236752-2e77-4386-b63b-0e34774a413d" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_WbemAdministrativeLocator {
	meta:
		description = "COM obj CLSID_WbemAdministrativeLocator"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://apt-browse.org/browse/ubuntu/trusty/universe/i386/wine1.6-dev/1%3A1.6.2-0ubuntu4/file/usr/include/wine/windows/wbemprov.h"
		tag = "attack.execution"
	strings:
		$clsid0 = "cb8555cc-9128-11d1-ad9b-00c04fd8fdff" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_FirewallControlPanel {
	meta:
		description = "COM obj FirewallControlPanel"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.fixdllfile.com/English/FirewallControlPanel.dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "cc271f08-e1dd-49bf-87cc-cd6dcf3f3d9f" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_FilterMapper2 {
	meta:
		description = "COM obj CLSID_FilterMapper2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/Interop/coclasses.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "cda42200-bd88-11d0-bd4e-00a0c911ce86" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_URL_Search_Hook {
	meta:
		description = "COM obj Microsoft_URL_Search_Hook"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/CLSID/5772-ieframe_dll_shdocvw_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "cfbfae00-17a6-11d0-99cb-00c04fd64497" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetworkListManager {
	meta:
		description = "COM obj INetworkListManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://forundex.ru/admin/JetAudio-Basic-229470"
		tag = "attack.execution"
	strings:
		$clsid0 = "d0074ffd-570f-4a9b-8d69-199fdba5723b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IPSFactoryBuffer {
	meta:
		description = "COM obj IID_IPSFactoryBuffer"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/ms695281(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "d5f569d0-593b-101a-b569-08002b2dbf7a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IMapMIMEToCLSID {
	meta:
		description = "COM obj IMapMIMEToCLSID"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://read.pudn.com/downloads37/sourcecode/windows/120118/Microsoft%20Visual%20Studio/VC98/Include/OCMM.IDL__.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "d9e89500-30fa-11d0-b724-00aa006c1a01" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_SSV_Helper {
	meta:
		description = "COM obj SSV_Helper"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/CLSID/6407-jp2ssv_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "dbc80044-a445-435b-bc74-9c25c1c588a9" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IWbemLocator {
	meta:
		description = "COM obj IID_IWbemLocator"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://marc.info/?l=metasploit-framework&m=136872390501333&w=2"
		tag = "attack.execution"
	strings:
		$clsid0 = "dc12a687-737f-11cf-884d-00aa004b2e24" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetworkListManager2 {
	meta:
		description = "COM obj INetworkListManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-interface-dcb00000-570f-4a9b-8d69-199fdba5723b"
		tag = "attack.execution"
	strings:
		$clsid0 = "dcb00000-570f-4a9b-8d69-199fdba5723b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetworkListManager3 {
	meta:
		description = "COM obj INetworkListManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://social.technet.microsoft.com/Forums/windowsserver/en-US/e1acf5d3-2bd0-4393-928f-561bfbe9fa96/api-inetworklistmanager-in-powershell?forum=winserverpowershell"
		tag = "attack.execution"
	strings:
		$clsid0 = "dcb00c01-570f-4a9b-8d69-199fdba5723b" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IMLangFontLink2 {
	meta:
		description = "COM obj IMLangFontLink2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/SubtitleEdit/subtitleedit/blob/master/libse/DetectEncoding/Multilang/IMLangFontLink2.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "dccfc162-2b38-11d2-b7ec-00c04f8f5d9a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IMultiLanguage2 {
	meta:
		description = "COM obj IMultiLanguage2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://code.google.com/p/subtitleedit/source/browse/trunk/src/Logic/DetectEncoding/Multilang/IMultiLanguage2.cs?r=137"
		tag = "attack.execution"
	strings:
		$clsid0 = "dccfc164-2b38-11d2-b7ec-00c04f8f5d9a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_UserAssist {
	meta:
		description = "COM obj CLSID_UserAssist"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.geoffchappell.com/studies/windows/ie/browseui/classes/userassist.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "dd313e04-feff-11d1-8ecd-0000f87a470c" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ShellHWDetection {
	meta:
		description = "COM obj ShellHWDetection"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.bleepingcomputer.com/forums/t/396365/dcom-1084-error/"
		tag = "attack.execution"
	strings:
		$clsid0 = "dd522acc-f821-461a-a407-50b198b896dc" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Home_Group_Member_Status {
	meta:
		description = "COM obj Home_Group_Member_Status"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-de77ba04-3c92-4d11-a1a5-42352a53e0e3"
		tag = "attack.execution"
	strings:
		$clsid0 = "de77ba04-3c92-4d11-a1a5-42352a53e0e3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_GFN_CID_Default_Scenario_Factory {
	meta:
		description = "COM obj GFN_CID_Default_Scenario_Factory"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		tag = "attack.execution"
	strings:
		$clsid0 = "decdd26f-5491-11d2-bee7-00c04f797fb8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_REG_DWORD {
	meta:
		description = "COM obj REG_DWORD"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://markswinkels.nl/2012/08/remove-duplicate-personal-folders-within-windows-2008-r2-when-using-folder-redirection/"
		tag = "attack.execution"
	strings:
		$clsid0 = "dffacdc5-679f-4156-8947-c5c76bc0b67f" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_System_Clock {
	meta:
		description = "COM obj System_Clock"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-e436ebb1-524f-11ce-9f53-0020af0ba770"
		tag = "attack.execution"
	strings:
		$clsid0 = "e436ebb1-524f-11ce-9f53-0020af0ba770" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_FilgrapghManager {
	meta:
		description = "COM obj FilgrapghManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/aa645736(v=vs.71).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "e436ebb3-524f-11ce-9f53-0020af0ba770" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_WebCheck {
	meta:
		description = "COM obj WebCheck"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://forums.malwarebytes.org/index.php?/topic/64083-is-webchecker-startup-program-a-virus/"
		tag = "attack.execution"
	strings:
		$clsid0 = "e6fb5e20-de35-11cf-9c87-00aa005127ed" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_StoreNamespace {
	meta:
		description = "COM obj CLSID_StoreNamespace"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-e70c92a9-4bfd-11d1-8a95-00c04fb951f3"
		tag = "attack.execution"
	strings:
		$clsid0 = "e70c92a9-4bfd-11d1-8a95-00c04fb951f3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IStoreNamespace {
	meta:
		description = "COM obj IID_IStoreNamespace"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/msoeapi.idl"
		tag = "attack.execution"
	strings:
		$clsid0 = "e70c92aa-4bfd-11d1-8a95-00c04fb951f3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IAutoComplete2 {
	meta:
		description = "COM obj IID_IAutoComplete2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://stackoverflow.com/questions/34317985/how-to-use-iautocomplete-together-with-tstringsadapter"
		tag = "attack.execution"
	strings:
		$clsid0 = "eac04bc0-3791-11d2-bb95-0060977b464c" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDeskBand {
	meta:
		description = "COM obj IDeskBand"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://social.msdn.microsoft.com/Forums/vstudio/en-US/a5e756a4-89a9-4afb-8ce4-0c572fba6eaf/how-to-implement-ideskband2-interface-in-c?forum=clr"
		tag = "attack.execution"
	strings:
		$clsid0 = "eb0fe172-1a3a-11d0-89b3-00a0c90a90ac" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Path_Page {
	meta:
		description = "COM obj Path_Page"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		tag = "attack.execution"
	strings:
		$clsid0 = "ebc02112-5992-48b7-b365-a2ba35afe3cf" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetFwAuthorizedApplicationGuid {
	meta:
		description = "COM obj INetFwAuthorizedApplicationGuid"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://assab.cs.washington.edu/cct/Misc/RecordingServer/RecordingServerService/FirewallUtility.cs"
		tag = "attack.execution"
	strings:
		$clsid0 = "ec9846b3-2762-4a6b-a214-6acb603462d2" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MyDocs_Copy_Hook {
	meta:
		description = "COM obj MyDocs_Copy_Hook"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.shouldiblockit.com/mydocs.dll-5ba1486116ece4d10c1b6ea4c6086b5f.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "ecf03a33-103d-11d2-854d-006008059367" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_XMLHTTP {
	meta:
		description = "COM obj Microsoft.XMLHTTP"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://support.microsoft.com/en-us/kb/321924"
		tag = "attack.execution"
	strings:
		$clsid0 = "ed8c108e-4349-11d2-91a4-00c04f7969e8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IShellMenu {
	meta:
		description = "COM obj IID_IShellMenu"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://www.autoitscript.com/forum/topic/145473-the-favorites-menu/"
		tag = "attack.execution"
	strings:
		$clsid0 = "ee1f7637-e138-11d1-8379-00c04fd918d0" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemLevel1Login {
	meta:
		description = "COM obj IWbemLevel1Login"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/cc250755.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "f309ad18-d86a-11d0-a075-00c04fb68820" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_JScript5_8 {
	meta:
		description = "COM obj JScript5.8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://stackoverflow.com/questions/7167690/what-is-the-progid-or-clsid-for-ie9s-javascript-engine-code-named-chakra"
		tag = "attack.execution"
	strings:
		$clsid0 = "f414c260-6ac0-11cf-b6d1-00aa00bbbb58" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument30 {
	meta:
		description = "COM obj CLSID_DOMDocument30"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms766426(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "f5078f32-c551-11d3-89b9-0000f81fe221" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument {
	meta:
		description = "COM obj CLSID_DOMDocument"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms766426(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "f6d90f11-9c73-11d3-b32e-00c04f990bb4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_XMLHTTP {
	meta:
		description = "COM obj CLSID_XMLHTTP"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/ms766426(v=vs.85).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "f6d90f16-9c73-11d3-b32e-00c04f990bb4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_Forms_2_1_Toolbox {
	meta:
		description = "COM obj Microsoft_Forms_2.1_Toolbox"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://www.wikispaces.com/file/view/cc_20100727_220557.reg"
		tag = "attack.execution"
	strings:
		$clsid0 = "f748b5f0-15d0-11ce-bf0d-00aa0044bb60" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetFwMgr {
	meta:
		description = "COM obj INetFwMgr"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.teamfoundation.common.inetfwmgr(v=vs.120).aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "f7898af5-cac4-4632-a2ec-da06e5111af2" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetConnectionManager2 {
	meta:
		description = "COM obj INetConnectionManager2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		tag = "attack.execution"
	strings:
		$clsid0 = "faedcf69-31fe-11d1-aad2-00805fc1270e" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Messenger {
	meta:
		description = "COM obj Messenger"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/O9/287-msmsgs_exe.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "fb5f1910-f110-11d2-bb9e-00c04f795683" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CDBurn {
	meta:
		description = "COM obj CDBurn"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.systemlookup.com/O21/242-SystemRoot_system32_SHELL32_dll.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "fbeb8a05-beee-4442-804e-409d6c4515e9" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Internet_Shortcut {
	meta:
		description = "COM obj Internet_Shortcut"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-fbf23b40-e3f0-101b-8488-00aa003e56f8"
		tag = "attack.execution"
	strings:
		$clsid0 = "fbf23b40-e3f0-101b-8488-00aa003e56f8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IObjectWithSite {
	meta:
		description = "COM obj IObjectWithSite"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iobjectwithsite.aspx"
		tag = "attack.execution"
	strings:
		$clsid0 = "fc4801a3-2ba9-11cf-a229-00aa003d7352" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IImnAccountManager {
	meta:
		description = "COM obj IImnAccountManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://doxygen.reactos.org/d0/daa/imnact_8idl_source.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "fd465481-1384-11d0-abbd-0020afdfd10a" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_IMimeAllocator {
	meta:
		description = "COM obj CLSID_IMimeAllocator"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "http://doxygen.reactos.org/d4/d2f/inetcomm_8idl_source.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "fd853cdd-7f86-11d0-8252-00c04fd85ab4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_SHCoCreateInstance {
	meta:
		description = "COM obj SHCoCreateInstance"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://www.playonlinux.com/en/issue-1628.html"
		tag = "attack.execution"
	strings:
		$clsid0 = "fe787bcb-0ee8-44fb-8c89-12f508913c40" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_History {
	meta:
		description = "COM obj History"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://autohotkey.com/docs/misc/CLSID-List.htm"
		tag = "attack.execution"
	strings:
		$clsid0 = "ff393560-c2a7-11cf-bff4-444553540000" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}




rule COM_obj_StdOleLink {
	meta:
		description = "COM obj StdOleLink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000300-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_File_Moniker {
	meta:
		description = "COM obj File_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000303-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Item_Moniker {
	meta:
		description = "COM obj Item_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000304-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Anti_Moniker {
	meta:
		description = "COM obj Anti_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000305-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Pointer_Moniker {
	meta:
		description = "COM obj Pointer_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000306-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Packager_Moniker {
	meta:
		description = "COM obj Packager_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000308-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Composite_Moniker {
	meta:
		description = "COM obj Composite_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000309-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Class_Moniker {
	meta:
		description = "COM obj Class_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0000031a-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ADODB_RecordSet {
	meta:
		description = "COM obj ADODB_RecordSet"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00000535-0000-0010-8000-00AA006D2EA4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OutlookAttachMoniker {
	meta:
		description = "COM obj OutlookAttachMoniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0002034c-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OutlookMessageMoniker {
	meta:
		description = "COM obj OutlookMessageMoniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0002034e-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Sheet_5 {
	meta:
		description = "COM obj Excel_Sheet_5"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020810-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Chart_5 {
	meta:
		description = "COM obj Excel_Chart_5"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020811-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Sheet_8 {
	meta:
		description = "COM obj Excel_Sheet_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020820-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Chart_8 {
	meta:
		description = "COM obj Excel_Chart_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020821-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Sheet_12 {
	meta:
		description = "COM obj Excel_Sheet_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020830-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_SheetMacroEnabled_12 {
	meta:
		description = "COM obj Excel_SheetMacroEnabled_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020832-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_SheetBinaryMacroEnabled_12 {
	meta:
		description = "COM obj Excel_SheetBinaryMacroEnabled_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020833-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Word_Document_6 {
	meta:
		description = "COM obj Word_Document_6"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020900-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Word_Document_8 {
	meta:
		description = "COM obj Word_Document_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020906-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj1 {
	meta:
		description = "COM obj OLE_pobj1"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00020C01-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Windows_LNK {
	meta:
		description = "COM obj Windows_LNK"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00021401-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Equation_2_0 {
	meta:
		description = "COM obj Equation_2_0"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00021700-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj2 {
	meta:
		description = "COM obj OLE_pobj2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00022601-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj8 {
	meta:
		description = "COM obj OLE_pobj8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00022602-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj3 {
	meta:
		description = "COM obj OLE_pobj3"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "00022603-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Equation_3_0 {
	meta:
		description = "COM obj Equation_3_0"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0002CE02-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MathType_Equation {
	meta:
		description = "COM obj MathType_Equation"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0002CE03-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Equation {
	meta:
		description = "COM obj Equation"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0003000B-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj4 {
	meta:
		description = "COM obj OLE_pobj4"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0003000C-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj5 {
	meta:
		description = "COM obj OLE_pobj5"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0003000D-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj6 {
	meta:
		description = "COM obj OLE_pobj6"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0003000E-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Equation_2_0_2 {
	meta:
		description = "COM obj Equation_2_0-2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0004A6B0-0000-0000-C000-000000000046" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Powerpoint_Slide_12 {
	meta:
		description = "COM obj Powerpoint_Slide_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "048EB43E-2059-422F-95E0-557DA96038AF" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_otkloadr_WRLoader {
	meta:
		description = "COM obj otkloadr_WRLoader"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "05741520-C4EB-440A-AC3F-9643BBC9F847" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scripletfile {
	meta:
		description = "COM obj scripletfile"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "06290BD2-48AA-11D2-8432-006008C3FBFC" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Script_Moniker {
	meta:
		description = "COM obj Script_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "06290BD3-48AA-11D2-8432-006008C3FBFC" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll2 {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0CF774D0-F077-11D1-B1BC-00C04F86C324" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSScriptControl_ScriptControl {
	meta:
		description = "COM obj MSScriptControl_ScriptControl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_BCSAddin_Connect {
	meta:
		description = "COM obj BCSAddin_Connect"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "1461A561-24E8-4BA3-8D4A-FFEEF980556B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_WUAEXT_DLL2 {
	meta:
		description = "COM obj Loads_WUAEXT_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "14CE31DC-ABC2-484C-B061-CF3416AED8FF" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UPnP_DescriptionDocument {
	meta:
		description = "COM obj UPnP_DescriptionDocument"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "1D8A9B47-3A28-4CE2-8A4B-BD34E45BCEEB" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_TabStrip {
	meta:
		description = "COM obj MSCOMCTL_TabStrip"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "1EFB6596-857C-11D1-B16A-00C0F0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shockwave_Control_Objects {
	meta:
		description = "COM obj Shockwave_Control_Objects"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "233C1507-6A77-46A4-9443-F871F945D258" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_UmEvmCtrl {
	meta:
		description = "COM obj UmOutlookAddin_UmEvmCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "23CE100B-1390-49D6-BA00-F17D3AEE149C" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_SSCE_DropTable {
	meta:
		description = "COM obj SSCE_DropTable"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "3018609E-CDBC-47E8-A255-809D46BAA319" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_HTML_Application {
	meta:
		description = "COM obj HTML_Application"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "3050F4D8-98B5-11CF-BB82-00AA00BDCE0B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_osf_SandboxManager {
	meta:
		description = "COM obj osf_SandboxManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "33BD73C2-7BB4-48F4-8DBC-82B8B313AE16" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UPnP_DescriptionDocumentEx {
	meta:
		description = "COM obj UPnP_DescriptionDocumentEx"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "33FD0563-D81A-4393-83CC-0195B1DA2F91" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_ELSEXT_DLL2 {
	meta:
		description = "COM obj Loads_ELSEXT_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "394C052E-B830-11D0-9A86-00C04FD8DBF7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_osf_SandboxContent {
	meta:
		description = "COM obj osf_SandboxContent"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "3BA59FA5-41BF-4820-98E4-04645A806698" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Search_XmlContentFilter {
	meta:
		description = "COM obj Search_XmlContentFilter"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "41B9BE05-B3AF-460C-BF0B-2CDD44A093B1" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Device {
	meta:
		description = "COM obj Device"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "4315D437-5B8C-11D0-BD3B-00A0C911CE86" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Control_TaskSymbol {
	meta:
		description = "COM obj Control_TaskSymbol"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "44F9A03B-A3EC-4F3B-9364-08E0007F21DF" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_MultiPage {
	meta:
		description = "COM obj Forms_MultiPage"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "46E31370-3F7A-11CE-BED6-00AA00611080" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_Image {
	meta:
		description = "COM obj Forms_Image"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "4C599241-6926-101B-9992-00000B65C6F9" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2000_2002 {
	meta:
		description = "COM obj AutoCAD_2000-2002"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "4D3263E4-CAB7-11D2-802A-0080C703929C" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_R14 {
	meta:
		description = "COM obj AutoCAD_R14"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "5E4405B0-5374-11CE-8E71-0020AF04B1D7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Powerpoint_Show_8 {
	meta:
		description = "COM obj Powerpoint_Show_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "64818D10-4F9B-11CF-86EA-00AA00B929E8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Powerpoint_Slide_8 {
	meta:
		description = "COM obj Powerpoint_Slide_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "64818D11-4F9B-11CF-86EA-00AA00B929E8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_Toolbar {
	meta:
		description = "COM obj MSCOMCTL_Toolbar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "66833FE6-8583-11D1-B16A-00C0F0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2013 {
	meta:
		description = "COM obj AutoCAD_2013"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "6A221957-2D85-42A7-8E19-BE33950D1DEB" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_BCSAddin_ManageSolutionHelper {
	meta:
		description = "COM obj BCSAddin_ManageSolutionHelper"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "6AD4AE40-2FF1-4D88-B27A-F76FC7B40440" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_Frame {
	meta:
		description = "COM obj Forms_Frame"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "6E182020-F460-11CE-9BCD-00AA00608E01" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_VbaAddin {
	meta:
		description = "COM obj Microsoft_VbaAddin"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "799ED9EA-FB5E-11D1-B7D6-00C04FC2AAE2" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_StdHlink {
	meta:
		description = "COM obj StdHlink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9D0-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_StdHlinkBrowseContext {
	meta:
		description = "COM obj StdHlinkBrowseContext"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9D1-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_URL_Moniker {
	meta:
		description = "COM obj URL_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9E0-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_APPH_http {
	meta:
		description = "COM obj APPH_http"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9E2-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_APPH_ftp {
	meta:
		description = "COM obj APPH_ftp"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9E3-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_APPH_https {
	meta:
		description = "COM obj APPH_https"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9E5-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_APPH_mk {
	meta:
		description = "COM obj APPH_mk"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9E6-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_APPH_file_or_local {
	meta:
		description = "COM obj APPH_file_or_local"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "79EAC9E7-BAF9-11CE-8C82-00AA004BA90B" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2007_2009 {
	meta:
		description = "COM obj AutoCAD_2007-2009"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "7AABBB95-79BE-4C0F-8024-EB6AF271231C" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll3 {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "85131630-480C-11D2-B1F9-00C04F86C324" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll4 {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "85131631-480C-11D2-B1F9-00C04F86C324" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_ButtonBar {
	meta:
		description = "COM obj UmOutlookAddin_ButtonBar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "8627E73B-B5AA-4643-A3B0-570EDA17E3E7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2004_2006 {
	meta:
		description = "COM obj AutoCAD_2004-2006"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "8E75D913-3D21-11D2-85C4-080009A0C626" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_TreeCtrl {
	meta:
		description = "COM obj MSCOMCTL_TreeCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_ELSEXT_DLL {
	meta:
		description = "COM obj Loads_ELSEXT_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "975797FC-4E2A-11D0-B702-00C04FD8DBF7" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_ListViewCtrl {
	meta:
		description = "COM obj MSCOMCTL_ListViewCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "996BF5E0-8044-4650-ADEB-0B013914E99C" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_otkloadr {
	meta:
		description = "COM obj otkloadr"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "A08A033D-1A75-4AB6-A166-EAD02F547959" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_vbscript_dll {
	meta:
		description = "COM obj vbscript_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "B54F3741-5B07-11CF-A4B0-00AA004A55E8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_ListViewCtrl2 {
	meta:
		description = "COM obj MSCOMCTL_ListViewCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "BDD1F04B-858B-11D1-B16A-00C0F0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ShellBrowserWindow {
	meta:
		description = "COM obj ShellBrowserWindow"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "C08AFD90-F2A1-11D1-8455-00A0C91F3880" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_Form {
	meta:
		description = "COM obj Forms_Form"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "C62A69F0-16DC-11CE-9E98-00AA00574A4F" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_TreeCtrl2 {
	meta:
		description = "COM obj MSCOMCTL_TreeCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_RoomsCTP {
	meta:
		description = "COM obj UmOutlookAddin_RoomsCTP"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "CCD068CD-1260-4AEA-B040-A87974EB3AEF" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_osf_Sandbox {
	meta:
		description = "COM obj osf_Sandbox"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "CDDBCC7C-BE18-4A58-9CBF-D62A012272CE" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_InspectorContext {
	meta:
		description = "COM obj UmOutlookAddin_InspectorContext"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "CDF1C8AA-2D25-43C7-8AFE-01F73A3C66DA" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Powerpoint_Show_12 {
	meta:
		description = "COM obj Powerpoint_Show_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "CF4F55F4-8F87-4D47-80BB-5808164BB3F8" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shockwave_Flash_Object {
	meta:
		description = "COM obj Shockwave_Flash_Object"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "D27CDB6E-AE6D-11CF-96B8-444553540000" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shockwave_Flash_Object2 {
	meta:
		description = "COM obj Shockwave_Flash_Object2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "D27CDB70-AE6D-11CF-96B8-444553540000" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_PlayOnPhoneDlg {
	meta:
		description = "COM obj UmOutlookAddin_PlayOnPhoneDlg"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "D50FED35-0A08-4B17-B3E0-A8DD0EDE375D" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_2_0 {
	meta:
		description = "COM obj Forms_2_0"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "D7053240-CE69-11CD-A777-00DD01143C57" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2010_2012 {
	meta:
		description = "COM obj AutoCAD_2010-2012"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "D70E31AD-2614-49F2-B0FC-ACA781D81F3E" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_WUAEXT_DLL {
	meta:
		description = "COM obj Loads_WUAEXT_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "D93CE8B5-3BF8-462C-A03F-DED2730078BA" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_ImageComboCtrl {
	meta:
		description = "COM obj MSCOMCTL_ImageComboCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "DD9DA666-8594-11D1-B16A-00C0F0283628" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Silverlight_Objects {
	meta:
		description = "COM obj Silverlight_Objects"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "DFEAF541-F3E1-4c24-ACAC-99C30715084A" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_InkEd_InkEdit {
	meta:
		description = "COM obj InkEd_InkEdit"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "E5CA59F5-57C4-4DD8-9BD6-1DEEEDD27AF4" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSDAORA_1 {
	meta:
		description = "COM obj MSDAORA_1"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "E8CC4CBE-FDFF-11D0-B865-00A0C9081C1D" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_OCI_DLL {
	meta:
		description = "COM obj Loads_OCI_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "E8CC4CBF-FDFF-11D0-B865-00A0C9081C1D" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_New_Moniker {
	meta:
		description = "COM obj New_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "ECABAFC6-7F19-11D2-978E-0000F8757E2A" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_MQRT_DLL {
	meta:
		description = "COM obj Loads_MQRT_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "ECABAFC9-7F19-11D2-978E-0000F8757E2A" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_SOAP_Moniker {
	meta:
		description = "COM obj SOAP_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "ECABB0C7-7F19-11D2-978E-0000F8757E2A" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_FormRegionContext {
	meta:
		description = "COM obj UmOutlookAddin_FormRegionContext"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "ECF44975-786E-462F-B02A-CBCCB1A2C4A2" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj7 {
	meta:
		description = "COM obj OLE_pobj7"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "F20DA720-C02F-11CE-927B-0800095AE340" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_jscript_dll {
	meta:
		description = "COM obj jscript_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "F414C260-6AC0-11CF-B6D1-00AA00BBBB58" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Word_Document_12 {
	meta:
		description = "COM obj Word_Document_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "F4754C9B-64F5-4B40-8AF4-679732AC0607" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_FormRegionAddin {
	meta:
		description = "COM obj UmOutlookAddin_FormRegionAddin"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 5
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		tag = "attack.execution"
	strings:
		$clsid0 = "F959DBBB-3867-41F2-8E5F-3B8BEFAA81B3" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}


