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
		weight = 4
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1223"
	strings:
		$clsid0 = "ADB880A6-D8FF-11CF-9377-00AA003B7A11" nocase ascii wide
		$clsid1 = "Internet.HHCtrl" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MMC {
	meta:
		description = "COM obj MMC Plugable Internet Protocol call"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "MITRE ATTACK"
	    tag = "attack.execution,attack.t1189"
	strings:
		$clsid0 = "B0395DA5-6A15-4E44-9F36-9A9DC7A2F341" nocase ascii wide
		$clsid1 = "MMC.IconControl" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_WMDMCESP {
	meta:
		description = "COM obj WMDMCESP"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://www.blackhat.com/docs/us-15/materials/us-15-Li-Attacking-Interoperability-An-OLE-Edition.pdf"
	    tag = "attack.execution,attack.t1189"
	strings:
		$clsid0 = "067B4B81-B1EC-489f-B111-940EBDC44EBE" nocase ascii wide
		$clsid1 = "WMDMCESP.WMDMCESP" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MsComCtl {
	meta:
		description = "COM obj MsComCtl call for potential exploit CVE-2012-1856"
		author = "Lionel PRAT"
        version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
	    tag = "attack.execution,attack.t1189"
	strings:
		$clsid0 = "1EFB6596-857C-11D1-B16A-00C0F0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.TabStrip" nocase ascii wide
	condition:
	    check_clsid_bool and any of ($clsid*)
}

rule COM_obj_EmptyField {
	meta:
		description = "COM obj EmptyField"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/system.guid.empty.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/ms680509.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iclassfactory.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/dd542707.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.ipersiststream.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/system.runtime.interopservices.comtypes.ipersistfile.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.ioleobject.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iparsedisplayname.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/nl-nl/ms679756"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ee379697.aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00000303-0000-0000-c000-000000000046" nocase ascii wide
		//$clsid1 = "file" nocase ascii wide //more flase positive
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ItemMoniker {
	meta:
		description = "COM obj ItemMoniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://doxygen.reactos.org/d4/dfd/ole32__objidl_8idl_source.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://doxygen.reactos.org/d4/dfd/ole32__objidl_8idl_source.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc226820.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc226820.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://support.microsoft.com/en-us/kb/288706"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00000542-0000-0010-8000-00aa006d2ea4" nocase ascii wide
		$clsid1 = "ADODB.ErrorLookup" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ADODB_Stream {
	meta:
		description = "COM obj ADODB.Stream"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://support.microsoft.com/en-us/kb/870669"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00000566-0000-0010-8000-00aa006d2ea4" nocase ascii wide
		$clsid1 = "ADODB.Stream" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_PSDispatch {
	meta:
		description = "COM obj PSDispatch"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.mazecomputer.com/sxs/help/proxy.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://stackoverflow.com/questions/14712408/jna-cocreateinstance"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00021401-0000-0000-c000-000000000046" nocase ascii wide
		$clsid1 = "lnkfile" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellFolder {
	meta:
		description = "COM obj IShellFolder"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://pinvoke.net/default.aspx/Interfaces/IShellFolder.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc144110.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://computer-programming-forum.com/16-visual-basic/364d93d0f6ee4195.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://technet.microsoft.com/nl-nl/ms686642"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://kb4sp.wordpress.com/2011/06/30/fixing-the-dcom-error-the-application-specific-permission-settings-do-not-grant-local-activation-permission-for-the-com-server-application-with-clsid/"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "000c101c-0000-0000-c000-000000000046" nocase ascii wide
		$clsid1 = "IMsiServer" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_AutoComplete {
	meta:
		description = "COM obj Microsoft_AutoComplete"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-00bb2763-6a77-11d0-a535-00c04fd7d062"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-00bb2764-6a77-11d0-a535-00c04fd7d062"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-interface-016fe2ec-b2c8-45f8-b23b-39e53a75396b"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/CLSID/256-browseui_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.checkfilename.com/view-details/Jukebox-Pro/RespageIndex/0/sTab/2/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://sourceforge.net/p/jedi-apilib/mailman/jedi-apilib-wscl-svn/?viewmonth=200902&viewday=11"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/SETUP/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://technet.microsoft.com/nl-nl/library/Cc786827(v=WS.10).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "05589fa1-c356-11ce-bf01-00aa0055595a" nocase ascii wide
		$clsid1 = "AMOVIE.ActiveMovieControl" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Scriptlet_Constructor {
	meta:
		description = "COM obj Scriptlet.Constructor"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-06290bd1-48aa-11d2-8432-006008c3fbfc"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "06290bd1-48aa-11d2-8432-006008c3fbfc" nocase ascii wide
		$clsid1 = "Scriptlet.Constructor" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ActiveXVulnerability {
	meta:
		description = "COM obj ActiveXVulnerability"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.securityfocus.com/bid/598/exploit"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "06290bd5-48aa-11d2-8432-006008c3fbfc" nocase ascii wide
		$clsid1 = "Scriptlet.TypeLib" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellFolder2_QueryInterface_Unimplemented_interface {
	meta:
		description = "COM obj IShellFolder2_QueryInterface_Unimplemented_interface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://www.winehq.org/pipermail/wine-users/2010-May/072093.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/CLSID/32558-AcroIEhelper_ocx_ACROIE_1_DLL_AcroIEhelper_dll_ACROIE_1_OCX.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://tredosoft.com/files/IE7s/newIE7.reg"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-0700f42f-eee3-443a-9899-166f16286796"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ubuntuforums.org/archive/index.php/t-869952.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://social.msdn.microsoft.com/Forums/vstudio/en-US/f7c9d4d2-dbfa-44bd-a804-9f2fa1d27093/vs6-to-vs2010-font"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0be35203-8f91-11ce-9de3-00aa004bb851" nocase ascii wide
		$clsid1 = "StdFont" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_StdPict {
	meta:
		description = "COM obj CLSID_StdPict"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.systemlookup.com/O16/2069-OPW_25900_cab.html"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0be35204-8f91-11ce-9de3-00aa004bb851" nocase ascii wide
		$clsid1 = "StdPicture" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IShellIconOverlayIdentifier {
	meta:
		description = "COM obj IShellIconOverlayIdentifier"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/dwmkerr/sharpshell/blob/master/SharpShell/SharpShell/Interop/IShellIconOverlayIdentifier.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://sourceforge.net/p/zeoslib/code-0/3534/tree//branches/testing-7.3/src/plain/ZOleDB.pas?barediff=500986a671b75b2b8b001f0f:3533"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-0d43fe01-f093-11cf-8940-00a0c9054228"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0d43fe01-f093-11cf-8940-00a0c9054228" nocase ascii wide
		$clsid1 = "Scripting.FileSystemObject" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Links {
	meta:
		description = "COM obj &Links"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.systemlookup.com/CLSID/72019-browseui_dll_shell32_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-0e890f83-5f79-11d1-9043-00c04fd9189d"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://uni-smr.ac.ru/archive/dev/cc++/ms/vs2010_en/VCExpress/vs_setup.pdi"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/bb776890(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "13709620-c279-11ce-a49e-444553540000" nocase ascii wide
		$clsid1 = "Shell.Application" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_winmgmts {
	meta:
		description = "COM obj winmgmts"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://technet.microsoft.com/en-us/library/ee198932.aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "172bddf8-ceea-11d1-8b05-00600806d9b6" nocase ascii wide
		$clsid1 = "WINMGMTS" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UBoxProSetup_exe {
	meta:
		description = "COM obj UBoxProSetup.exe"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://malwr.com/analysis/YjRmZmVkMGI5MDYwNDM0NDkwOWM2YjYwYzNhNmM5Mjc/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/troj_agent_0000176.toma"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://social.msdn.microsoft.com/Forums/en-US/6ae7127f-95e1-44d0-af7a-3d086fcbe42f/unexpected-reboots-in-admin-setup-of-vs2005-team-edition-for-sw-developers?forum=vssetup"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/phuslu/pyMSAA/blob/master/comtypes/errorinfo.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-1f486a52-3cb1-48fd-8f50-b8dc300d9f9d"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-2087c2f4-2cef-4953-a8ab-66779b670495"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "2087c2f4-2cef-4953-a8ab-66779b670495" nocase ascii wide
		$clsid1 = "WinHttp.WinHttpRequest" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IErrorInfo2 {
	meta:
		description = "COM obj IErrorInfo"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://blogs.msdn.com/b/askie/archive/2012/09/12/how-to-determine-the-clsid-of-an-activex-control.aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "25336920-03f9-11cf-8fd0-00aa00686f13" nocase ascii wide
		$clsid1 = "htmlfile" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IDXTaskManager_Interface {
	meta:
		description = "COM obj IDXTaskManager_Interface"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/DShowIDL/dxtrans.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://code.google.com/p/subtitleedit/source/browse/trunk/src/Logic/DetectEncoding/Multilang/IMultiLanguage.cs?r=17"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-275c23e2-3747-11d0-9fea-00aa003f8646"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.office.interop.infopath.semitrust.ixmldomdocument.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-interface-2933bf95-7b36-11d2-b20e-00c04f983e60"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-304ce942-6e39-40d8-943a-b913c40c9cd4"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "304ce942-6e39-40d8-943a-b913c40c9cd4" nocase ascii wide
		$clsid1 = "HNetCfg.FwMgr" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_HTML_About_Pluggable_Protocol {
	meta:
		description = "COM obj Microsoft_HTML_About_Pluggable_Protocol"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3050f406-98b5-11cf-bb82-00aa00bdce0b"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/lutzroeder/Writer/blob/master/Source/Html/NativeMethods.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3050f4cf-98b5-11cf-bb82-00aa00bdce0b"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "3050f4cf-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
		$clsid1 = "PeerFactory.PeerFactory" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Trident_HTMLEditor {
	meta:
		description = "COM obj Trident_HTMLEditor"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3050f4f5-98b5-11cf-bb82-00aa00bdce0b"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "3050f4f5-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
		$clsid1 = "Trident.HTMLEditor" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IHTMLEditor {
	meta:
		description = "COM obj IHTMLEditor"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/searchapi.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/DShowIDL/dxtrans.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-30c3b080-30fb-11d0-b724-00aa006c1a01"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "30c3b080-30fb-11d0-b724-00aa006c1a01" nocase ascii wide
		$clsid1 = "ImgUtil.CoMapMIMEToCLSID" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_SysTray {
	meta:
		description = "COM obj SysTray"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.systemlookup.com/CLSID/61109-stobject_dll_dllwsco_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-385a91bc-1e8a-4e4a-a7a6-f4fc1e6ca1bd"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "385a91bc-1e8a-4e4a-a7a6-f4fc1e6ca1bd" nocase ascii wide
		$clsid1 = "Object.Microsoft.DXTFilter" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IWbemPath {
	meta:
		description = "COM obj IWbemPath"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/angelcolmenares/pash/blob/master/External/System.Management/System.Management/IWbemPath.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-3c374a40-bae4-11cf-bf7d-00aa006946ee"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.experts-exchange.com/Programming/Languages/Pascal/Delphi/Q_22520713.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-40dd6e20-7c17-11ce-a804-00aa003ca9f6"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowssecrets.com/forums/showthread.php/135115-Icons-for-Firefox-missing-in-Windows-Explorer"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://nakedsecurity.sophos.com/2012/06/06/zeroaccess-rootkit-usermode/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/O22/68-SYSDIR_browseui_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc250946.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://whiteboard.nektra.com/internet-explorer-7-favorites-doesn-t-work-classfactory-cannot-supply-requested-class"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://forums.winamp.com/showthread.php?t=309949"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc250726.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc250726.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.fixdllfile.com/Dutch/fvevol.sys.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://a-whiter.livejournal.com/1266.html?thread=1522"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://www.wikispaces.com/file/view/cc_20100727_220557.reg"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "46e31370-3f7a-11ce-bed6-00aa00611080" nocase ascii wide
		$clsid1 = "Forms.MultiPage" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_InterfaceID {
	meta:
		description = "COM obj InterfaceID"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/arank/cs181-practical2/blob/master/train/1e1cc235291c576f6e5f480fcfd444Ad7671b338d.None.xml"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://appdb.winehq.org/objectManager.php?sClass=version&iId=5826&iTestingId=15991"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-4a16043f-676d-11d2-994e-00c04fa309d4"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/bb931215(v=vs.85).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-4cb26c03-ff93-11d0-817e-0000f87557db"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://read.pudn.com/downloads3/sourcecode/windows/6437/soap/Samples/Echo/Service/Rpc/CppSrv/ReleaseUMinDependency/msxml3.tlh__.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ftp.icpdas.com/pub/beta_version/VHM/wince600/at91sam9g45m10ek_armv4i/cesysgen/sdk/inc/imgutil.h"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ftp.uma.es/Drivers/TVIDEO/ATI/128RAGE/WIN9X/DIRECTX6/DIRECTX/DDRAW.INF"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://users.jyu.fi/~vesal/kurssit/winohj/htyot/h00/panniva/DAnim.pas"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-50d5107a-d278-4871-8989-f4ceaaf59cfc"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-interface-50ea08b0-dd1b-4664-9a50-c2f40f4bd79a"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://uni-smr.ac.ru/archive/dev/cc++/ms/vs2010_en/VCExpress/setup.sdb"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-53bd6b4e-3780-4693-afc3-7161c2f3ee9c"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-540d8a8b-1c3f-4e32-8132-530f6a502090"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://users.jyu.fi/~vesal/kurssit/winohj/htyot/h00/panniva/DShow.pas"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://rapidq.phatcode.net/examples/video/DirectShow_test.bas"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-56fdf344-fd6d-11d0-958a-006097c9a090"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://q.cnblogs.com/q/55896/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-5b4dae26-b807-11d0-9815-00c04fd91972"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/tigersoldier/wine/blob/master/include/wia_lh.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/SETUP/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-603d3801-bd81-11d0-a3a5-00c04fd706ec"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-623e2882-fc0e-11d1-9a77-0000f8756a10"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "623e2882-fc0e-11d1-9a77-0000f8756a10" nocase ascii wide
		$clsid1 = "DXImageTransform.Microsoft.Gradient" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Start_Menu_Cache {
	meta:
		description = "COM obj Start_Menu_Cache"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-660b90c8-73a9-4b58-8cae-355b7f55341b"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://dvlabs.tippingpoint.com/blog/2009/03/05/mindshare-labeling-uuids-from-type-information"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "66833fe6-8583-11d1-b16a-00c0f0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.Toolbar" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_WBEM_Call_Context {
	meta:
		description = "COM obj Microsoft_WBEM_Call_Context"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-674b6698-ee92-11d0-ad71-00c04fd8fdff"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://malwr.com/analysis/MWQyMjRiZWQwODU2NDM2NmIwOWZhNmQ1ZjQxNGFiMmY/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-6a01fda0-30df-11d0-b724-00aa006c1a01"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "6a01fda0-30df-11d0-b724-00aa006c1a01" nocase ascii wide
		$clsid1 = "ImgUtil.CoSniffStream" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ISystemDebugEventFire {
	meta:
		description = "COM obj ISystemDebugEventFire"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.cepes.pucrs.br/experiment/Sessions/Session%203/Task%202/Shopping%205/data/lrc_recregistry.dat"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://sourceforge.net/p/mingw-w64/mailman/mingw-w64-svn/thread/From_ktietz70@users.sourceforge.net_Fri_Sep_06_14%3A53%3A13_2013/"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/nl-nl/library/accessibility.caccpropservices(v=vs.80).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://smithii.com/files/plugins/acroread6.inf"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.codeproject.com/Articles/13280/How-to-display-Windows-Explorer-objects-in-one-com"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7007accf-3202-11d1-aad2-00805fc1270e"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-72c24dd5-d70a-438b-8a42-98424b88afb8"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "72c24dd5-d70a-438b-8a42-98424b88afb8" nocase ascii wide
		$clsid1 = "WScript.Shell" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Offline_Files {
	meta:
		description = "COM obj Offline_Files"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://ftp.feg.unesp.br/remocao_virus/linkfile_fix/linkfile_fix.reg"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-76765b11-3f95-4af2-ac9d-ea55d8994f1a"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7849596a-48ea-486e-8937-a2a3009f31a9"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/dblock/dotnetinstaller/blob/master/ThirdParty/Microsoft/Visual%20Studio%208/VC/PlatformSDK/Include/HlGuids.h"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/graemeg/freepascal/blob/master/packages/winunits-base/src/urlmon.pp"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.uii.csr.browser.web.iinternetsecuritymanager.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://referencesource.microsoft.com/#System/net/System/Net/IntranetCredentialPolicy.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://sourceforge.net/p/mingw-w64/mingw-w64/ci/9e485077ead88db6f56412c5c23d9b14ebd384f2/tree/mingw-w64-headers/include/shobjidl.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7b8a2d94-0ac9-11d1-896c-00c04fb6bfc4"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7b8a2d95-0ac9-11d1-896c-00c04fb6bfc4"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc250946.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://answers.microsoft.com/en-us/windows/forum/windows_xp-performance/dcom-got-error-attempting-to-start-the-service/8122ab95-40b4-42c3-a186-ece55b010b6e?db=5"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-7eb5fbe4-2100-49e6-8593-17e130122f91"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-81397204-f51a-4571-8d7b-dc030521aabd"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "81397204-f51a-4571-8d7b-dc030521aabd" nocase ascii wide
		$clsid1 = "BehaviorFactory.Microsoft.DXTFilterFactory" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IRunnableTask {
	meta:
		description = "COM obj IRunnableTask"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://stackoverflow.com/questions/16368215/how-to-add-reference-to-irunnabletask"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/cc836570(v=vs.85).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://hwiegman.home.xs4all.nl/clsid.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://stackoverflow.com/questions/8783863/activex-control-8856f961-340a-11d0-a96b-00c04fd705a2-cannot-be-instantiated-be"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "8856f961-340a-11d0-a96b-00c04fd705a2" nocase ascii wide
		$clsid1 = "Shell.Explorer" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument40 {
	meta:
		description = "COM obj CLSID_DOMDocument40"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://support.microsoft.com/en-us/kb/305019"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "88d969e5-f192-11d4-a65f-0040963251e5" nocase ascii wide
		$clsid1 = "Msxml2.DOMDocument" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_XMLSchemaCache50 {
	meta:
		description = "COM obj CLSID_XMLSchemaCache50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "88d969e7-f192-11d4-a65f-0040963251e5" nocase ascii wide
		$clsid1 = "Msxml2.XMLSchemaCache" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_SAXXMLReader50 {
	meta:
		description = "COM obj CLSID_SAXXMLReader50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://technet.microsoft.com/nl-be/ms759214"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "88d969ec-8b8b-4c3d-859e-af6cd158be0f" nocase ascii wide
		$clsid1 = "Msxml2.SAXXMLReader" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_MXXMLWriter50 {
	meta:
		description = "COM obj CLSID_MXXMLWriter50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "88d969ef-f192-11d4-a65f-0040963251e5" nocase ascii wide
		$clsid1 = "Msxml2.MXXMLWriter" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_MXNamespaceManager50 {
	meta:
		description = "COM obj CLSID_MXNamespaceManager50"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms759214(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "88d969f1-f192-11d4-a65f-0040963251e5" nocase ascii wide
		$clsid1 = "Msxml2.MXNamespaceManager" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument60 {
	meta:
		description = "COM obj CLSID_DOMDocument60"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms764622(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "88d96a05-f192-11d4-a65f-0040963251e5" nocase ascii wide
		$clsid1 = "Msxml2.DOMDocument" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Adbanner {
	meta:
		description = "COM obj Adbanner"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://codeverge.com/grc.spyware/reg-key-question/1594414"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.bleepingcomputer.com/forums/t/315688/google-searches-redirected-backdoorwin32agentasem-found/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://answers.microsoft.com/en-us/windows/forum/windows_7-performance/the-server-8bc3f05e-d86b-11d0-a075-00c04fb68820/7500c1d2-b873-4e68-af8c-89fe7e848658"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/O22/102-SYSDIR_browseui_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-8d4b04e1-1331-11d0-81b8-00c04fd85ab4"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-900c0763-5cad-4a34-bc1f-40cd513679d5"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://147.46.109.80:9090/town/projects.jsp?sort=1&file=C%3A%5CWindows%5Cdiagnostics%5Cscheduled%5CMaintenance%5CCL_Utility.ps1"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/O9/215-REFIEBAR_DLL.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.eightforums.com/performance-maintenance/36756-dcom-error-win-8-1-a.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.herdprotect.com/wscinterop.dll-63252873437a123f033a3c398a84db8311c7b9a9.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://social.microsoft.com/Forums/en-US/ce35e6c0-047a-4508-be2d-30ec5816d291/dcom-got-an-error-attempting-to-start-the-service-stisvc"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "a1f4e726-8cf1-11d1-bf92-0060081ed811" nocase ascii wide
		$clsid1 = "WiaDevMgr" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IImageDecodeFilter {
	meta:
		description = "COM obj IImageDecodeFilter"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://read.pudn.com/downloads37/sourcecode/windows/120118/Microsoft%20Visual%20Studio/VC98/Include/OCMM.IDL__.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowsexplored.com/2012/01/09/the-case-of-the-ie-hangs-and-missing-png-images-or-killing-two-birds-with-one-stone/"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "a3ccedf7-2de2-11d0-86f4-00a0c913f750" nocase ascii wide
		$clsid1 = "PNGFilter.CoPNGFilter" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Network_List_Manager {
	meta:
		description = "COM obj Network_List_Manager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://forums.sandboxie.com/phpBB3/viewtopic.php?p=84408"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://read.pudn.com/downloads3/sourcecode/windows/system/11495/shell/inc/shdguid.h__.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-a7ee7f34-3bd1-427f-9231-f941e9b7e1fe"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "a7ee7f34-3bd1-427f-9231-f941e9b7e1fe" nocase ascii wide
		$clsid1 = "Object.Microsoft.DXTFilterCollection" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IUserIdentityManager {
	meta:
		description = "COM obj IID_IUserIdentityManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/dblock/dotnetinstaller/blob/master/ThirdParty/Microsoft/Visual%20Studio%208/VC/PlatformSDK/Include/msident.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/dblock/dotnetinstaller/blob/master/ThirdParty/Microsoft/Visual%20Studio%208/VC/PlatformSDK/Include/msident.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://social.msdn.microsoft.com/Forums/vstudio/en-US/95804fa3-282b-4dfd-a0fc-da0ee0bf4189/where-is-searchguidsh?forum=windowsdesktopsearchdevelopment"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://www.winehq.org/pipermail/wine-cvs/2009-January/051255.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://cryptome.org/0002/cslid-list-08.htm"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "adc6cb82-424c-11d2-952a-00c04fa34f05" nocase ascii wide
		$clsid1 = "DXImageTransform.Microsoft.Alpha" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IDelegateFolder {
	meta:
		description = "COM obj IID_IDelegateFolder"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.codeproject.com/Articles/1840/Namespace-Extensions-the-IDelegateFolder-mystery"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-afba6b42-5692-48ea-8141-dc517dcf0ef1"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "afba6b42-5692-48ea-8141-dc517dcf0ef1" nocase ascii wide
		$clsid1 = "Msxml2.ServerXMLHTTP" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_IFontCache {
	meta:
		description = "COM obj CLSID_IFontCache"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-b0d17fc2-7bc4-11d1-bdfa-00c04fa31009"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/mimeole.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iclassfactory2.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/DShowIDL/dxtrans.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.sevenforums.com/general-discussion/162931-cant-find-vbscript-engine.html"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "b54f3741-5b07-11cf-a4b0-00aa004a55e8" nocase ascii wide
		$clsid1 = "VBScript" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_INetFwAuthorizedApplication {
	meta:
		description = "COM obj INetFwAuthorizedApplication"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.teamfoundation.common.inetfwauthorizedapplication(v=vs.120).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/accessibility.caccpropservicesclass(v=vs.110).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iolecommandtarget.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://support.microsoft.com/en-us/kb/934704"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://answers.microsoft.com/en-us/windows/forum/windows_xp-performance/dcom-error-10010-very-slow-login-very-slow-desktop/4614ae6d-93cd-45e6-b66a-cbde1db13f90?db=5"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://stackoverflow.com/questions/4744105/parse-and-execute-js-by-c-sharp"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.cgplusplus.com/online-reference/maxscript-reference/source/listview_activex_control.htm"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "bdd1f04b-858b-11d1-b16a-00c0f0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.ListViewCtrl" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_INetConnectionManager {
	meta:
		description = "COM obj IID_INetConnectionManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/NetCon.Idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c1ee01f2-b3b6-4a6a-9ddd-e988c088ec82"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://fossies.org/linux/monodevelop/src/addins/WindowsPlatform/WindowsAPICodePack/Shell/Interop/Taskbar/TaskbarCOMInterfaces.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.virtualbox.org/svn/vbox/trunk/src/VBox/Devices/Graphics/shaderlib/wine/include/mimeole.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c605507b-9613-4756-9c07-e0d74321cb1e"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c8b522cf-5cf3-11ce-ade5-00aa0044773d"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "c8b522cf-5cf3-11ce-ade5-00aa0044773d" nocase ascii wide
		$clsid1 = "MSDAER" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_User_Account_Control_Check_Provider {
	meta:
		description = "COM obj User_Account_Control_Check_Provider"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-c8e6f269-b90a-4053-a3be-499afcec98c4"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://sourceforge.net/p/libxml2-pas/git/ci/3a8107acbdcacf53e20811adf76476cd2368ddb5/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.herdprotect.com/werconcpl.dll-8e8df93fb599eedee7ac07da76c235ddcb6c6aee.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://apt-browse.org/browse/ubuntu/trusty/universe/i386/wine1.6-dev/1%3A1.6.2-0ubuntu4/file/usr/include/wine/windows/wbemprov.h"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.fixdllfile.com/English/FirewallControlPanel.dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/conferencexp/conferencexp/blob/master/MSR.LST.MDShow/Interop/coclasses.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/CLSID/5772-ieframe_dll_shdocvw_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://forundex.ru/admin/JetAudio-Basic-229470"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/windows/desktop/ms695281(v=vs.85).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://read.pudn.com/downloads37/sourcecode/windows/120118/Microsoft%20Visual%20Studio/VC98/Include/OCMM.IDL__.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/CLSID/6407-jp2ssv_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://marc.info/?l=metasploit-framework&m=136872390501333&w=2"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-interface-dcb00000-570f-4a9b-8d69-199fdba5723b"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://social.technet.microsoft.com/Forums/windowsserver/en-US/e1acf5d3-2bd0-4393-928f-561bfbe9fa96/api-inetworklistmanager-in-powershell?forum=winserverpowershell"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/SubtitleEdit/subtitleedit/blob/master/libse/DetectEncoding/Multilang/IMLangFontLink2.cs"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://code.google.com/p/subtitleedit/source/browse/trunk/src/Logic/DetectEncoding/Multilang/IMultiLanguage2.cs?r=137"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.geoffchappell.com/studies/windows/ie/browseui/classes/userassist.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.bleepingcomputer.com/forums/t/396365/dcom-1084-error/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-de77ba04-3c92-4d11-a1a5-42352a53e0e3"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.medbase.ca/download/VFOXPRO9.0/WCU/SETUP.SDB"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://markswinkels.nl/2012/08/remove-duplicate-personal-folders-within-windows-2008-r2-when-using-folder-redirection/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-e436ebb1-524f-11ce-9f53-0020af0ba770"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/aa645736(v=vs.71).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://forums.malwarebytes.org/index.php?/topic/64083-is-webchecker-startup-program-a-virus/"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://windowrdb.com/w.php?w=hkcr-clsid-e70c92a9-4bfd-11d1-8a95-00c04fb951f3"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/nihon-tc/Rtest/blob/master/header/Microsoft%20SDKs/Windows/v7.0A/Include/msoeapi.idl"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://stackoverflow.com/questions/34317985/how-to-use-iautocomplete-together-with-tstringsadapter"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://social.msdn.microsoft.com/Forums/vstudio/en-US/a5e756a4-89a9-4afb-8ce4-0c572fba6eaf/how-to-implement-ideskband2-interface-in-c?forum=clr"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://ftp.fstp.ir/Categories/Programing/Microsoft%20Visual%20Basic%202005%20Express%20Edition/setup.sdb"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://assab.cs.washington.edu/cct/Misc/RecordingServer/RecordingServerService/FirewallUtility.cs"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "ec9846b3-2762-4a6b-a214-6acb603462d2" nocase ascii wide
		$clsid1 = "HNetCfg.FwAuthorizedApplication" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MyDocs_Copy_Hook {
	meta:
		description = "COM obj MyDocs_Copy_Hook"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "http://www.shouldiblockit.com/mydocs.dll-5ba1486116ece4d10c1b6ea4c6086b5f.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://support.microsoft.com/en-us/kb/321924"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "ed8c108e-4349-11d2-91a4-00c04f7969e8" nocase ascii wide
		$clsid1 = "Microsoft.XMLHTTP" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IID_IShellMenu {
	meta:
		description = "COM obj IID_IShellMenu"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://www.autoitscript.com/forum/topic/145473-the-favorites-menu/"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/cc250755.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://stackoverflow.com/questions/7167690/what-is-the-progid-or-clsid-for-ie9s-javascript-engine-code-named-chakra"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "f414c260-6ac0-11cf-b6d1-00aa00bbbb58" nocase ascii wide
		$clsid1 = "JScript" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument30 {
	meta:
		description = "COM obj CLSID_DOMDocument30"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms766426(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "f5078f32-c551-11d3-89b9-0000f81fe221" nocase ascii wide
		$clsid1 = "Msxml2.DOMDocument" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_DOMDocument {
	meta:
		description = "COM obj CLSID_DOMDocument"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms766426(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "f6d90f11-9c73-11d3-b32e-00c04f990bb4" nocase ascii wide
		$clsid1 = "Msxml2.DOMDocument" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_CLSID_XMLHTTP {
	meta:
		description = "COM obj CLSID_XMLHTTP"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/ms766426(v=vs.85).aspx"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "f6d90f16-9c73-11d3-b32e-00c04f990bb4" nocase ascii wide
		$clsid1 = "Msxml2.XMLHTTP" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_Forms_2_1_Toolbox {
	meta:
		description = "COM obj Microsoft_Forms_2.1_Toolbox"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://www.wikispaces.com/file/view/cc_20100727_220557.reg"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.teamfoundation.common.inetfwmgr(v=vs.120).aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/nihilus/GUID-Finder/blob/master/GUID-Finder/Interfaces.txt"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/O9/287-msmsgs_exe.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.systemlookup.com/O21/242-SystemRoot_system32_SHELL32_dll.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://www.windowrdb.com/w.php?w=hkcr-clsid-fbf23b40-e3f0-101b-8488-00aa003e56f8"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "fbf23b40-e3f0-101b-8488-00aa003e56f8" nocase ascii wide
		$clsid1 = "InternetShortcut" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_IObjectWithSite {
	meta:
		description = "COM obj IObjectWithSite"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://msdn.microsoft.com/en-us/library/microsoft.visualstudio.ole.interop.iobjectwithsite.aspx"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://doxygen.reactos.org/d0/daa/imnact_8idl_source.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "http://doxygen.reactos.org/d4/d2f/inetcomm_8idl_source.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://www.playonlinux.com/en/issue-1628.html"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://autohotkey.com/docs/misc/CLSID-List.htm"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00000303-0000-0000-C000-000000000046" nocase ascii wide
		//$clsid1 = "file" nocase ascii wide //more false positive
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Item_Moniker {
	meta:
		description = "COM obj Item_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0000031a-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "clsid" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ADODB_RecordSet {
	meta:
		description = "COM obj ADODB_RecordSet"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00000535-0000-0010-8000-00AA006D2EA4" nocase ascii wide
		$clsid1 = "ADODB.Recordset" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OutlookAttachMoniker {
	meta:
		description = "COM obj OutlookAttachMoniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020810-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.Sheet" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Chart_5 {
	meta:
		description = "COM obj Excel_Chart_5"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020811-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.Chart" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Sheet_8 {
	meta:
		description = "COM obj Excel_Sheet_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020820-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.Sheet" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Chart_8 {
	meta:
		description = "COM obj Excel_Chart_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020821-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.Chart" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_Sheet_12 {
	meta:
		description = "COM obj Excel_Sheet_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020830-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.Sheet" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_SheetMacroEnabled_12 {
	meta:
		description = "COM obj Excel_SheetMacroEnabled_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020832-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.SheetMacroEnabled" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Excel_SheetBinaryMacroEnabled_12 {
	meta:
		description = "COM obj Excel_SheetBinaryMacroEnabled_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020833-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Excel.SheetBinaryMacroEnabled" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Word_Document_6 {
	meta:
		description = "COM obj Word_Document_6"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020900-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Word.Document" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Word_Document_8 {
	meta:
		description = "COM obj Word_Document_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00020906-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Word.Document" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj1 {
	meta:
		description = "COM obj OLE_pobj1"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00021401-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "lnkfile" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Equation_2_0 {
	meta:
		description = "COM obj Equation_2_0"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "00021700-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Equation" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj2 {
	meta:
		description = "COM obj OLE_pobj2"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0002CE02-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Equation" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MathType_Equation {
	meta:
		description = "COM obj MathType_Equation"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0003000B-0000-0000-C000-000000000046" nocase ascii wide
		$clsid1 = "Equation" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj4 {
	meta:
		description = "COM obj OLE_pobj4"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "048EB43E-2059-422F-95E0-557DA96038AF" nocase ascii wide
		$clsid1 = "PowerPoint.Slide" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_otkloadr_WRLoader {
	meta:
		description = "COM obj otkloadr_WRLoader"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "05741520-C4EB-440A-AC3F-9643BBC9F847" nocase ascii wide
		$clsid1 = "otkloadr.WRLoader" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scripletfile {
	meta:
		description = "COM obj scripletfile"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "06290BD2-48AA-11D2-8432-006008C3FBFC" nocase ascii wide
		$clsid1 = "Scriptlet.Factory" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Script_Moniker {
	meta:
		description = "COM obj Script_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "06290BD3-48AA-11D2-8432-006008C3FBFC" nocase ascii wide
		//$clsid1 = "script" nocase ascii wide //more false positive
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll2 {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0CF774D0-F077-11D1-B1BC-00C04F86C324" nocase ascii wide
		$clsid1 = "HTML.HostEncode" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0D43FE01-F093-11CF-8940-00A0C9054228" nocase ascii wide
		$clsid1 = "Scripting.FileSystemObject" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSScriptControl_ScriptControl {
	meta:
		description = "COM obj MSScriptControl_ScriptControl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "0E59F1D5-1FBE-11D0-8FF2-00A0D10038BC" nocase ascii wide
		$clsid1 = "MSScriptControl.ScriptControl" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_BCSAddin_Connect {
	meta:
		description = "COM obj BCSAddin_Connect"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "1D8A9B47-3A28-4CE2-8A4B-BD34E45BCEEB" nocase ascii wide
		$clsid1 = "UPnP.DescriptionDocument" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_TabStrip {
	meta:
		description = "COM obj MSCOMCTL_TabStrip"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "1EFB6596-857C-11D1-B16A-00C0F0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.TabStrip" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shockwave_Control_Objects {
	meta:
		description = "COM obj Shockwave_Control_Objects"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "3050F4D8-98B5-11CF-BB82-00AA00BDCE0B" nocase ascii wide
		$clsid1 = "htafile" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_osf_SandboxManager {
	meta:
		description = "COM obj osf_SandboxManager"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "41B9BE05-B3AF-460C-BF0B-2CDD44A093B1" nocase ascii wide
		$clsid1 = "Search.XmlContentFilter" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Device {
	meta:
		description = "COM obj Device"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "4315D437-5B8C-11D0-BD3B-00A0C911CE86" nocase ascii wide
		$clsid1 = "device" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Control_TaskSymbol {
	meta:
		description = "COM obj Control_TaskSymbol"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "44F9A03B-A3EC-4F3B-9364-08E0007F21DF" nocase ascii wide
		$clsid1 = "Control.TaskSymbol" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_MultiPage {
	meta:
		description = "COM obj Forms_MultiPage"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "46E31370-3F7A-11CE-BED6-00AA00611080" nocase ascii wide
		$clsid1 = "Forms.MultiPage" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_Image {
	meta:
		description = "COM obj Forms_Image"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "4C599241-6926-101B-9992-00000B65C6F9" nocase ascii wide
		$clsid1 = "Forms.Image" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2000_2002 {
	meta:
		description = "COM obj AutoCAD_2000-2002"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "64818D10-4F9B-11CF-86EA-00AA00B929E8" nocase ascii wide
		$clsid1 = "PowerPoint.Show" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Powerpoint_Slide_8 {
	meta:
		description = "COM obj Powerpoint_Slide_8"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "64818D11-4F9B-11CF-86EA-00AA00B929E8" nocase ascii wide
		$clsid1 = "PowerPoint.Slide" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_Toolbar {
	meta:
		description = "COM obj MSCOMCTL_Toolbar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "66833FE6-8583-11D1-B16A-00C0F0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.Toolbar" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2013 {
	meta:
		description = "COM obj AutoCAD_2013"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "6E182020-F460-11CE-9BCD-00AA00608E01" nocase ascii wide
		$clsid1 = "Forms.Frame" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Microsoft_VbaAddin {
	meta:
		description = "COM obj Microsoft_VbaAddin"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "799ED9EA-FB5E-11D1-B7D6-00C04FC2AAE2" nocase ascii wide
		$clsid1 = "Microsoft.VbaAddinForOutlook" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_StdHlink {
	meta:
		description = "COM obj StdHlink"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "85131630-480C-11D2-B1F9-00C04F86C324" nocase ascii wide
		$clsid1 = "JSFile.HostEncode" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_scrrun_dll4 {
	meta:
		description = "COM obj scrrun_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "85131631-480C-11D2-B1F9-00C04F86C324" nocase ascii wide
		$clsid1 = "VBSFile.HostEncode" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_ButtonBar {
	meta:
		description = "COM obj UmOutlookAddin_ButtonBar"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "8627E73B-B5AA-4643-A3B0-570EDA17E3E7" nocase ascii wide
		$clsid1 = "UmOutlookAddin.ButtonBar" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2004_2006 {
	meta:
		description = "COM obj AutoCAD_2004-2006"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "A08A033D-1A75-4AB6-A166-EAD02F547959" nocase ascii wide
		$clsid1 = "otkloadr.WRAssembly" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_vbscript_dll {
	meta:
		description = "COM obj vbscript_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "B54F3741-5B07-11CF-A4B0-00AA004A55E8" nocase ascii wide
		$clsid1 = "VBScript" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_ListViewCtrl2 {
	meta:
		description = "COM obj MSCOMCTL_ListViewCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "BDD1F04B-858B-11D1-B16A-00C0F0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.ListViewCtrl" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_ShellBrowserWindow {
	meta:
		description = "COM obj ShellBrowserWindow"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "C62A69F0-16DC-11CE-9E98-00AA00574A4F" nocase ascii wide
		$clsid1 = "Forms.Form" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSCOMCTL_TreeCtrl2 {
	meta:
		description = "COM obj MSCOMCTL_TreeCtrl"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "C74190B6-8589-11D1-B16A-00C0F0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.TreeCtrl" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_RoomsCTP {
	meta:
		description = "COM obj UmOutlookAddin_RoomsCTP"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "CF4F55F4-8F87-4D47-80BB-5808164BB3F8" nocase ascii wide
		$clsid1 = "PowerPoint.Show" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Shockwave_Flash_Object {
	meta:
		description = "COM obj Shockwave_Flash_Object"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "D50FED35-0A08-4B17-B3E0-A8DD0EDE375D" nocase ascii wide
		$clsid1 = "UmOutlookAddin.PlayOnPhoneDlg" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Forms_2_0 {
	meta:
		description = "COM obj Forms_2_0"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "D7053240-CE69-11CD-A777-00DD01143C57" nocase ascii wide
		$clsid1 = "Forms.CommandButton" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_AutoCAD_2010_2012 {
	meta:
		description = "COM obj AutoCAD_2010-2012"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "DD9DA666-8594-11D1-B16A-00C0F0283628" nocase ascii wide
		$clsid1 = "MSComctlLib.ImageComboCtl" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Silverlight_Objects {
	meta:
		description = "COM obj Silverlight_Objects"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "E5CA59F5-57C4-4DD8-9BD6-1DEEEDD27AF4" nocase ascii wide
		$clsid1 = "InkEd.InkEdit" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_MSDAORA_1 {
	meta:
		description = "COM obj MSDAORA_1"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "E8CC4CBE-FDFF-11D0-B865-00A0C9081C1D" nocase ascii wide
		$clsid1 = "MSDAORA" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_OCI_DLL {
	meta:
		description = "COM obj Loads_OCI_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "E8CC4CBF-FDFF-11D0-B865-00A0C9081C1D" nocase ascii wide
		$clsid1 = "MSDAORA ErrorLookup" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_New_Moniker {
	meta:
		description = "COM obj New_Moniker"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "ECABAFC6-7F19-11D2-978E-0000F8757E2A" nocase ascii wide
		//$clsid1 = "new" nocase ascii wide //more false positive
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Loads_MQRT_DLL {
	meta:
		description = "COM obj Loads_MQRT_DLL"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
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
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "ECABB0C7-7F19-11D2-978E-0000F8757E2A" nocase ascii wide
		$clsid1 = "soap" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_FormRegionContext {
	meta:
		description = "COM obj UmOutlookAddin_FormRegionContext"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "ECF44975-786E-462F-B02A-CBCCB1A2C4A2" nocase ascii wide
		$clsid1 = "UmOutlookAddin.FormRegionContext" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_OLE_pobj7 {
	meta:
		description = "COM obj OLE_pobj7"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "F20DA720-C02F-11CE-927B-0800095AE340" nocase ascii wide
		//$clsid1 = "Package" nocase ascii wide // more false positive
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_jscript_dll {
	meta:
		description = "COM obj jscript_dll"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "F414C260-6AC0-11CF-B6D1-00AA00BBBB58" nocase ascii wide
		$clsid1 = "JScript" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_Word_Document_12 {
	meta:
		description = "COM obj Word_Document_12"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "F4754C9B-64F5-4B40-8AF4-679732AC0607" nocase ascii wide
		$clsid1 = "Word.Document" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}

rule COM_obj_UmOutlookAddin_FormRegionAddin {
	meta:
		description = "COM obj UmOutlookAddin_FormRegionAddin"
		author = "Lionel PRAT"
		version = "0.1"
		weight = 4
		reference = "https://github.com/decalage2/oletools/blob/master/oletools/common/clsid.py"
		ids = "win_comobj"
	    tag = "attack.execution"
	strings:
		$clsid0 = "F959DBBB-3867-41F2-8E5F-3B8BEFAA81B3" nocase ascii wide
		$clsid1 = "UmOutlookAddin.FormRegionAddin" nocase ascii wide
	condition:
		check_clsid_bool and any of ($clsid*)
}



rule ActivX_obj_1 {
    meta:
        description = "ActiveX obj Certificate Property Archived"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2037-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CCertPropertyArchived" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_2 {
    meta:
        description = "ActiveX obj CertServerPolicy Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4c4a5e40-732c-11d0-8816-00a0c903b83c" nocase ascii wide
        $clsid1 = "CertificateAuthority.ServerExit" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_3 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.ComConversionLossAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8a3fd229-b2a9-347f-93d2-87f3b7f92753" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.ComConversionLossAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_4 {
    meta:
        description = "ActiveX obj X509 Attribute Archivekey"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2027-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509AttributeArchiveKey" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_5 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, RAW Disc-At-Once CD Writer"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "27354128-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftDiscFormat2RawCD" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_6 {
    meta:
        description = "ActiveX obj LexRefBilingualServiceAttribute Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "abf651a1-0f07-48df-9ff6-8b1b557669ca" nocase ascii wide
        $clsid1 = "LR.LexRefBilingualServiceAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_7 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 8"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a9d7038d-b5ed-472e-9c47-94bea90a5910" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_8 {
    meta:
        description = "ActiveX obj System.Reflection.InvalidFilterCriteriaException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7b938a6f-77bf-351c-a712-69483c91115d" nocase ascii wide
        $clsid1 = "System.Reflection.InvalidFilterCriteriaException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_9 {
    meta:
        description = "ActiveX obj System.Runtime.Remoting.Services.EnterpriseServicesHelper"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bc5062b6-79e8-3f19-a87e-f9daf826960c" nocase ascii wide
        $clsid1 = "System.Runtime.Remoting.Services.EnterpriseServicesHelper" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_10 {
    meta:
        description = "ActiveX obj OSE.DiscussionServers"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bdeadedd-c265-11d0-bced-00a0c90ab50f" nocase ascii wide
        $clsid1 = "OSE.DiscussionServers" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_11 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.TypeLibConverter"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f1c3bf79-c3e4-11d3-88e7-00902754c43a" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.TypeLibConverter" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_12 {
    meta:
        description = "ActiveX obj WCN-Config Function Discovery Provider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "375ff002-dd27-11d9-8f9c-0002b3988e81" nocase ascii wide
        $clsid1 = "FunctionDiscovery.WCNProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_13 {
    meta:
        description = "ActiveX obj TraceDataProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "03837513-098b-11d8-9414-505054503030" nocase ascii wide
        $clsid1 = "PLA.TraceDataProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_14 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.RegistrationHelper"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "89a86e7b-c229-4008-9baa-2f5c8411d7e0" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.RegistrationHelper" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_15 {
    meta:
        description = "ActiveX obj SppWmiProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "6acb028e-48c0-4a44-964c-e14567c578ba" nocase ascii wide
        $clsid1 = "SPPWMI.SppWmiProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_16 {
    meta:
        description = "ActiveX obj ModemActivation Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "00bc7eae-28d5-4310-be9f-11526a7fa37f" nocase ascii wide
        $clsid1 = "SppComApi.ModemActivation" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_17 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.AppDomainHelper"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ef24f689-14f8-4d92-b4af-d7b1f0e70fd4" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.AppDomainHelper" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_18 {
    meta:
        description = "ActiveX obj Windows Search Service Tripoli Indexer Engine"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9e175bb7-f52a-11d8-b9a5-505054503030" nocase ascii wide
        $clsid1 = "Search.TripoliIndexer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_19 {
    meta:
        description = "ActiveX obj AnimateDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca828-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimateDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_20 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.ClrObjectFactory"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabafd1-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.ClrObjectFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_21 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 4a"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "6a6f4b83-45c5-4ca9-bdd9-0d81c12295e4" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP.3.a" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_22 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvOverlaySurface"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d6-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvOverlaySurface" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_23 {
    meta:
        description = "ActiveX obj X.509 Policy Server URL Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91f3902a-217f-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509PolicyServerUrl" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_24 {
    meta:
        description = "ActiveX obj UPnPDevice Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a32552c5-ba61-457a-b59a-a2561e125e33" nocase ascii wide
        $clsid1 = "UPnP.UPnPDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_25 {
    meta:
        description = "ActiveX obj Event Publisher"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ab944620-79c6-11d1-88f9-0080c7d771bf" nocase ascii wide
        $clsid1 = "EventSystem.EventPublisher" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_26 {
    meta:
        description = "ActiveX obj BurnDevice Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "6570b2aa-1f63-4959-9d98-c12abb483dfc" nocase ascii wide
        $clsid1 = "SBEServer.BurnDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_27 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.Publish"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d8013eef-730b-45e2-ba24-874b7242c425" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.Publish" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_28 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.RNGCryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "40031115-09d2-3851-a13f-56930be48038" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.RNGCryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_29 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.InvalidOleVariantTypeException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9a944885-edaf-3a81-a2ff-6a9d5d1abfc7" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.InvalidOleVariantTypeException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_30 {
    meta:
        description = "ActiveX obj BDA Tuner Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a2e3074e-6c3d-11d3-b653-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidBDATunerDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_31 {
    meta:
        description = "ActiveX obj Utility Object for Binding Events SubObjects in Script Variables"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "577faa18-4518-445e-8f70-1473f8cf4ba4" nocase ascii wide
        $clsid1 = "MSVidCtl.MSEventBinder" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_32 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9059f30f-4eb1-4bd2-9fdc-36f43a218f4a" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_33 {
    meta:
        description = "ActiveX obj Microsoft XPS Rich Preview Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "85862eda-f507-4d5b-aca9-bb2c34a85682" nocase ascii wide
        $clsid1 = "Windows.XPSRichPreview" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_34 {
    meta:
        description = "ActiveX obj RandomDissolve"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f7f4a1b6-8e87-452f-a2d7-3077f508dbc0" nocase ascii wide
        $clsid1 = "DXImageTransform.Microsoft.RandomDissolve" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_35 {
    meta:
        description = "ActiveX obj Video Mixing Renderer 9 Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "24dc3975-09bf-4231-8655-3ee71f43837d" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidVMR9" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_36 {
    meta:
        description = "ActiveX obj EhEPGdatEventsMediator Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "afd8ea5a-2b6e-4504-b681-c6e8bad64bb6" nocase ascii wide
        $clsid1 = "EhSched.EhEPGdatEventsMediator" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_37 {
    meta:
        description = "ActiveX obj RecoveryTaskDispatchServer Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "0b3f871d-38d9-4677-8853-a247c6366483" nocase ascii wide
        $clsid1 = "eHome.RecoveryTaskDispatchServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_38 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.IISVirtualRoot"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d8013ef1-730b-45e2-ba24-874b7242c425" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.IISVirtualRoot" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_39 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.MarshalDirectiveException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "742ad1fb-b2f0-3681-b4aa-e736a3bce4e1" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.MarshalDirectiveException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_40 {
    meta:
        description = "ActiveX obj UPnPDevices Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b9e84ffd-ad3c-40a4-b835-0882ebcbaaa8" nocase ascii wide
        $clsid1 = "UPnP.UPnPDevices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_41 {
    meta:
        description = "ActiveX obj Home Networking NAT Traversal via UPnP Configuration Manager"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ae1e00aa-3fd5-403c-8a27-2bbdc30cd0e1" nocase ascii wide
        $clsid1 = "HNetCfg.NATUPnP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_42 {
    meta:
        description = "ActiveX obj DAO.PrivateDBEngine.36"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "00000101-0000-0010-8000-00aa006d2ea4" nocase ascii wide
        $clsid1 = "DAO.PrivateDBEngine" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_43 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.RegistrationServices"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "475e398f-8afa-43a7-a3be-f4ef8d6787c9" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.RegistrationServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_44 {
    meta:
        description = "ActiveX obj EapMschapv2Cfg Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2af6bcaa-f526-4803-aeb8-5777ce386647" nocase ascii wide
        $clsid1 = "EapMschapv2Cfg.EapMschapv2Cfg" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_45 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.SHA1CryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "fc13a7d5-e2b3-37ba-b807-7fa6238284d5" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.SHA1CryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_46 {
    meta:
        description = "ActiveX obj ImeKeyEventHandler Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a38f3677-32fc-4dac-99b3-d804b193d2c4" nocase ascii wide
        $clsid1 = "ImeKeyEventHandler1041" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_47 {
    meta:
        description = "ActiveX obj Server XML HTTP 3.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "afb40ffd-b609-40a3-9828-f88bbe11e4e3" nocase ascii wide
        $clsid1 = "Msxml2.ServerXMLHTTP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_48 {
    meta:
        description = "ActiveX obj Constructor for Scriptlet Event Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "06290bd9-48aa-11d2-8432-006008c3fbfc" nocase ascii wide
        $clsid1 = "ScriptletHandler.Event" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_49 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.CallConvStdcall"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bcb67d4d-2096-36be-974c-a003fc95041b" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.CallConvStdcall" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_50 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 6"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4eb2f086-c818-447e-b32c-c51ce2b30d31" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_51 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Simple Message Parser class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "86eb31ec-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.SimpleParser30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_52 {
    meta:
        description = "ActiveX obj DownloadBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3050f5be-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
        $clsid1 = "DownloadBehavior.DownloadBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_53 {
    meta:
        description = "ActiveX obj WCF/COM+ Integration Service Moniker"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ce39d6f3-dab7-41b3-9f7d-bd1cc4e92399" nocase ascii wide
        $clsid1 = /[^A-Z0-9]service[^A-Z0-9]/ nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_54 {
    meta:
        description = "ActiveX obj RDSServer.DataFactory"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9381d8f5-0288-11d0-9501-00aa00b911a5" nocase ascii wide
        $clsid1 = "RDSServer.DataFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_55 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Stream concatenation utility"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "27354125-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftStreamConcatenate" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_56 {
    meta:
        description = "ActiveX obj TokenActivation Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "0a14d3ff-ec53-450f-aa30-ffbc55be26a2" nocase ascii wide
        $clsid1 = "SppComApi.TokenActivation" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_57 {
    meta:
        description = "ActiveX obj System.DivideByZeroException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f6914a11-d95d-324f-ba0f-39a374625290" nocase ascii wide
        $clsid1 = "System.DivideByZeroException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_58 {
    meta:
        description = "ActiveX obj DxDiagProvider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a65b8071-3bfe-4213-9a5b-491da4461ca7" nocase ascii wide
        $clsid1 = "DxDiag.DxDiagProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_59 {
    meta:
        description = "ActiveX obj DeviceRect Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3050f6d4-98b5-11cf-bb82-00aa00bdce0b" nocase ascii wide
        $clsid1 = "DeviceRect.DeviceRect" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_60 {
    meta:
        description = "ActiveX obj System.Runtime.Remoting.ServerException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "db13821e-9835-3958-8539-1e021399ab6c" nocase ascii wide
        $clsid1 = "System.Runtime.Remoting.ServerException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_61 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.SafeArrayRankMismatchException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4be89ac3-603d-36b2-ab9b-9c38866f56d5" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.SafeArrayRankMismatchException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_62 {
    meta:
        description = "ActiveX obj CivicAddress Report Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d39e7bdd-7d05-46b8-8721-80cf035f57d7" nocase ascii wide
        $clsid1 = "CivicAddressReport" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_63 {
    meta:
        description = "ActiveX obj Constructor for Scriptlet Behavior Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "06290bdb-48aa-11d2-8432-006008c3fbfc" nocase ascii wide
        $clsid1 = "ScriptletHandler.Behavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_64 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.CallConvThiscall"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "46080ca7-7cb8-3a55-a72e-8e50eca4d4fc" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.CallConvThiscall" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_65 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Media Erase"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2735412b-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftDiscFormat2Erase" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_66 {
    meta:
        description = "ActiveX obj MSOLAPExtLevels Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1e083974-829f-11d3-ab5d-00c04f9407b9" nocase ascii wide
        $clsid1 = "MSOlapAdmin2.MSOLAPExtLevels" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_67 {
    meta:
        description = "ActiveX obj CADProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f91b9abc-985b-4c04-b5e7-9c7099fc2cda" nocase ascii wide
        $clsid1 = "adprovider.cadprovider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_68 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.InvalidComObjectException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a7248ec6-a8a5-3d07-890e-6107f8c247e5" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.InvalidComObjectException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_69 {
    meta:
        description = "ActiveX obj CEIPLuaElevationHelper"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "01d0a625-782d-4777-8d4e-547e6457fad5" nocase ascii wide
        $clsid1 = "CEIPLuaElevationHelper" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_70 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.OptionalAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b81cb5ed-e654-399f-9698-c83c50665786" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.OptionalAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_71 {
    meta:
        description = "ActiveX obj CWinCredProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ff8a71c2-7eb8-418b-950d-3b49f43f024f" nocase ascii wide
        $clsid1 = "wincredprovider.cwincredprovider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_72 {
    meta:
        description = "ActiveX obj Search Gatherer Log File Provider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9e175ba9-f52a-11d8-b9a5-505054503030" nocase ascii wide
        $clsid1 = "Search.GathererLogFileProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_73 {
    meta:
        description = "ActiveX obj OnlineActivation Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a4ddca2b-e73c-40c5-83b1-9f40269d0b0d" nocase ascii wide
        $clsid1 = "SppComApi.OnlineActivation" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_74 {
    meta:
        description = "ActiveX obj Microsoft StatusBar Control, version 6.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8e3867a3-8586-11d1-b16a-00c0f0283628" nocase ascii wide
        $clsid1 = "MSComctlLib.SBarCtrl" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_75 {
    meta:
        description = "ActiveX obj PortableDevice Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "728a21c5-3d9e-48d7-9810-864848f0f404" nocase ascii wide
        $clsid1 = "PortableDevice.PortableDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_76 {
    meta:
        description = "ActiveX obj Windows Search Service File Protocol Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9e175b76-f52a-11d8-b9a5-505054503030" nocase ascii wide
        $clsid1 = "Search.FileHandler" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_77 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 5"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "6ae29350-321b-42be-bbe5-12fb5270c0de" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_78 {
    meta:
        description = "ActiveX obj X509 Extension Alternative Names"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2015-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509ExtensionAlternativeNames" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_79 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.SEHException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ca805b13-468c-3a22-bf9a-818e97efa6b7" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.SEHException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_80 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.TripleDESCryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "daa132bf-1170-3d8b-a0ef-e2f55a68a91d" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.TripleDESCryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_81 {
    meta:
        description = "ActiveX obj IImeIPointSrv wrapper class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "99a73266-0cdf-4479-88af-1842cbaada22" nocase ascii wide
        $clsid1 = "IImeIPointSrv1041" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_82 {
    meta:
        description = "ActiveX obj Standard Video Renderer Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "37b03543-a4c8-11d2-b634-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidVideoRenderer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_83 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Zero Stream"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "27354127-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftStreamZero" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_84 {
    meta:
        description = "ActiveX obj Shell Execute Hardware Event Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ffb8655f-81b9-4fce-b89c-9a6ba76d13e7" nocase ascii wide
        $clsid1 = "Shell.HWEventHandlerShellExecute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_85 {
    meta:
        description = "ActiveX obj IRService.IRServiceManager"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3109cfe8-dca4-4272-bd4e-605af9d675a1" nocase ascii wide
        $clsid1 = "IRService.IRServiceManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_86 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Dime Message Composer class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "86eb31df-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.DimeComposer30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_87 {
    meta:
        description = "ActiveX obj Event System"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4e14fba2-2e22-11d1-9964-00c04fbbb345" nocase ascii wide
        $clsid1 = "EventSystem.EventSystem" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_88 {
    meta:
        description = "ActiveX obj Engrave"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f515306e-0156-11d2-81ea-0000f87557db" nocase ascii wide
        $clsid1 = "DXImageTransform.Microsoft.Engrave" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_89 {
    meta:
        description = "ActiveX obj Win32_JobObject Provider Component"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7fb1d98a-f895-4761-8dc2-774969c84d10" nocase ascii wide
        $clsid1 = "JobObjectProv.JobObjectProv" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_90 {
    meta:
        description = "ActiveX obj LDAP Provider Object"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "228d9a81-c302-11cf-9aa4-00aa004a5691" nocase ascii wide
        $clsid1 = "LDAP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_91 {
    meta:
        description = "ActiveX obj System.OverflowException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4286fa72-a2fa-3245-8751-d4206070a191" nocase ascii wide
        $clsid1 = "System.OverflowException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_92 {
    meta:
        description = "ActiveX obj IEAnimBehaviorFactory Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a4639d2f-774e-11d3-a490-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.IEAnimBehaviorFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_93 {
    meta:
        description = "ActiveX obj Terminal Services Connection Manager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f9a874b6-f8a8-4d73-b5a8-ab610816828b" nocase ascii wide
        $clsid1 = "RCM.ConnectionManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_94 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.ComImportAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f1eba909-6621-346d-9ce2-39f266c9d011" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.ComImportAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_95 {
    meta:
        description = "ActiveX obj Microsoft ProgressBar Control, version 6.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "35053a22-8589-11d1-b16a-00c0f0283628" nocase ascii wide
        $clsid1 = "MSComctlLib.ProgCtrl" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_96 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvStreamSelector"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141db-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvStreamSelector" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_97 {
    meta:
        description = "ActiveX obj EvalRat Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c5c5c5f1-3abc-11d6-b25b-00c04fa0c026" nocase ascii wide
        $clsid1 = "TvRatings.EvalRat" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_98 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Soap Http Connector class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "fee17fa5-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.HttpConnector30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_99 {
    meta:
        description = "ActiveX obj MessageMover Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabb0bf-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "QC.MessageMover" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_100 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 4"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7584c670-2274-4efb-b00b-d6aaba6d3850" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_101 {
    meta:
        description = "ActiveX obj System.Runtime.Serialization.FormatterConverter"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d23d2f41-1d69-3e03-a275-32ae381223ac" nocase ascii wide
        $clsid1 = "System.Runtime.Serialization.FormatterConverter" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_102 {
    meta:
        description = "ActiveX obj Microsoft OLE DB Service Component Data Links"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2206cdb2-19c1-11d1-89e0-00c04fd7a829" nocase ascii wide
        $clsid1 = "DataLinks" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_103 {
    meta:
        description = "ActiveX obj Microsoft ImageList Control, version 6.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2c247f23-8591-11d1-b16a-00c0f0283628" nocase ascii wide
        $clsid1 = "MSComctlLib.ImageListCtrl" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_104 {
    meta:
        description = "ActiveX obj System.Runtime.Remoting.Services.TrackingServices"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e822f35c-ddc2-3fb2-9768-a2aebced7c40" nocase ascii wide
        $clsid1 = "System.Runtime.Remoting.Services.TrackingServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_105 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.SoapUtility"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "5f9a955f-aa55-4127-a32b-33496aa8a44e" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.SoapUtility" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_106 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3523c2fb-4031-44e4-9a3b-f1e94986ee7f" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_107 {
    meta:
        description = "ActiveX obj CCAPIProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e5899c7c-0fc7-499e-a262-174fd692dc9f" nocase ascii wide
        $clsid1 = "capiprovider.ccapiprovider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_108 {
    meta:
        description = "ActiveX obj ComponentServicesExtensionSnapin Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "dfffae4d-f0cf-46cd-9586-fe891237ab8a" nocase ascii wide
        $clsid1 = "COMSNAP.ComponentServicesExtensionSnapin" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_109 {
    meta:
        description = "ActiveX obj MCEMediaOutputDevice Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a8298e0c-7201-470e-84d5-728cff85bcbf" nocase ascii wide
        $clsid1 = "eHomeSchedulerService.MCEMediaOutputDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_110 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.SafeArrayTypeMismatchException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2d5ec63c-1b3e-3ee4-9052-eb0d0303549c" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.SafeArrayTypeMismatchException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_111 {
    meta:
        description = "ActiveX obj WcsPlugInService Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "69b37063-2bb6-43b5-a109-60e69a77840f" nocase ascii wide
        $clsid1 = "WcsPlugInService.WcsPlugInService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_112 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 8"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "54d38bf7-b1ef-4479-9674-1bd6ea465258" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_113 {
    meta:
        description = "ActiveX obj SBEDeviceManager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e62456f4-62ac-45cb-99de-4e0f6b6062d7" nocase ascii wide
        $clsid1 = "SBEServer.SBEDeviceManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_114 {
    meta:
        description = "ActiveX obj WPDServiceProvider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "77f7f122-20b0-4117-a2fb-059d1fc88256" nocase ascii wide
        $clsid1 = "WPDSp.WPDServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_115 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.ComUnregisterFunctionAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8f45c7ff-1e6e-34c1-a7cc-260985392a05" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.ComUnregisterFunctionAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_116 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Disc Master"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2735412e-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftDiscMaster2" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_117 {
    meta:
        description = "ActiveX obj X509 Attribute Csp Provider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e202b-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509AttributeCspProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_118 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, .ISO Image Manager utility"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ceee3b62-8f56-4056-869b-ef16917e3efc" nocase ascii wide
        $clsid1 = "IMAPI2FS.MsftIsoImageManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_119 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.RuntimeEnvironment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "78d22140-40cf-303e-be96-b3ac0407a34d" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.RuntimeEnvironment" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_120 {
    meta:
        description = "ActiveX obj WebDVD Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "011b3619-fe63-4814-8a84-15a194ce9ce3" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidWebDVD" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_121 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.SoapServerTlb"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f6b6768f-f99e-4152-8ed2-0412f78517fb" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.SoapServerTlb" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_122 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.DSACryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "673dfe75-9f93-304f-aba8-d2a86ba87d7c" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.DSACryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_123 {
    meta:
        description = "ActiveX obj DirectMusicWaveTrack"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "eed36461-9ea5-11d3-9bd1-0080c7150a74" nocase ascii wide
        $clsid1 = "Microsoft.DirectMusicWaveTrack" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_124 {
    meta:
        description = "ActiveX obj LexRefTfFunctionProvider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "5591379c-b467-4bca-b647-a438712504b0" nocase ascii wide
        $clsid1 = "LR.LexRefTfFunctionProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_125 {
    meta:
        description = "ActiveX obj wtv2dvrms Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "76fd18f9-45ac-456d-8449-e1da59b5e3d2" nocase ascii wide
        $clsid1 = "eHome.wtv2dvrms" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_126 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvStreamInfo"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141da-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvStreamInfo" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_127 {
    meta:
        description = "ActiveX obj AnimRotationDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca82e-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimRotationDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_128 {
    meta:
        description = "ActiveX obj MSOLAPLevels Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1e08396c-829f-11d3-ab5d-00c04f9407b9" nocase ascii wide
        $clsid1 = "MSOlapAdmin2.MSOLAPLevels" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_129 {
    meta:
        description = "ActiveX obj Event Subscription"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7542e960-79c7-11d1-88f9-0080c7d771bf" nocase ascii wide
        $clsid1 = "EventSystem.EventSubscription" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_130 {
    meta:
        description = "ActiveX obj DvbSiParser Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f6b96eda-1a94-4476-a85f-4d3dc7b39c3f" nocase ascii wide
        $clsid1 = "Psisdecd.DvbSiParser" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_131 {
    meta:
        description = "ActiveX obj NAP Elevated class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "677126ed-2a91-40ff-8c52-06181c064573" nocase ascii wide
        $clsid1 = "QAgent.CNapElevated" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_132 {
    meta:
        description = "ActiveX obj PhotoAcqDeviceSelectionDlg"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "00f29a34-b8a1-482c-bcf8-3ac7b0fe8f62" nocase ascii wide
        $clsid1 = "Microsoft.PhotoAcqDeviceSelectionDlg" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_133 {
    meta:
        description = "ActiveX obj Windows Media Player Device Autoplay"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "94e03510-31b9-47a0-a44e-e932ac86bb17" nocase ascii wide
        $clsid1 = "WMP.Device" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_134 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.RegistrationHelperTx"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9e31421c-2f15-4f35-ad20-66fb9d4cd428" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.RegistrationHelperTx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_135 {
    meta:
        description = "ActiveX obj Picture (Device Independent Bitmap)"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "00000316-0000-0000-c000-000000000046" nocase ascii wide
        $clsid1 = "StaticDib" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_136 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.SoapClientImport"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "346d5b9f-45e1-45c0-aadf-1b7d221e9063" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.SoapClientImport" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_137 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Dime Message Parser class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "86eb31e2-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.DimeParser30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_138 {
    meta:
        description = "ActiveX obj File Playback Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "37b0353c-a4c8-11d2-b634-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidFilePlaybackDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_139 {
    meta:
        description = "ActiveX obj X509 Enrollment Policy Web Service"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91f39028-217f-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509EnrollmentPolicyWebService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_140 {
    meta:
        description = "ActiveX obj TimeDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a4639d41-774e-11d3-a490-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.TimeDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_141 {
    meta:
        description = "ActiveX obj TimeExecutiveBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a4639d33-774e-11d3-a490-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.TimeExecutiveBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_142 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.ExternalException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "afc681cf-e82f-361a-8280-cf4e1f844c3e" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.ExternalException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_143 {
    meta:
        description = "ActiveX obj OLE DB Row Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ef636393-f343-11d0-9477-00c04fd36226" nocase ascii wide
        $clsid1 = "DBROWPRX.AsServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_144 {
    meta:
        description = "ActiveX obj SdrRestoreService Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "47135eea-06b6-4452-8787-4a187c64a47e" nocase ascii wide
        $clsid1 = "SdrService.SdrRestoreService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_145 {
    meta:
        description = "ActiveX obj LexRefServiceManager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "688b0d3d-af8f-483c-a712-8f4e9868b8da" nocase ascii wide
        $clsid1 = "LR.LexRefServiceManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_146 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 5a"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "54ce37e0-9834-41ae-9896-4dab69dc022b" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP.4.a" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_147 {
    meta:
        description = "ActiveX obj CrmRecoveryClerk Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabb0be-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "CrmRecoveryClerk.CrmRecoveryClerk" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_148 {
    meta:
        description = "ActiveX obj OleCvt Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "65303443-ad66-11d1-9d65-00c04fc30df6" nocase ascii wide
        $clsid1 = "OlePrn.OleCvt" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_149 {
    meta:
        description = "ActiveX obj WinNT Provider Object"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8b20cd60-0f29-11cf-abc4-02608c9e7553" nocase ascii wide
        $clsid1 = "WinNT" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_150 {
    meta:
        description = "ActiveX obj Collection of all the available BDA Tuning Model Tuning Space objects on this system"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d02aac50-027e-11d3-9d8e-00c04f72d980" nocase ascii wide
        $clsid1 = "BDATuner.SystemTuningSpaces" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_151 {
    meta:
        description = "ActiveX obj Certificate Property Archived Key Hash"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e203b-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CCertPropertyArchivedKeyHash" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_152 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvServiceInfo"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d7-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvServiceInfo" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_153 {
    meta:
        description = "ActiveX obj SppWmiTokenActivationSigner"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "cb6e2b90-25fa-4f08-b46c-696f5a2b6ca5" nocase ascii wide
        $clsid1 = "SPPWMI.SppWmiTokenActivationSigner" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_154 {
    meta:
        description = "ActiveX obj Microsoft Works Imaging Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "00e1db59-6efd-4ce7-8c0a-2da3bcaad9c6" nocase ascii wide
        $clsid1 = "MicrosoftWorks.WkImgSrv.WksImagingServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_155 {
    meta:
        description = "ActiveX obj UPnPDeviceFinder Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e2085f28-feb7-404a-b8e7-e659bdeaaa02" nocase ascii wide
        $clsid1 = "UPnP.UPnPDeviceFinder" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_156 {
    meta:
        description = "ActiveX obj MSOLAPExtLevel Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1e083975-829f-11d3-ab5d-00c04f9407b9" nocase ascii wide
        $clsid1 = "MSOlapAdmin2.MSOLAPExtLevel" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_157 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.CompilerGlobalScopeAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4b601364-a04b-38bc-bd38-a18e981324cf" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.CompilerGlobalScopeAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_158 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.InAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "96a058cd-faf7-386c-85bf-e47f00c81795" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.InAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_159 {
    meta:
        description = "ActiveX obj ServerDataCollectorSet"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "03837546-098b-11d8-9414-505054503030" nocase ascii wide
        $clsid1 = "PLA.SystemDataCollectorSet" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_160 {
    meta:
        description = "ActiveX obj RecoveryTaskMonitor Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a5cf917a-0f75-4b29-a0a0-5348e501da59" nocase ascii wide
        $clsid1 = "eHome.RecoveryTaskMonitor" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_161 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.NativeCppClassAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c437ab2e-865b-321d-ba15-0c8ec4ca119b" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.NativeCppClassAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_162 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Standard Data Writer"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2735412a-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftDiscFormat2Data" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_163 {
    meta:
        description = "ActiveX obj IETimeBehaviorFactory Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a4639d29-774e-11d3-a490-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.IETimeBehaviorFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_164 {
    meta:
        description = "ActiveX obj DeviceHostICSSupport Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "797a9bb1-9e49-4e63-afe1-1b45b9dc8162" nocase ascii wide
        $clsid1 = "UPnP.DeviceHostICSSupport" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_165 {
    meta:
        description = "ActiveX obj System.Runtime.Remoting.InternalRemotingServices"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "53a3c917-bb24-3908-b58b-09ecda99265f" nocase ascii wide
        $clsid1 = "System.Runtime.Remoting.InternalRemotingServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_166 {
    meta:
        description = "ActiveX obj CommandDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "5dc20347-0a84-11d4-a4ee-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.CommandDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_167 {
    meta:
        description = "ActiveX obj BDA Data Services Feature Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "334125c0-77e5-11d3-b653-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidDataServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_168 {
    meta:
        description = "ActiveX obj COM+ Event Notification Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabafbc-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "EventPublisher.EventPublisher" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_169 {
    meta:
        description = "ActiveX obj AnimSetDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca832-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimSetDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_170 {
    meta:
        description = "ActiveX obj AnimMotionDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca82c-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimMotionDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_171 {
    meta:
        description = "ActiveX obj PortableDeviceFTM Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f7c0039a-4762-488a-b4b3-760ef9a1ba9b" nocase ascii wide
        $clsid1 = "PortableDeviceFTM.PortableDeviceFTM" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_172 {
    meta:
        description = "ActiveX obj KernelTraceProvider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9877d8a7-fda1-43f9-aeea-f90747ea66b0" nocase ascii wide
        $clsid1 = "Krnlprov.KernelTraceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_173 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 5"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4edcb26c-d24c-4e72-af07-b576699ac0de" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_174 {
    meta:
        description = "ActiveX obj System.Runtime.Remoting.Lifetime.LifetimeServices"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8fd730c1-dd1b-3694-84a1-8ce7159e266b" nocase ascii wide
        $clsid1 = "System.Runtime.Remoting.Lifetime.LifetimeServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_175 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Audio CD Writer"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "27354129-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftDiscFormat2TrackAtOnce" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_176 {
    meta:
        description = "ActiveX obj SpStreamFormatConverter Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7013943a-e2ec-11d2-a086-00c04f8ef9b5" nocase ascii wide
        $clsid1 = "SAPI.SpStreamFormatConverter" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_177 {
    meta:
        description = "ActiveX obj PhotoAcqHWEventHandler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "00f2b433-44e4-4d88-b2b0-2698a0a91dba" nocase ascii wide
        $clsid1 = "Microsoft.PhotoAcqHWEventHandler" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_178 {
    meta:
        description = "ActiveX obj DeviceManager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e1c5d730-7e97-4d8a-9e42-bbae87c2059f" nocase ascii wide
        $clsid1 = "WIA.DeviceManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_179 {
    meta:
        description = "ActiveX obj MediaDevMgr Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "25baad81-3560-11d3-8471-00c04f79dbc0" nocase ascii wide
        $clsid1 = "MediaDevMgr.MediaDevMgr" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_180 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvTuning"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141dc-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvTuning" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_181 {
    meta:
        description = "ActiveX obj LexRefServiceContainer Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "75c11604-5c51-48b2-b786-df5e51d10ec7" nocase ascii wide
        $clsid1 = "LR.LexRefServiceContainer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_182 {
    meta:
        description = "ActiveX obj LexRefBilingualService Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "75c11604-5c51-48b2-b786-df5e51d10ec6" nocase ascii wide
        $clsid1 = "LR.LexRefBilingualService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_183 {
    meta:
        description = "ActiveX obj FaxServer Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "cda8acb0-8cf5-4f6c-9ba2-5931d40c8cae" nocase ascii wide
        $clsid1 = "FaxComEx.FaxServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_184 {
    meta:
        description = "ActiveX obj System.Security.UnverifiableCodeAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7e3393ab-2ab2-320b-8f6f-eab6f5cf2caf" nocase ascii wide
        $clsid1 = "System.Security.UnverifiableCodeAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_185 {
    meta:
        description = "ActiveX obj TraceDataProviderCollection"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "03837511-098b-11d8-9414-505054503030" nocase ascii wide
        $clsid1 = "PLA.TraceDataProviderCollection" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_186 {
    meta:
        description = "ActiveX obj ServerDataCollectorSet"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "03837531-098b-11d8-9414-505054503030" nocase ascii wide
        $clsid1 = "PLA.ServerDataCollectorSet" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_187 {
    meta:
        description = "ActiveX obj ExecutivePlatform"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b3fd5602-eb0f-415e-9f32-75da391d6bf9" nocase ascii wide
        $clsid1 = "MMC.ExecutivePlatform" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_188 {
    meta:
        description = "ActiveX obj Standard Audio Renderer Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "37b03544-a4c8-11d2-b634-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidAudioRenderer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_189 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.PreserveSigAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "204d5a28-46a0-3f04-bd7c-b5672631e57f" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.PreserveSigAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_190 {
    meta:
        description = "ActiveX obj Microsoft Slider Control, version 6.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f08df954-8592-11d1-b16a-00c0f0283628" nocase ascii wide
        $clsid1 = "MSComctlLib.Slider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_191 {
    meta:
        description = "ActiveX obj Windows Search Service Media Center Namespace Extension Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "98d99750-0b8a-4c59-9151-589053683d73" nocase ascii wide
        $clsid1 = "MediaCenterHandler.ShellFolder" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_192 {
    meta:
        description = "ActiveX obj System.InvalidOperationException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9546306b-1b68-33af-80db-3a9206501515" nocase ascii wide
        $clsid1 = "System.InvalidOperationException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_193 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.ComRegisterFunctionAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "630a3ef1-23c6-31fe-9d25-294e3b3e7486" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.ComRegisterFunctionAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_194 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.ComManagedImportUtil"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3b0398c9-7812-4007-85cb-18c771f2206f" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.ComManagedImportUtil" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_195 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 3a"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "971127bb-259f-48c2-bd75-5f97a3331551" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP.2.a" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_196 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 7"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7390f3d8-0439-4c05-91e3-cf5cb290c3d0" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_197 {
    meta:
        description = "ActiveX obj iTvHost Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141b3-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "eHome.iTvHost" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_198 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.BackgroundImageFactory"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d4-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.BackgroundImageFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_199 {
    meta:
        description = "ActiveX obj CImeCommandAvailabilityView_JK Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9f75fdc4-0aba-4866-88a9-75ebb9e7d584" nocase ascii wide
        $clsid1 = "IMEAPI.CImeCommandAvailabilityViewJK" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_200 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Raw CD Image Creator"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "25983561-9d65-49ce-b335-40630d901227" nocase ascii wide
        $clsid1 = "IMAPI2.MsftRawCDImageCreator" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_201 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, PRNG based stream"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "27354126-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftStreamPrng001" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_202 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.RegistrationConfig"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "36dcda30-dc3b-4d93-be42-90b2d74c64e7" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.RegistrationConfig" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_203 {
    meta:
        description = "ActiveX obj Windows Search Service Office Outlook Protocol Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9e175baf-f52a-11d8-b9a5-505054503030" nocase ascii wide
        $clsid1 = "Search.MAPI2Handler" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_204 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.AssemblyLocator"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "458aa3b5-265a-4b75-bc05-9bea4630cf18" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.AssemblyLocator" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_205 {
    meta:
        description = "ActiveX obj SdoService Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bc94d813-4d7f-11d2-a8c9-00aa00a71dca" nocase ascii wide
        $clsid1 = "IAS.SdoService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_206 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.AudioClipFactory"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d2-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.AudioClipFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_207 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.RSACryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d9035152-6b1f-33e3-86f4-411cd21cde0e" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.RSACryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_208 {
    meta:
        description = "ActiveX obj System.Runtime.Hosting.ApplicationActivator"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1d09b407-a97f-378a-accb-82ca0082f9f3" nocase ascii wide
        $clsid1 = "System.Runtime.Hosting.ApplicationActivator" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_209 {
    meta:
        description = "ActiveX obj Wave"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "adc6cb88-424c-11d2-952a-00c04fa34f05" nocase ascii wide
        $clsid1 = "DXImageTransform.Microsoft.Wave" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_210 {
    meta:
        description = "ActiveX obj X509 Attribute Archivekeyhash"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2028-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509AttributeArchiveKeyHash" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_211 {
    meta:
        description = "ActiveX obj RecordingEventsMediator Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "33d8c85a-b8c1-4828-b51a-4f3349ad5f9e" nocase ascii wide
        $clsid1 = "EhSched.RecordingEventsMediator" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_212 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.IDispatchConstantAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e947a0b0-d47f-3aa3-9b77-4624e0f3aca4" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.IDispatchConstantAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_213 {
    meta:
        description = "ActiveX obj PortableDeviceClassExtension Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4cadfae1-5512-456a-9d65-5b5e7e9ca9a3" nocase ascii wide
        $clsid1 = "PortableDeviceClassExtension.PortableDeviceClassExtension" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_214 {
    meta:
        description = "ActiveX obj System.InvalidProgramException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91591469-efef-3d63-90f9-88520f0aa1ef" nocase ascii wide
        $clsid1 = "System.InvalidProgramException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_215 {
    meta:
        description = "ActiveX obj PortableDeviceServiceFTM Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1649b154-c794-497a-9b03-f3f0121302f3" nocase ascii wide
        $clsid1 = "PortableDeviceServiceFTM.PortableDeviceServiceFTM" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_216 {
    meta:
        description = "ActiveX obj UpdateServiceManager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f8d253d9-89a4-4daa-87b6-1168369f0b21" nocase ascii wide
        $clsid1 = "Microsoft.Update.ServiceManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_217 {
    meta:
        description = "ActiveX obj X.509 Policy Server List Manager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91f39029-217f-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509PolicyServerListManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_218 {
    meta:
        description = "ActiveX obj CDPAPIProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b6dc98b1-0bec-45e1-b2e4-3a2d943f0be4" nocase ascii wide
        $clsid1 = "dpapiprovider.cdpapiprovider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_219 {
    meta:
        description = "ActiveX obj Windows Search Service Client Side Cache Protocol Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a373f500-7a87-11d3-b1c1-00c04f68155c" nocase ascii wide
        $clsid1 = "Search.CscHandler" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_220 {
    meta:
        description = "ActiveX obj Microsoft Office 2007 Access Database Engine Conflict Resolver"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c33b33e1-e069-44eb-a9a5-bbf72268ac5e" nocase ascii wide
        $clsid1 = "AceCnfViewer.Wizard" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_221 {
    meta:
        description = "ActiveX obj Output Devices Collection Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c5702ccd-9b79-11d3-b654-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidOutputDevices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_222 {
    meta:
        description = "ActiveX obj McxRemoteDvrPlayer Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "188db6a1-5b9a-489e-bb92-0f900822ac9d" nocase ascii wide
        $clsid1 = "eHome.McxRemoteDvrPlayer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_223 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvMediaCenterSettings"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141de-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvMediaCenterSettings" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_224 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Simple Message Composer class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "86eb31eb-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.SimpleComposer30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_225 {
    meta:
        description = "ActiveX obj System.Collections.CaseInsensitiveHashCodeProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "47d3c68d-7d85-3227-a9e7-88451d6badfc" nocase ascii wide
        $clsid1 = "System.Collections.CaseInsensitiveHashCodeProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_226 {
    meta:
        description = "ActiveX obj CServiceConfig Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabb0c8-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "COMSVCS.CServiceConfig" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_227 {
    meta:
        description = "ActiveX obj OAVMediaDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3408c281-eaea-11d3-a4dc-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.OAVMediaDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_228 {
    meta:
        description = "ActiveX obj System.EventArgs"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3fb717af-9d21-3016-871a-df817abddd51" nocase ascii wide
        $clsid1 = "System.EventArgs" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_229 {
    meta:
        description = "ActiveX obj MapiCvt Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "0006f085-0000-0000-c000-000000000046" nocase ascii wide
        $clsid1 = "MapiCvt.MapiCvt" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_230 {
    meta:
        description = "ActiveX obj FunctionDiscovery Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c72be2ec-8e90-452c-b29a-ab8ff1c071fc" nocase ascii wide
        $clsid1 = "FunctionDiscovery.Discovery" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_231 {
    meta:
        description = "ActiveX obj CDvb Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "abba0006-3075-11d6-88a4-00b0d0200f88" nocase ascii wide
        $clsid1 = "Psisdecd.CDvb" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_232 {
    meta:
        description = "ActiveX obj CivicAddressReportFactory Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2a11f42c-3e81-4ad4-9cbe-45579d89671a" nocase ascii wide
        $clsid1 = "LocationDisp.CivicAddressReportFactory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_233 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.DESCryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b6eb52d5-bb1c-3380-8bca-345ff43f4b04" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.DESCryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_234 {
    meta:
        description = "ActiveX obj System.IO.DriveNotFoundException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a8f9f740-70c9-30a7-937c-59785a9bb5a4" nocase ascii wide
        $clsid1 = "System.IO.DriveNotFoundException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_235 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Data Encoder Factory class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "86eb31e8-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.DataEncoderFactory30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_236 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvSession"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d8-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvSession" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_237 {
    meta:
        description = "ActiveX obj InkDivider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8854f6a0-4683-4ae7-9191-752fe64612c3" nocase ascii wide
        $clsid1 = "msinkdiv.InkDivider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_238 {
    meta:
        description = "ActiveX obj Convolution"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2bc0ef29-e6ba-11d1-81dd-0000f87557db" nocase ascii wide
        $clsid1 = "DXImageTransform.Microsoft.Convolution" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_239 {
    meta:
        description = "ActiveX obj DirectSoundI3DL2ReverbDMO"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ef985e71-d5c7-42d4-ba4d-2d073e2e96f4" nocase ascii wide
        $clsid1 = "Microsoft.DirectSoundI3DL2ReverbDMO" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_240 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.IUnknownConstantAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "590e4a07-dafc-3be7-a178-da349bba980b" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.IUnknownConstantAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_241 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.OutAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "fdb2dc94-b5a0-3702-ae84-bbfa752acb36" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.OutAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_242 {
    meta:
        description = "ActiveX obj Alternative Name Collection"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2014-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CAlternativeNames" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_243 {
    meta:
        description = "ActiveX obj NCProvider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "29f06f0c-fb7f-44a5-83cd-d41705d5c525" nocase ascii wide
        $clsid1 = "NCProv.NCProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_244 {
    meta:
        description = "ActiveX obj SpWaveFormatEx Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c79a574c-63be-44b9-801f-283f87f898be" nocase ascii wide
        $clsid1 = "SAPI.SpWaveFormatEx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_245 {
    meta:
        description = "ActiveX obj ERCLuaElevationHelper"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4bc67f23-d805-4384-bca3-6f1edff50e2c" nocase ascii wide
        $clsid1 = "ERCLuaElevationHelper" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_246 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.Pvr.Service.PvrService"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91081579-ee4d-4991-9451-e1725a9df347" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.Pvr.Service.PvrService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_247 {
    meta:
        description = "ActiveX obj Windows Mail Envelope"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a08af898-c2a3-11d1-be23-00c04fa31009" nocase ascii wide
        $clsid1 = "WindowsMail.Envelope" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_248 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.RegistrationHelperTx"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c89ac250-e18a-4fc7-abd5-b8897b6a78a5" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.RegistrationHelperTx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_249 {
    meta:
        description = "ActiveX obj OSE.DiscussionServer"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bdeadedc-c265-11d0-bced-00a0c90ab50f" nocase ascii wide
        $clsid1 = "OSE.DiscussionServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_250 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.ClientRemotingConfig"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e7d574d5-2e51-3400-9fb6-a058f2d5b8ab" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.ClientRemotingConfig" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_251 {
    meta:
        description = "ActiveX obj IEEventListenerProxy Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1a556daa-781c-11d3-a490-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.IEEventListenerProxy" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_252 {
    meta:
        description = "ActiveX obj System.Security.Policy.Evidence"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "62545937-20a9-3d0f-b04b-322e854eacb0" nocase ascii wide
        $clsid1 = "System.Security.Policy.Evidence" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_253 {
    meta:
        description = "ActiveX obj OLE DB Rowset Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ef636391-f343-11d0-9477-00c04fd36226" nocase ascii wide
        $clsid1 = "DBRSTPRX.AsServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_254 {
    meta:
        description = "ActiveX obj ElevationConfig Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91ecfdb4-2606-43e4-8f86-e25b0cb01f1e" nocase ascii wide
        $clsid1 = "SppComApi.ElevationConfig" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_255 {
    meta:
        description = "ActiveX obj RecoveryTaskWrapper Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7fa3a1c3-3c87-40de-ac16-b6e2815a4cc8" nocase ascii wide
        $clsid1 = "eHome.RecoveryTaskWrapper" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_256 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP Port Connector Factory class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "fee17fa8-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.ConnectorFactory30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_257 {
    meta:
        description = "ActiveX obj System.Runtime.Remoting.Channels.ServerChannelSinkStack"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "5c35f099-165e-3225-a3a5-564150ea17f5" nocase ascii wide
        $clsid1 = "System.Runtime.Remoting.Channels.ServerChannelSinkStack" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_258 {
    meta:
        description = "ActiveX obj McxRemoteDvdPlayer Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4df7bc39-c84d-4c80-8950-edc1d77c9d4b" nocase ascii wide
        $clsid1 = "eHome.McxRemoteDvdPlayer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_259 {
    meta:
        description = "ActiveX obj WPD Settings Review Page Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "fabd6ea5-ae10-4e7a-b83b-5f07acc84214" nocase ascii wide
        $clsid1 = "WPD.SettingsReviewPage" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_260 {
    meta:
        description = "ActiveX obj AnimColorDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca825-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimColorDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_261 {
    meta:
        description = "ActiveX obj RASrv Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "3c3a70a7-a468-49b9-8ada-28e11fccad5d" nocase ascii wide
        $clsid1 = "RAServer.RASrv" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_262 {
    meta:
        description = "ActiveX obj System.InvalidCastException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7f6bcbe5-eb30-370b-9f1b-92a6265afedd" nocase ascii wide
        $clsid1 = "System.InvalidCastException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_263 {
    meta:
        description = "ActiveX obj Windows Theme Thumbnail Preview"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "49c407ef-78b9-4c82-a40b-2fe02f8e771d" nocase ascii wide
        $clsid1 = "Theme.ThemeThumbnail" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_264 {
    meta:
        description = "ActiveX obj SMTP OnArrival Script Host Sink Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "cd000005-8b95-11d1-82db-00c04fb1625d" nocase ascii wide
        $clsid1 = "CDO.SS_SMTPOnArrivalSink" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_265 {
    meta:
        description = "ActiveX obj COM+ Active Process Iteration Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4b2e958d-0393-11d1-b1ab-00aa00ba3258" nocase ascii wide
        $clsid1 = "Mts.MtsGrp" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_266 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, CD DVD Device Object"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2735412d-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftDiscRecorder2" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_267 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Stream interleave utility"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "27354124-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftStreamInterleave" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_268 {
    meta:
        description = "ActiveX obj RevealTrans"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "e31e87c4-86ea-4940-9b8a-5bd5d179a737" nocase ascii wide
        $clsid1 = "DXImageTransform.Microsoft.RevealTrans" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_269 {
    meta:
        description = "ActiveX obj PortableDeviceWiaCompat Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "70f98452-3c38-4271-8e76-6f444852ebc8" nocase ascii wide
        $clsid1 = "PortableDeviceWiaCompat.PortableDeviceWiaCompat" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_270 {
    meta:
        description = "ActiveX obj OWSClientEventSubscription Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bdeade3e-c265-11d0-bced-00a0c90ab50f" nocase ascii wide
        $clsid1 = "OWS.ClientEventSubscription" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_271 {
    meta:
        description = "ActiveX obj Certificate Property Enrollment Policy Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e204c-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CCertPropertyEnrollmentPolicyServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_272 {
    meta:
        description = "ActiveX obj Windows Search Service Jet Property Storage Engine"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9e175bb8-f52a-11d8-b9a5-505054503030" nocase ascii wide
        $clsid1 = "Search.JetPropStore" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_273 {
    meta:
        description = "ActiveX obj System.Runtime.InteropServices.COMException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "07f94112-a42e-328b-b508-702ef62bcc29" nocase ascii wide
        $clsid1 = "System.Runtime.InteropServices.COMException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_274 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.SoapServerVRoot"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "caa817cc-0c04-4d22-a05c-2b7e162f4e8f" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.SoapServerVRoot" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_275 {
    meta:
        description = "ActiveX obj AnimFilterDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca82a-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimFilterDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_276 {
    meta:
        description = "ActiveX obj SpPhoneConverter Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9185f743-1143-4c28-86b5-bff14f20e5c8" nocase ascii wide
        $clsid1 = "SAPI.SpPhoneConverter" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_277 {
    meta:
        description = "ActiveX obj System.StackOverflowException"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9c125a6f-eae2-3fc1-97a1-c0dceab0b5df" nocase ascii wide
        $clsid1 = "System.StackOverflowException" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_278 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.ServerWebConfig"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "31d353b3-0a0a-3986-9b20-3ec4ee90b389" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.ServerWebConfig" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_279 {
    meta:
        description = "ActiveX obj Enhanced Storage Icon Overlay Handler Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d9144dcd-e998-4eca-ab6a-dcd83ccba16d" nocase ascii wide
        $clsid1 = "EhStorShell.IconOverlayHandler" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_280 {
    meta:
        description = "ActiveX obj DirectSoundWavesReverbDMO"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "87fc0268-9a55-4360-95aa-004a1d9de26c" nocase ascii wide
        $clsid1 = "Microsoft.DirectSoundWavesReverbDMO" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_281 {
    meta:
        description = "ActiveX obj IterateDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b96f84f7-d5ab-11d3-a4ca-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.IterateDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_282 {
    meta:
        description = "ActiveX obj EvtSink Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "08f5d2f6-4ae5-486b-98e0-3e85ba6b4d11" nocase ascii wide
        $clsid1 = "Ietag.EvtSink" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_283 {
    meta:
        description = "ActiveX obj Microsoft XPS Active Document"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "5848a73d-e9c2-499e-bb92-887cabcb2bd6" nocase ascii wide
        $clsid1 = "Windows.XPSActiveDocument" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_284 {
    meta:
        description = "ActiveX obj UPnPService Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c624ba95-fbcb-4409-8c03-8cceec533ef1" nocase ascii wide
        $clsid1 = "UPnP.UPnPService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_285 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 7"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d2ea46a7-c2bf-426b-af24-e19c44456399" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_286 {
    meta:
        description = "ActiveX obj DXTFilterBehavior"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "649eec1e-b579-4e8c-bb3b-4997f8426536" nocase ascii wide
        $clsid1 = "Behavior.Microsoft.DXTFilterBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_287 {
    meta:
        description = "ActiveX obj Previous Versions"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9db7a13c-f208-4981-8353-73cc61ae2783" nocase ascii wide
        $clsid1 = "Previous.Versions" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_288 {
    meta:
        description = "ActiveX obj Alternative Name"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2013-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CAlternativeName" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_289 {
    meta:
        description = "ActiveX obj Event Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "cdbec9c0-7a68-11d1-88f9-0080c7d771bf" nocase ascii wide
        $clsid1 = "EventSystem.EventClass" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_290 {
    meta:
        description = "ActiveX obj ServerDataCollectorSetCollection"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "03837532-098b-11d8-9414-505054503030" nocase ascii wide
        $clsid1 = "PLA.ServerDataCollectorSetCollection" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_291 {
    meta:
        description = "ActiveX obj DvbSiParser Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "aff4a44b-1897-453f-b6a1-be152d0a0f75" nocase ascii wide
        $clsid1 = "ehGLID.DvbSiParser" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_292 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvStreamEvents"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d9-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvStreamEvents" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_293 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.MD5CryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d2548bf2-801a-36af-8800-1f11fbf54361" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.MD5CryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_294 {
    meta:
        description = "ActiveX obj Input Devices Collection Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c5702ccc-9b79-11d3-b654-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidInputDevices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_295 {
    meta:
        description = "ActiveX obj UPnPServices Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c0bc4b4a-a406-4efc-932f-b8546b8100cc" nocase ascii wide
        $clsid1 = "UPnP.UPnPServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_296 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvCaptionControl"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141d5-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvCaptionControl" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_297 {
    meta:
        description = "ActiveX obj Debug Dump Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabb0c4-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "Pdump.ProcessDump" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_298 {
    meta:
        description = "ActiveX obj Microsoft OLE DB Data Conversion Library"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c8b522d1-5cf3-11ce-ade5-00aa0044773d" nocase ascii wide
        $clsid1 = "MSDADC" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_299 {
    meta:
        description = "ActiveX obj SPPUIObjectInteractive Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "f87b28f1-da9a-4f35-8ec0-800efcf26b83" nocase ascii wide
        $clsid1 = "SPPUI.SPPUIObjectInteractive" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_300 {
    meta:
        description = "ActiveX obj Microsoft DirectSound Wave"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8a667154-f9cb-11d2-ad8a-0060b0575abc" nocase ascii wide
        $clsid1 = "Microsoft.DirectSoundWave" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_301 {
    meta:
        description = "ActiveX obj Microsoft.MediaCenter.iTv.CiTvVideoSurface"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "599141dd-b243-11db-8460-00123f76e1f7" nocase ascii wide
        $clsid1 = "Microsoft.MediaCenter.iTv.CiTvVideoSurface" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_302 {
    meta:
        description = "ActiveX obj EhTraceProvider Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ed233797-f47d-475e-9fca-3d549e4ddaa4" nocase ascii wide
        $clsid1 = "EhEtwServer.EhTraceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_303 {
    meta:
        description = "ActiveX obj Server XML HTTP 6.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "88d96a0b-f192-11d4-a65f-0040963251e5" nocase ascii wide
        $clsid1 = "Msxml2.ServerXMLHTTP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_304 {
    meta:
        description = "ActiveX obj Windows Live Services Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "34a19196-274e-4d75-9d30-d7a45a0a4178" nocase ascii wide
        $clsid1 = "wlsrvc.WLServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_305 {
    meta:
        description = "ActiveX obj Binary Converter"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2002-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CBinaryConverter" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_306 {
    meta:
        description = "ActiveX obj System.Security.Cryptography.RC2CryptoServiceProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "62e92675-cb77-3fc9-8597-1a81a5f18013" nocase ascii wide
        $clsid1 = "System.Security.Cryptography.RC2CryptoServiceProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_307 {
    meta:
        description = "ActiveX obj MSOLAPLevel Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1e08396d-829f-11d3-ab5d-00c04f9407b9" nocase ascii wide
        $clsid1 = "MSOlapAdmin2.MSOLAPLevel" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_308 {
    meta:
        description = "ActiveX obj CivicAddress Report Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4c596aec-8544-4082-ba9f-eb0a7d8e65c6" nocase ascii wide
        $clsid1 = "LocationDisp.DispCivicAddressReport" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_309 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.DiscardableAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "837a6733-1675-3bc9-bbf8-13889f84daf4" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.DiscardableAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_310 {
    meta:
        description = "ActiveX obj Microsoft.JScript.DebugConvert"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "432d76ce-8c9e-4eed-addd-91737f27a8cb" nocase ascii wide
        $clsid1 = "Microsoft.JScript.DebugConvert" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_311 {
    meta:
        description = "ActiveX obj ADs Provider Object (potential false positive on ADS)"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4753da60-5b71-11cf-b035-00aa006e0975" nocase ascii wide
        $clsid1 = /[^A-Z0-9]ADs[^A-Z0-9]/ nocase ascii wide //fix false positive "ADs"
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_312 {
    meta:
        description = "ActiveX obj SpNullPhoneConverter Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "455f24e9-7396-4a16-9715-7c0fdbe3efe3" nocase ascii wide
        $clsid1 = "SAPI.SpNullPhoneConverter" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_313 {
    meta:
        description = "ActiveX obj AppEventsDHTMLConnector 1.0 Object"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ade6444b-c91f-4e37-92a4-5bb430a33340" nocase ascii wide
        $clsid1 = "NODEMGR.AppEventsDHTMLConnector" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_314 {
    meta:
        description = "ActiveX obj IRService.CSetTopBox"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4f71c8b1-f8de-4773-a6cb-e507c2d5819c" nocase ascii wide
        $clsid1 = "IRService.CSetTopBox" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_315 {
    meta:
        description = "ActiveX obj PortableDeviceValues Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "0c15d503-d017-47ce-9016-7b3f978721cc" nocase ascii wide
        $clsid1 = "PortableDeviceValues.PortableDeviceValues" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_316 {
    meta:
        description = "ActiveX obj AnimTargetDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "df2efcb5-917a-11d3-a49e-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimTargetDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_317 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 4"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ace575fd-1fcf-4074-9401-ebab990fa9de" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_318 {
    meta:
        description = "ActiveX obj PortableDeviceManager Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "0af10cec-2ecd-4b92-9581-34f6ae0637f3" nocase ascii wide
        $clsid1 = "PortableDeviceManager.PortableDeviceManager" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_319 {
    meta:
        description = "ActiveX obj AccServerDocMgr Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "6089a37e-eb8a-482d-bd6f-f9f46904d16d" nocase ascii wide
        $clsid1 = "AccServerDocMgr.AccServerDocMgr" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_320 {
    meta:
        description = "ActiveX obj Microsoft Office SOAP WinInet Connector class version 3"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "fee17fa6-a46f-11d6-9500-00065b874123" nocase ascii wide
        $clsid1 = "MSOSOAP.WinInetConnector30" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_321 {
    meta:
        description = "ActiveX obj System.Management.Instrumentation.ManagedCommonProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2a7b042d-578a-4366-9a3d-154c0498458e" nocase ascii wide
        $clsid1 = "System.Management.Instrumentation.ManagedCommonProvider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_322 {
    meta:
        description = "ActiveX obj X509 Private Key"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e200c-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509PrivateKey" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_323 {
    meta:
        description = "ActiveX obj AnimScaleDHTMLBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "816ca830-8be4-11d3-a498-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimScaleDHTMLBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_324 {
    meta:
        description = "ActiveX obj CertServerPolicy Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "aa000926-ffbe-11cf-8800-00a0c903b83c" nocase ascii wide
        $clsid1 = "CertificateAuthority.ServerPolicy" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_325 {
    meta:
        description = "ActiveX obj CTrkEvntListener Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2c3e140b-7a0d-42d1-b2aa-d343500a90cf" nocase ascii wide
        $clsid1 = "COMEXPS.CTrkEvntListener" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_326 {
    meta:
        description = "ActiveX obj PortableDeviceService Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ef5db4c2-9312-422c-9152-411cd9c4dd84" nocase ascii wide
        $clsid1 = "PortableDeviceService.PortableDeviceService" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_327 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.MethodImplAttribute"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "48d0cfe7-3128-3d2c-a5b5-8c7b82b4ab4f" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.MethodImplAttribute" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_328 {
    meta:
        description = "ActiveX obj FaxServer Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d73733c8-cc80-11d0-b225-00c04fb6c2f5" nocase ascii wide
        $clsid1 = "FaxServer.FaxServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_329 {
    meta:
        description = "ActiveX obj DAO.PrivateDBEngine.120"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "6f3dd387-5af2-492b-bde2-30ff2f451241" nocase ascii wide
        $clsid1 = "DAO.PrivateDBEngine" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_330 {
    meta:
        description = "ActiveX obj IRService.IRUser"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "87dbe38c-a22e-43d3-8128-27ffa848a113" nocase ascii wide
        $clsid1 = "IRService.IRUser" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_331 {
    meta:
        description = "ActiveX obj STSServerInstance Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d3c536b8-d0ec-48ab-838f-d4cc9a281bb5" nocase ascii wide
        $clsid1 = "STSServer.STSServerInstance" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_332 {
    meta:
        description = "ActiveX obj Server XML HTTP 5.0"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "88d969eb-f192-11d4-a65f-0040963251e5" nocase ascii wide
        $clsid1 = "Msxml2.ServerXMLHTTP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_333 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.CallConvCdecl"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a3a1f076-1fa7-3a26-886d-8841cb45382f" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.CallConvCdecl" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_334 {
    meta:
        description = "ActiveX obj RecoveryTasks Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "c78a4622-a033-4dab-94e8-43de54b461f4" nocase ascii wide
        $clsid1 = "eHome.RecoveryTasks" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_335 {
    meta:
        description = "ActiveX obj System.Threading.Overlapped"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7fe87a55-1321-3d9f-8fef-cd2f5e8ab2e9" nocase ascii wide
        $clsid1 = "System.Threading.Overlapped" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_336 {
    meta:
        description = "ActiveX obj Microsoft Jet 4.0 OLE DB Provider Error Lookup"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "dee35071-506b-11cf-b1aa-00aa00b8de95" nocase ascii wide
        $clsid1 = "Microsoft.Jet.OLEDB.ErrorLookup" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_337 {
    meta:
        description = "ActiveX obj OfflineActivation Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "8a99553a-7971-4445-93b5-aaa43d1433c5" nocase ascii wide
        $clsid1 = "SppComApi.OfflineActivation" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_338 {
    meta:
        description = "ActiveX obj Microsoft Terminal Services Client Control - version 1"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a41a4187-5a86-4e26-b40a-856f9035d9cb" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_339 {
    meta:
        description = "ActiveX obj Byot Server Extended Object"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ecabb0aa-7f19-11d2-978e-0000f8757e2a" nocase ascii wide
        $clsid1 = "Byot.ByotServerEx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_340 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.ComSoapPublishError"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b0f64827-79bb-3163-b1ab-a2ea0e1fda23" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.ComSoapPublishError" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_341 {
    meta:
        description = "ActiveX obj Microsoft IMAPI v2, Write Engine"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2735412c-7f64-5b0f-8f00-5d77afbe261e" nocase ascii wide
        $clsid1 = "IMAPI2.MsftWriteEngine2" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_342 {
    meta:
        description = "ActiveX obj Allows configuration and control of the Windows Management Instrumentation (WMI) service."
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "5c659258-e236-11d2-8899-00104b2afb46" nocase ascii wide
        $clsid1 = "WMISnapinAbout" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_343 {
    meta:
        description = "ActiveX obj OWSDiscussionServers Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "bdeadeb7-c265-11d0-bced-00a0c90ab50f" nocase ascii wide
        $clsid1 = "OWS.DiscussionServers" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_344 {
    meta:
        description = "ActiveX obj AnimExecutiveBehavior Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "a4639d3f-774e-11d3-a490-00c04f6843fb" nocase ascii wide
        $clsid1 = "MsoRun.AnimExecutiveBehavior" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_345 {
    meta:
        description = "ActiveX obj User Mode Bus Driver Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "9197e04d-2b9f-4849-8bf7-75294eb5c043" nocase ascii wide
        $clsid1 = "FunctionDiscovery.UMBusDriver" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_346 {
    meta:
        description = "ActiveX obj CCNGProvider"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "b3179149-2b99-48b2-b44b-11aa2034c1a3" nocase ascii wide
        $clsid1 = "cngprovider.ccngprovider" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_347 {
    meta:
        description = "ActiveX obj PortableDeviceWMDRM Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4b6657e4-b973-46cd-9bb3-6e5ebd82448f" nocase ascii wide
        $clsid1 = "PortableDeviceWMDRM.PortableDeviceWMDRM" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_348 {
    meta:
        description = "ActiveX obj COM+ Catalog Server"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "182c40f0-32e4-11d0-818b-00a0c9231c29" nocase ascii wide
        $clsid1 = "Catsrv.CatalogServer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_349 {
    meta:
        description = "ActiveX obj Legacy Analog TV Tuner Device Segment"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "1c15d484-911d-11d2-b632-00c04f79498e" nocase ascii wide
        $clsid1 = "MSVidCtl.MSVidAnalogTunerDevice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_350 {
    meta:
        description = "ActiveX obj WindowsMediaLibrarySharingServices Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ad581b00-7b64-4e59-a38d-d2c5bf51ddb3" nocase ascii wide
        $clsid1 = "WMLSS.WindowsMediaLibrarySharingServices" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_351 {
    meta:
        description = "ActiveX obj Configure Windows Portable Device Task Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "34c219bd-85c1-4338-95e8-788a36901dc2" nocase ascii wide
        $clsid1 = "WPD.WindowsPortableDeviceTask" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_352 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control (redistributable) - version 6"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "4eb89ff4-7f78-4a0f-8b8d-2bf02e94e4b2" nocase ascii wide
        $clsid1 = "MsRDP.MsRDP" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_353 {
    meta:
        description = "ActiveX obj Certificate Property Key Provider Information"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "884e2036-217d-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CCertPropertyKeyProvInfo" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_354 {
    meta:
        description = "ActiveX obj Windows Search Service Media Center Protocol Handler"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "2eb444b3-0c42-490f-9f28-c77129aca136" nocase ascii wide
        $clsid1 = "Search.MediaCenterHandler" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_355 {
    meta:
        description = "ActiveX obj Microsoft RDP Client Control - version 2"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "7cacbd7b-0d99-468f-ac33-22e495c0afe5" nocase ascii wide
        $clsid1 = "MsTscAx.MsTscAx" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_356 {
    meta:
        description = "ActiveX obj InkOverlay Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "65d00646-cde3-4a88-9163-6769f0f1a97d" nocase ascii wide
        $clsid1 = "msinkaut.InkOverlay" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_357 {
    meta:
        description = "ActiveX obj System.Runtime.CompilerServices.CallConvFastcall"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "ed0bc45c-2438-31a9-bbb6-e2a3b5916419" nocase ascii wide
        $clsid1 = "System.Runtime.CompilerServices.CallConvFastcall" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_358 {
    meta:
        description = "ActiveX obj System.Collections.CaseInsensitiveComparer"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "35e946e4-7cda-3824-8b24-d799a96309ad" nocase ascii wide
        $clsid1 = "System.Collections.CaseInsensitiveComparer" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_359 {
    meta:
        description = "ActiveX obj speechtextservice class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "dcbd6fa8-032f-11d3-b5b1-00c04fc324a1" nocase ascii wide
        $clsid1 = "stsinproc.speechtextservice" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_360 {
    meta:
        description = "ActiveX obj X509 Enrollment Policy Active Directory"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "91f39027-217f-11da-b2a4-000e7bbb2b09" nocase ascii wide
        $clsid1 = "X509Enrollment.CX509EnrollmentPolicyActiveDirectory" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_361 {
    meta:
        description = "ActiveX obj ImeKeyEventHandler Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "95688ffa-250d-49bd-b40a-8ed3a8ef4c8e" nocase ascii wide
        $clsid1 = "ImeKeyEventHandler1042" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_362 {
    meta:
        description = "ActiveX obj System.EnterpriseServices.Internal.GenerateMetadata"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "d8013ff1-730b-45e2-ba24-874b7242c425" nocase ascii wide
        $clsid1 = "System.EnterpriseServices.Internal.GenerateMetadata" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}

rule ActivX_obj_363 {
    meta:
        description = "ActiveX obj InstallEventsMediator Class"
        author = "Lionel PRAT"
        version = "0.1"
        weight = 3
        tag = "attack.execution"
    strings:
        $clsid0 = "50d9196a-dd32-4f64-9bd1-20ab9175858e" nocase ascii wide
        $clsid1 = "EhSched.InstallEventsMediator" nocase ascii wide
    condition:
        check_clsid_bool and any of ($clsid*)
}
