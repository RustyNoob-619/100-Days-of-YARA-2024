
import "pe"

rule APT_CN__Package2_DLL_April2024 {
    meta:
        Description = "Detects malware (Package 2) used by a Chinese APT targeting ASEAN entities"
        Author = "RustyNoob619"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "5cd4003ccaa479734c7f5a01c8ff95891831a29d857757bbd7fe4294f3c5c126"
        Info = "This malicious DLL part of the SCR (Package 2) which contains a legit executable, a malicious executable and this DLL"
    
    strings:
        $str1 = "C:\\ProgramData\\updata" wide fullword
        $str2 = "estarmygame" wide

    condition:
        (pe.imphash() == "a069baeb4f8e125a451dc73aca6576b8"
        or (pe.imports("ADVAPI32.dll","RegCloseKey")
        and pe.imports("ADVAPI32.dll","RegOpenKeyExA")
        and pe.imports("KERNEL32.dll","IsProcessorFeaturePresent")
        and pe.imports("KERNEL32.dll","QueryPerformanceCounter")
        and pe.imports("KERNEL32.dll","IsDebuggerPresent")
        and pe.imports("ADVAPI32.dll","RegOpenKeyExA")
        and pe.imports("ADVAPI32.dll","RegSetValueExA")
        and pe.imports("SHELL32.dll","CommandLineToArgvW"))
        and pe.exports("RunServer"))
        and all of them

 }


rule APT_CN__Package2_EXE_April2024 {
    meta:
        Description = "Detects malware (Package 2) used by a Chinese APT targeting ASEAN entities"
        Author = "RustyNoob619"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "02f4186b532b3e33a5cd6d9a39d9469b8d9c12df7cb45dba6dcab912b03e3cb8"
        Info = "This malicious EXE part of  SCR (Package 2) which contains a legit executable, a malicious DLL and this EXE"
    
    strings:
        $str1 = "http://" wide fullword
        $str2 = "FWININET.DLL" wide fullword
        $str3 = "TKernel32.dll" wide fullword
        $str4 = "TComdlg32.dll" wide fullword

        $path1 = "C:\\Users\\Public\\EACore.dll" wide
        $path2 = "C:\\Users\\Public\\WindowsUpdate.exe" wide

        $url1 = "http://123.253.32.71/EACore.dll" wide
        $url2 = "http://123.253.32.71/WindowsUpdate.exe" wide

    condition:
        (pe.imphash() == "cf4236da1b59447c2fe49d31eb7bb6e2"
        or (pe.imports("UxTheme.dll","GetWindowTheme")
        and pe.imports("SHLWAPI.dll","PathIsUNCW")
        and pe.imports("MSIMG32.dll","AlphaBlend")
        and pe.imports("OLEACC.dll","AccessibleObjectFromWindow")
        and pe.imports("WINMM.dll","PlaySoundW")
        and pe.imports("ole32.dll","DoDragDrop")
        and pe.imports("ADVAPI32.dll","SystemFunction036")
        and pe.imports("SHELL32.dll","SHGetSpecialFolderLocation")
        and pe.imports("WINSPOOL.DRV","DocumentPropertiesW")))
        
        and (2 of ($str*)
        or any of ($path*)
        or any of ($url*))

 }

