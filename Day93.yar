
import "pe"

rule APT_CN_Stately_Taurus_DLL_Backdoor_April2024 {
    meta:
        Description = "Detects malware used by Chinese APT Stately Taurus aka Mustang Panda targeting ASEAN entities"
        Author = "RustyNoob619"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "316541143187acff1404b98659c6d9c8566107bd652310705214777f03ea10c8"
        TTP = "This malicious DLL part of a ZIP (Package 1) which contains a legit executable that uses DLL sideloading to load this DLL"
        
    condition:
        (for any signature in pe.signatures:
            (signature.thumbprint == "b433e25212a2a52210a96da575e80ef0ac402109")
        or pe.version_info["LegalCopyright"] contains "QFX Software Corporation")

        and (pe.imphash() == "1a2edb7063fdbf7acc5a2c6a6f801ee8"
        or (pe.imports("USER32.dll","MessageBoxA")
        and pe.imports("COMDLG32.dll","ChooseColorW")
        and pe.imports("SHLWAPI.dll","SHSetValueA")))

        and pe.exports("KSInit")
        and pe.exports("KSMain")
        and pe.exports("KSOptions")
        and pe.exports("KSPromptForKey")
        and pe.exports("KSSetKeyInfo")
        and pe.exports("KSSetOption")
        and pe.exports("KSUninit")
        and pe.exports("KSSetOption")
        and pe.exports("KSUpdate")


 }
