import "pe"

rule DLL_BankingTrojan_Coyote_Feb2024 {
    meta:
        Description = "Detects Coyote malware samples based on the PE properties"
        Author = "RustyNoob619"
        Reference = "https://securelist.com/coyote-multi-stage-banking-trojan/111846/"
        Hash = "1bed3755276abd9b54db13882fcf29c543ebf604be3b7fcf060cbd6d68bcd23f"
    
    condition:
       pe.dll_name == "chrome_elf.dll"
       and pe.number_of_exports > 25 
       and for 10 export in pe.export_details:
       (export.name == "DumpHungProcessWithPtype_ExportThunk"
       or export.name == "RequestSingleCrashUpload_ExportThunk"
       or export.name == "GetCrashpadDatabasePath_ExportThunk"
       or export.name == "InjectDumpForHungInput_ExportThunk"
       or export.name == "SetUploadConsent_ExportThunk"
       or export.name == "DrainLog"
       or export.name == "GetInstallDetailsPayload"
       or export.name == "GetUniqueBlockedModulesCount"
       or export.name == "IsExtensionPointDisableSet"
       or export.name == "IsBrowserProcess"
       or export.name == "SetUploadConsent_ExportThunk"
       or export.name == "SignalChromeElf")
       
 }

