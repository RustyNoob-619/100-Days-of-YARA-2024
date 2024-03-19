import "pe"
 
rule EXE_Backdoor_Rust_Feb2024 {
    meta:
        Description = "Detects an interesting Rust based backdoor/infostealer with one matched file linked to the Spica Backdoor used by Callisto"
        Author = "RustyNoob619"
        Reference = " https://blog.google/threat-analysis-group/google-tag-coldriver-russian-phishing-malware/"
        Spica_Backdoor_Info = "Spica Backdoor is used by the Russian APT COLDRIVER aka Callisto. Currently only one sample surfacing VT"
        Spica_Backdoor_Hash = "37c52481711631a5c73a6341bd8bea302ad57f02199db7624b580058547fb5a9"
        Number_of_Matched_Files = "39 (including the Spica Backdoor)"
   
    strings:
        $rust = "/rustc/"
    condition:
        #rust > 10
        and pe.number_of_imports > 20
        and pe.imports("kernel32.dll","GetLogicalDrives")
        and pe.imports("kernel32.dll","WakeConditionVariable")
        and pe.imports("kernel32.dll","SleepConditionVariableSRW")
        and pe.imports("kernel32.dll","SetFileCompletionNotificationModes")
        and pe.imports("kernel32.dll","GetTickCount64")
        and pe.imports("advapi32.dll","LookupAccountSidW")
        and pe.imports("advapi32.dll","SystemFunction036")
        and pe.imports("ws2_32.dll","ioctlsocket")
        and pe.imports("ole32.dll","CoSetProxyBlanket")
        and pe.imports("bcrypt.dll","BCryptGenRandom")
        and pe.imports("ntdll.dll","NtDeviceIoControlFile")
        and pe.imports("ntdll.dll","NtQueryInformationProcess")
        and pe.imports("crypt32.dll","CryptUnprotectData")
        and pe.imports("psapi.dll","GetPerformanceInfo")
        and pe.imports("shell32.dll","CommandLineToArgvW")
        and pe.imports("iphlpapi.dll","GetAdaptersAddresses")
        and pe.imports("netapi32.dll","NetUserGetLocalGroups")
        and pe.imports("secur32.dll","LsaEnumerateLogonSessions")
        and pe.imports("pdh.dll","PdhCollectQueryData")
        and pe.imports("powrprof.dll","CallNtPowerInformation")
        and for 5 lib in pe.import_details:
        (lib.library_name startswith "api-ms-win-crt")
       
 }
