import "pe"

rule TTP_API_Functions_Defense_Evasion_Feb2024
{
    meta:
        author = "RustyNoob619"
        description = "Leverages the PE properties in YARA to identify API functions used for defense evasion"
        reference = "https://malapi.io/"
        usage = "This rule should be combined with other YARA rules to avoid firing on False Positives"

   condition:
       pe.imports("kernel32.dll","CreateFileMappingA")
       or pe.imports("kernel32.dll","DeleteFileA")
       or pe.imports("kernel32.dll","GetModuleHandleA")
       or pe.imports("kernel32.dll","GetProcAddress")
       or pe.imports("kernel32.dll","LoadLibraryA")
       or pe.imports("kernel32.dll","LoadLibraryExA")
       or pe.imports("kernel32.dll","LoadResource")
       or pe.imports("kernel32.dll","SetEnvironmentVariableA")
       or pe.imports("kernel32.dll","SetFileTime")
       or pe.imports("kernel32.dll","Sleep")
       or pe.imports("kernel32.dll","WaitForSingleObject")
       or pe.imports("kernel32.dll","SetFileAttributesA")
       or pe.imports("kernel32.dll","SleepEx")
       or pe.imports("ntdll.dll","NtDelayExecution")
       or pe.imports("ntdll.dll","NtWaitForMultipleObjects")
       or pe.imports("ntdll.dll","NtWaitForSingleObject")
       or pe.imports("user32.dll","CreateWindowExA")
       or pe.imports("ntdll.dll","RegisterHotKey")
       or pe.imports("winmm.dll","timeSetEvent")
       or pe.imports("iphlpapi.dll","IcmpSendEcho")
       or pe.imports("kernel32.dll","WaitForSingleObjectEx")
       or pe.imports("kernel32.dll","WaitForMultipleObjects")
       or pe.imports("kernel32.dll","WaitForMultipleObjectsEx")
       or pe.imports("kernel32.dll","SetWaitableTimer")
       or pe.imports("kernel32.dll","CreateTimerQueueTimer")
       or pe.imports("kernel32.dll","CreateWaitableTimer")
       or pe.imports("kernel32.dll","SetWaitableTimer")
       or pe.imports("user32.dll","SetTimer")
       or pe.imports("ws2_32.dll","Select")
       or pe.imports("advapi32.dll","ImpersonateLoggedOnUser")
       or pe.imports("advapi32.dll","SetThreadToken")
       or pe.imports("advapi32.dll","DuplicateToken")
       or pe.imports("kernel32.dll","SizeOfResource")
       or pe.imports("kernel32.dll","LockResource")
       or pe.imports("kernel32.dll","CreateProcessInternal")
       or pe.imports("winmm.dll","TimeGetTime")
       or pe.imports("kernel32.dll","EnumSystemLocalesA")
       or pe.imports("rpcrt4.dll","UuidFromStringA")
       or pe.imports("crypt32.dll","CryptProtectData")

}




