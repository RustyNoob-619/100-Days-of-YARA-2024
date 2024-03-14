import "pe"

rule TTP_API_Functions_Anti_Debugging_March2024
{
    meta:
        author = "RustyNoob619"
        description = "Leverages the PE properties in YARA to identify API functions used for Anti-Debugging"
        reference = "https://malapi.io/"
        usage = "This rule should be combined with other YARA rules to avoid firing on False Positives"

   condition:
       pe.imports("kernel32.dll","CreateToolhelp32Snapshot")
       or pe.imports("kernel32.dll","GetLogicalProcessorInformation")
       or pe.imports("kernel32.dll","GetLogicalProcessorInformationEx")
       or pe.imports("kernel32.dll","GetTickCount")
       or pe.imports("kernel32.dll","OutputDebugStringA")
       or pe.imports("kernel32.dll","CheckRemoteDebuggerPresent")
       or pe.imports("kernel32.dll","Sleep")
       or pe.imports("kernel32.dll","GetSystemTime")
       or pe.imports("kernel32.dll","GetComputerNameA")
       or pe.imports("kernel32.dll","SleepEx")
       or pe.imports("kernel32.dll","IsDebuggerPresent")
       or pe.imports("advapi32.dll","GetUserNameA")
       or pe.imports("ntdll.dll","NtQueryInformationProcess")
       or pe.imports("user32.dll","ExitWindowsEx")
       or pe.imports("user32.dll","FindWindowA")
       or pe.imports("user32.dll","FindWindowExA")
       or pe.imports("user32.dll","GetForegroundWindow")
       or pe.imports("kernel32.dll","GetTickCount64")
       or pe.imports("kernel32.dll","QueryPerformanceFrequency")
       or pe.imports("kernel32.dll","QueryPerformanceCounter")
       or pe.imports("kernel32.dll","GetNativeSystemInfo")
       or pe.imports("ntosKrnl.lib","RtlGetVersion")
       or pe.imports("kernel32.dll","GetSystemTimeAsFileTime")
       or pe.imports("user32.dll","CountClipboardFormats") 

}




