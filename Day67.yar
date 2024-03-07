import "pe"
import "math"

rule EXE_Unknown_Backdoor_March2024 {
    meta:
        Description = "Detects an unknown backdoor"
        Author = "RustyNoob619"
        Credits = "@naumovax for sharing the malware sample on Twitter"
        Reference = "https://twitter.com/naumovax/status/1765723034369872043"
        Hash = "ddf7b9bf24b19ee183d788f482a01e517048587e8ce21f5d32c927f6f0371824"
    
    strings:
        $str1 = "sNbUdD"
        $str2 = "U,.-.._"

    condition:
        pe.number_of_sections == 3
        and for section in pe.sections:
        (math.entropy(section.raw_data_offset, section.raw_data_size) > 7.84)
        and pe.imports("KERNEL32.DLL","VirtualAlloc")
        and pe.imports("KERNEL32.DLL","VirtualProtect")
        and pe.imports("KERNEL32.DLL","GetProcAddress")
        and pe.imports("ADVAPI32.DLL","DeleteService")
        and pe.imports("SHELL32.DLL","ShellExecuteA")
        and pe.imports("MSVCRT.DLL","printf")
        and pe.imports("WS2_32.DLL",116) // Ordinal 
        and all of them

}
