
import "pe"

rule EXE_gh0st_Dropper_first_stage_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects gh0st malware Dropper which contains an embedded second stage payload based on PE properties"
    file_hash = "c0721d7038ea7b1ba4db1d013ce0c1ee96106ebd74ce2862faa6dc0b4a97700d"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
  
  condition:
    (pe.pdb_path contains "gh0st"
    or pe.imphash() == "e2b4a22dd01bac62ec948d04cee8e739")
    and not pe.pdb_path contains "i386"
    and for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload 
    
}

rule DLL_gh0st_Dropper_second_stage_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects gh0st RAT which is the second stage paylaod dropped by gh0st Loader"
    file_hash = "86390c9407c61353595e43aa87475ffe96d9892cfac3324d02b374d11747184ds"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
  
  condition:
    pe.imphash() == "6fc18c74c016f984b6cb657a45d03cab"
    or (pe.imports("IMM32.dll","ImmGetContext")
    and pe.imports("WINMM.dll","mixerGetDevCapsW")
    and pe.imports("WININET.dll","InternetOpenW")
    and pe.imports("USERENV.dll","CreateEnvironmentBlock")
    and pe.imports("PSAPI.DLL","EnumProcessModules")
    and pe.imports("SHELL32.dll","ShellExecuteExW"))
    and pe.exports("Install")
    and pe.exports("Launch")
    and pe.exports("ServiceMain")
    and pe.exports("Uninstall")
    and pe.resources[0].language == 2052
    and pe.pdb_path contains "gh0st"
    and not pe.pdb_path contains "i386"
    
}
