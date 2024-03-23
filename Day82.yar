import "pe"

rule EXE_gh0st_RootKit_first_stage_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects gh0st Root Kit malware Dropper which contains an embedded second stage payload based on PE properties"
    file_hash = "f4041d6ad6fc394295bd976b45d092f4f36a90805705c048c637710f422632f0"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
  
  strings:
    $ghost1 = "Gh0st Update" fullword ascii 
    $ghost2 = "Global\\Gh0st %d" fullword ascii 
    $ghost3 = "gh0st\\server\\sys\\i386\\RESSDT.pdb"
    $ghost4 = "gh0st3.6_src\\HACKER\\i386\\HACKE.pdb"
    $ghost5 = "gh0st3.6_src\\Server\\sys\\i386\\CHENQI.pdb"
    $str1 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor"
    $str2 = "_kaspersky" fullword ascii
    $str3 = "\\.\\RESSDTDOS" fullword ascii

  condition:
    for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload
    and any of ($ghost*)
    and any of ($str*)
    
}

rule DLL_gh0st_Rootkit_second_stage_March2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects gh0st RAT which is the second stage paylaod dropped by gh0st Root kit"
    file_hash = "1a51096110781e3abdb464196fff9ecb218ccf9a897469b1a99c5ec94f5b1694"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"

  strings:
    $ghost1 = "Gh0st Update" fullword ascii 
    $ghost2 = "Global\\Gh0st %d" fullword ascii 
    $ghost3 = "gh0st\\server\\sys\\i386\\RESSDT.pdb"
    $ghost4 = "gh0st3.6_src\\HACKER\\i386\\HACKE.pdb"
    $ghost5 = "gh0st3.6_src\\Server\\sys\\i386\\CHENQI.pdb"
    $str1= "\\Device\\RESSDT"
    $str2= "\\??\\RESSDTDOS"
    $str3= "\\.\\RESSDTDOS"
    $str4= "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"

  condition:
    pe.imphash() == "5c38312da54af04f6a40592477000188"
    or (pe.imports("SHELL32.dll","SHGetSpecialFolderPathA")
    and pe.imports("SHLWAPI.dll","SHDeleteKeyA")
    and pe.imports("AVICAP32.dll","capGetDriverDescriptionA")
    and pe.imports("MSVFW32.dll","ICSendMessage")
    and pe.imports("PSAPI.DLL","EnumProcessModules")
    and pe.imports("WTSAPI32.dll","WTSFreeMemory"))
    and pe.exports("ResetSSDT")
    and pe.exports("ServiceMain")
    and pe.resources[0].language == 2052
    and any of ($ghost*)
    and any of ($str*)
    
}
