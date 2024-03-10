import "pe"
import "math"

rule EXE_Trojan_RomCom_Specific_Feb2024 {
    meta:
        Description = "Detects malware used by RomCom Threat Actor based on import hash"
        Author = "RustyNoob619"
        Credits = "Is Now on VT for notificaiton on the availiblity of the malware sample on Twitter"
        Reference = "https://twitter.com/Now_on_VT/status/1752598052819415467, https://blogs.blackberry.com/en/2023/07/romcom-targets-ukraine-nato-membership-talks-at-nato-summit"
        Hash = "1a7bb878c826fe0ca9a0677ed072ee9a57a228a09ee02b3c5bd00f54f354930f"
    
    condition:
       pe.imphash() == "48b74a60787e54387294ac125b7ed128"       
 }

 rule EXE_Trojan_RomCom_Broad_Feb2024 {
    meta:
        Description = "Detects malware used by RomCom Threat Actor based on high resource entropy and other PE Import characteristics"
        Author = "RustyNoob619"
        Credits = "Is Now on VT for notificaiton on the availiblity of the malware sample on Twitter"
        Reference = "https://twitter.com/Now_on_VT/status/1752598052819415467"
        Hash = "1a7bb878c826fe0ca9a0677ed072ee9a57a228a09ee02b3c5bd00f54f354930f"
    
    condition:
        pe.number_of_resources == 3
        and pe.number_of_imported_functions > 100
        and for any resource in pe.resources:
        (math.entropy(resource.offset, resource.length) > 7.9 and resource.type == 3 )
        and pe.imports("KERNEL32.dll", "GetStartupInfoW")
        and pe.imports("KERNEL32.dll", "GetPhysicallyInstalledSystemMemory")
        and pe.imports("KERNEL32.dll", "InitializeCriticalSectionAndSpinCount")
        and pe.imports("NETAPI32.dll", "NetUserGetInfo")
        and pe.imports("ADVAPI32.dll", "LookupAccountNameW")
        and pe.imports("ADVAPI32.dll", "ChangeServiceConfig2W")
             
 }

