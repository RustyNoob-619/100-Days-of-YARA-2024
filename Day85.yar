
import "pe"

rule DLL_Stealer_Strela_March2024 {
    meta:
        Description = "Detects Strela Stealer malware used in a Large-Scale Campaign in Early 2024"
        Author = "RustyNoob619"
        Reference = "https://unit42.paloaltonetworks.com/strelastealer-campaign/"
        File_Hash = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"

    strings:
        $gnu = "GNU C17 13.2.0 -march=nocona -msahf -mtune=generic -g -g -g -O2 -O2 -O2 -fPIC -fbuilding-libgcc -fno-stack-protector"
    condition:
        pe.imphash() == "c21fd41af2cf2392ca8ea5044cf42f43"
        and pe.exports("m")
        and filesize < 10MB
        and any of them 
 }













