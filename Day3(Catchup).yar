import "pe"

rule EXE_Ransomware_Phobos_Feb2024 {
    meta:
        Description = "Detects Phobos Ransomware that was used to attack hospitals in Romania"
        Author = "RustyNoob619"
        Reference = "https://grahamcluley.com/20-hospitals-in-romania-hit-hard-by-ransomware-attack-on-it-service-provider/"
        Hash = "396a2f2dd09c936e93d250e8467ac7a9c0a923ea7f9a395e63c375b877a399a6"
        Sample_Size = "Matches around 125 Phobos Samples"
    
    strings:
        $hex = {5c005c003f005c0055004e0043005c005c005c0065002d00}  // Represents \\?\UNC\\\e-
    condition:
        pe.imphash() == "851a0ba8fbb71710075bdfe6dcef92eb"
        and $hex
       
 }
