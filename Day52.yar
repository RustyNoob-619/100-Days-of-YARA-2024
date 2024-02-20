import "vt"

rule EXE_Ransomware_Phobos_VT_Feb2024 {
    meta:
        Description = "Detects Phobos Ransomware based on File Behaviour and Malware Config using VT Live Hunt"
        Author = "RustyNoob619"
        Reference = "https://grahamcluley.com/20-hospitals-in-romania-hit-hard-by-ransomware-attack-on-it-service-provider/"
        Hash = "396a2f2dd09c936e93d250e8467ac7a9c0a923ea7f9a395e63c375b877a399a6"
        Sample_Size = "Matches around 125 Phobos Samples"
    
    condition:
        vt.metadata.new_file
        and for any malware_name in vt.metadata.malware_families:
        (malware_name == "phobos")
        or 
        (for any process in vt.behaviour.processes_created:
            (process == "C:\\Windows\\System32\\wbem\\WMIC.exe wmic  shadowcopy delete")
        and for 50 file in vt.behaviour.files_written:
            (file endswith "[backmydata@skiff.com].backmydata"))
       
 }
