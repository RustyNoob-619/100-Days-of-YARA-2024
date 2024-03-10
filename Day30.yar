import "pe"

rule EXE_Stealer_Nightingale_Imphash_Jan2024 {
    meta:
        Description = "Detects Nightingale Stealer samples based on the import hash"
        Author = "RustyNoob619"
        Credits = "Yogesh Londhe @suyog41 for sharing the File Hash on Twitter"
        Reference = "https://twitter.com/suyog41/status/1751930165230469619"
        Hash = "c0cc6d724ac017163b40866c820fd67df6ac89924a623490ec1de2ecacf1d0219"
    
    condition:
       pe.imphash() == "b92e25fdf67d41fe9a0f94a46fd5528a"
       
 }

rule EXE_Stealer_Nightingale_Broad_Jan2024 {
    meta:
        Description = "Detects Nightingale Stealer samples based on PE properties"
        Author = "RustyNoob619"
        Credits = "Yogesh Londhe @suyog41 for sharing the File Hash on Twitter"
        Reference = "https://twitter.com/suyog41/status/1751930165230469619"
        Hash = "0cc6d724ac017163b40866c820fd67df6ac89924a623490ec1de2ecacf1d0219"
    
    condition:
        pe.import_details[1].library_name == "ucrtbase.dll"
        and for 5 function in pe.import_details[0].functions: //KERNEL32.dll
        (function.name endswith "CriticalSection" or function.name == "Sleep")
        and for 7 section in pe.sections:
        (section.full_name startswith ".debug")
       
 }
