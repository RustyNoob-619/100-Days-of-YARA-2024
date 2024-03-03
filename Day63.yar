import "pe"

rule EXE_Virus_Neshta_March2024 {
    meta:
        Description = "Detects Neshta malware which is a 2005 Belarusian file infector virus written in Delphi"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/Neshta/"
        Hash = "c1d5818fc1485e70c43d4575fd81197980602726802d61e3a0d2e0781c4b3b7f"

    strings:
        $dlph = "SOFTWARE\\Borland\\Delphi\\RTL"
        $nshta1 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus"
        $nshta2 = "Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]"
    condition:
        pe.imphash() == "9f4693fc0c511135129493f2161d1e86"
        and pe.timestamp == 708992537 // Delphi Time Stamp (1992:06:19 22:22:17+00:00)
        and pe.locale(0x0419) // Russian (RU)
        and $dlph 
        and any of ($nshta*)

 }



 




 

 


 




 

 