import "pe"

rule DLL_Stealer_Ov3rStealer_Feb2024 {
    meta:
        Description = "Detects Ov3r Stealer spread through FaceBook Ads"
        Author = "RustyNoob619"
        Reference = "https://www.trustwave.com/hubfs/Web/Library/Documents_pdf/FaceBook_Ad_Spreads_Novel_Malware.pdf"
        Hash = "c6765d92e540af845b3cbc4caa4f9e9d00d5003a36c9cb548ea79bb14c7e8f66"
    condition:
        pe.dll_name == "Dropper.dll"
        and pe.number_of_exports > 125
        and for 100 export in pe.export_details:
        (export.name startswith "Wer")
       
 }
