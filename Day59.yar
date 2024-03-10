
import "pe"

rule DLL_RAT_Xeno_Feb2024 {
    meta:
        Description = "Detects Xeno RAT malware based on PE properties"
        Author = "RustyNoob619"
        Reference = "https://www.cyfirma.com/outofband/xeno-rat-a-new-remote-access-trojan-with-advance-capabilities/"
        Hash = "1762536a663879d5fb8a94c1d145331e1d001fb27f787d79691f9f8208fc68f2"

    condition:
        pe.imphash() == "ed4aa283499e90f2a02acb700ea35a45"
        or pe.pdb_path == "C:\\Users\\IEUser\\Desktop\\samcli-FINAL\\x64\\Release\\samcli.pdb"
        and pe.number_of_exports == 36
        and pe.number_of_signatures == 1
        and for all export in pe.export_details:
        (export.name startswith "Net" and export.forward_name startswith "C:\\Windows\\System32\\samcli.Net")
        and for all resource in pe.resources:
        (resource.language == 2057 or resource.language == 1033) // English US and UK
        and pe.version_info["LegalCopyright"] == "\xa9 Microsoft Corporation. All rights reserved." // Impersonating Microsoft
       
 }



 

 
