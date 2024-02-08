import "pe"

rule EXE_Stealer_StealC_Feb2024 {
    meta:
        Description = "Detects Stealc malware samples based on PE properties"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/Stealc/"
        Hash = "2b9d440e0a2b6b641c148826946d60bb71a28f866922b05847548563708b4450"
        Sample_Test = "Tested against 5 Stealc samples and the broader malware collection"
    condition:
        filesize < 1MB
        and pe.pdb_path endswith ".pdb"
        and pe.import_details[0].number_of_functions > 80
        and for any entity in pe.import_details:
        ((entity.library_name == "GDI32.dll"
            or entity.library_name == "WINHTTP.dll"
            or entity.library_name == "ADVAPI32.dll")
        and entity.number_of_functions == 1) //looking for specific Dlls with one import function only
        and for any resource in pe.resources:
        (resource.language == 1048  or resource.language == 2137) //Checking for Romanian or Sindhi Sys Default languages 
       
 }

