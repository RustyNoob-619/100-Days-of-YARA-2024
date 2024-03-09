import "pe"

rule DLL_Loader_Pikabot_March2024 {
    meta:
        Description = "Detects Pikabot Loader malware based on PE import & export properties"
        Author = "RustyNoob619"
        Credits = "@pr0xylife for sharing the malware sample"
        Reference = "https://bazaar.abuse.ch/sample/238dcc5611ed9066b63d2d0109c9b623f54f8d7b61d5f9de59694cfc60a4e646/"
        Hash = "238dcc5611ed9066b63d2d0109c9b623f54f8d7b61d5f9de59694cfc60a4e646"

    condition:
        pe.imphash() == "55f1ba0b782341fa929d61651ef47f0c"
        and for 7 export in pe.export_details:
        (export.name startswith "Tmph")
        and pe.exports("HetModuleProp")
        and pe.exports("GetModul")
}
