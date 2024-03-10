import "pe"

rule DLL_Mustang_Panda_March2024 {
    meta:
        Description = "Detects a malicious DLL used by Mustang Panda (aka TA416) in a New Year Themed Campaign"
        Author = "RustyNoob619"
        Credits = "@smica83 for sharing the malware sample on Malware Bazaar"
        Reference = "https://cyble.com/blog/festive-facade-dissecting-multi-stage-malware-in-new-year-themed-lure/"
        Hash = "dd261a5db199b32414c33136aed44c3ebe2ae55f18991ae3dc341fc43a1ef7f4"

    strings:
        $unrefdll = "mscoree.dll"
    condition:
        pe.number_of_signatures == 0
        and pe.imphash() == "ff98d730c7b4fbaa92b85279e37acb21"
        and for 3 export in pe.export_details:
        (export.name startswith "WMGet")
        and pe.exports("DMGetDesktopInfo")
        and pe.exports("NVAutoStart")
        and pe.exports("NVLoadDatabase")
        and pe.exports("PMEnum")
        and any of them

}
