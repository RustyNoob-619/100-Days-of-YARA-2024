
import "pe"

rule DLL_Unknown_China_Feb2024 {
    meta:
        Description = "Detects an unknown suspicious DLL with Chinise artifacts that appears to impersonate Easy Language Program"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/sample/58d851d4909cd3833f18aec033c8856dc14c5ba60e037114193b92c18e9670b8/"
        Hash = "58d851d4909cd3833f18aec033c8856dc14c5ba60e037114193b92c18e9670b8"
    strings:
        $rust1 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\alloc\\src\\collections\\btree\\map\\entry.rsh"
        $rust2 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\slice\\iter.rs"
        $rust3 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\fmt\\mod.rs"
        $rust4 = "\\.\\pipe\\__rust_anonymous_pipe1__."
        $rust5 = "Local\\RustBacktraceMutex00000000"
        
        $unref = "AppPolicyGetProcessTerminationMethod"

        $susurl = "https://reboot.show/boredape/downloadx.cmdsrc\\main.rs"

    condition:
        pe.imphash() == "736bc598358bfd2d88645399ceb66351"
        and pe.export_details[0].name == "HelpCF"
        and pe.resources[index].language == "CHINESE SIMPLIFIED"
        and pe.version_info["LegalCopyright"] == "作者版权所有 请尊重并使用正版"
     
 }

