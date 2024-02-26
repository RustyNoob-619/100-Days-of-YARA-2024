
import "pe"

rule EXE_Stealer_RustyStealer_Feb2024 {
    meta:
        Description = "Detects Rusty Stealer malware"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/RustyStealer/"
        Hash = "d9e9008e6e668b1c484f7afe757b1102bb930059b66ef5f282c472af35778c28"
    strings:
        $rust1 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\alloc\\src\\collections\\btree\\map\\entry.rsh"
        $rust2 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\slice\\iter.rs"
        $rust3 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\fmt\\mod.rs"
        $rust4 = "\\.\\pipe\\__rust_anonymous_pipe1__."
        $rust5 = "Local\\RustBacktraceMutex00000000"
        
        $unref = "AppPolicyGetProcessTerminationMethod"

        $susurl = "https://reboot.show/boredape/downloadx.cmdsrc\\main.rs"

    condition:
        pe.imphash() == "88a2d6e140afe5bcad7a3b6bdb449e9c"
        or (
            pe.imports("ntdll.dll","RtlNtStatusToDosError")
            and pe.imports("bcrypt.dll","BCryptGenRandom")
            and pe.imports("secur32.dll","FreeCredentialsHandle")
            and 3 of ($rust*)
            and $unref 
            or $susurl
        )
     
 }

