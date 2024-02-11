import "pe"

rule Signed_Certificate_D2_Innovation_Feb2024 {
    meta:
        Description = "This is a legitimate Code Signing Certificate Stolen and used by Kimsuky"
        Author = "RustyNoob619"
        Reference = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        Hash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"

    condition:
        pe.signatures[0].subject contains "D2innovation"
        and pe.signatures[0].serial == "00:88:90:ca:b1:cd:51:0c:d2:0d:ab:4c:e5:94:8c:bc:3a"
          
 }

rule EXE_Stealer_TrollStealer_Feb2024 {
    meta:
        Description = "Detects Troll Stealer malware used by Kimsuky based on the PE export properties"
        Author = "RustyNoob619"
        Reference = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        Hash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"

    condition:
        Signed_Certificate_D2_Innovation_Feb2024
        and pe.dll_name == "golang.dll"
        and pe.export_details[0].name == "_cgo_dummy_export" 
        and for 9 export in pe.export_details:
        (export.name endswith "Trampoline")
       
 }

