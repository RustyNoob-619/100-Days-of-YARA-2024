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

rule TTP_Weird_symbols_In_Exports_Feb2024 {
    meta:
        Description = "Leverages a specific sequence of symbols in the export names as a TTP"
        Procedure_Examples = "Currently seen with the Go Bear Backdoor used by Kimsuky"
        Author = "RustyNoob619"
        Hash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"

    condition:
        pe.export_details[0].name contains "._:|"

}

rule EXE_Backdoor_GoBear_Feb2024 {
    meta:
        Description = "Detects the Go Bear Backdoor used by Kimsuky based on the PE export property"
        Author = "RustyNoob619"
        Reference = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        Hash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"

    condition:
        TTP_Weird_symbols_In_Exports_Feb2024
        and Signed_Certificate_D2_Innovation_Feb2024

}


  
