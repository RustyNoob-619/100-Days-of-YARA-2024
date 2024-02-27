
import "pe"

rule DLL_News_Penguin_Feb2024 {
    meta:
        Description = "Detects a DLL that was part of the tooling used by News Penguin to target orgs in Pakistan"
        Author = "RustyNoob619"
        Credits = "Is Now on VT! for notification of the malware sample"
        Reference = "https://blogs.blackberry.com/en/2023/02/newspenguin-a-previously-unknown-threat-actor-targets-pakistan-with-advanced-espionage-tool"
        Hash = "3eecb083d138fdcb5642cd2f0ed00ae6533eb44508e224f198961449d944dd14"

    condition:
        pe.imphash() == "e0802b7e9a99fdbe21c766f49a999b72"
        and for all export in pe.export_details:
            (export.name startswith "curl_easy_")        
     
 }

 rule UNKNOWN_News_Penguin_Feb2024 {
    meta:
        Description = "Detects an unknown File Type that was part of the tooling used by News Penguin to target orgs in Pakistan"
        Author = "RustyNoob619"
        Credits = "Is Now on VT! for notification of the malware sample"
        Reference = "https://blogs.blackberry.com/en/2023/02/newspenguin-a-previously-unknown-threat-actor-targets-pakistan-with-advanced-espionage-tool"
        Hash = "538bb2540aad0dcb512c6f0023607382456f9037d869b4bf00bcbdb18856b338"

strings:
    $penguin = "penguin"
    condition:
        #penguin > 100       
     
 }

 

 