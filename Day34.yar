import "pe"
rule Old_Code__Signature_AnyDesk_Feb2024 {
    meta:
        Description = "Detects files with older and no longer valid code signing certifcates of AnyDesk"
        Author = "RustyNoob619"
        Credits = "Inspired by Florian Roth"
        Reference = "https://twitter.com/cyb3rops/status/1753440743480238459"
        Goodware_Hash = "55e4ce3fe726043070ecd7de5a74b2459ea8bed19ef2a36ce7884b2ab0863047"
    
    condition:
        pe.version_info["CompanyName"] contains "AnyDesk"
        and for 2 signature in pe.signatures:
        (signature.thumbprint != "646f52926e01221c981490c8107c2f771679743a") //Latest AnyDesk Code Sign Cert
       
 }

rule Sus_AnyDesk_Attempts_Feb2024 {
    meta:
        Description = "Detects files attempting to impersonate AnyDesk Windows Version"
        Author = "RustyNoob619"
        Credits = "Inspired by Florian Roth"
        Reference = "https://twitter.com/cyb3rops/status/1753440743480238459"
        Goodware_Hash = "55e4ce3fe726043070ecd7de5a74b2459ea8bed19ef2a36ce7884b2ab0863047"
    
    condition:
       pe.version_info["CompanyName"] contains  "AnyDesk"
       and pe.version_info["LegalCopyright"] != "(C) 2022 AnyDesk Software GmbH"
       and pe.pdb_path != "C:\\Users\\anyadmin\\Documents\\anydesk\\release\\app-32\\win_loader\\AnyDesk.pdb"
    
 }

 
