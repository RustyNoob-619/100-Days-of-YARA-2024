import "pe"

rule EXE_Unknown_Byakugan_April2024 {
    meta:
        Description = "Detects Byakugan malware based on the PE properties"
        Author = "RustyNoob619"
        Reference = "https://www.fortinet.com/blog/threat-research/byakugan-malware-behind-a-phishing-attack"
        File_Hash = "9ef9bbfce214ee10a2e563e56fb6486161c2a623cd91bb5be055f5745edd6479"
    
    condition:
        (pe.imphash() == "4d0fb8dc9ee470058274f448bebbb85f"
        or pe.imphash() == "2905d3c578dd8f8b4132143b23256eb9")
        and pe.number_of_exports > 50
        and for 25 export in pe.export_details:
        (export.name startswith "??$" and export.name contains "@")
        and filesize > 20MB
        
 }
