import "pe"

rule TTP_Impersonating_Google_Updates_March2024 {
    meta:
        Description = "Detects Windows executables which are impersonating Google Update utilities"
        Author = "RustyNoob619"
        Credits = "@ULTRAFRAUD shared a signed Async RAT sample disguised as Google Chrome"
        Reference = "https://twitter.com/ULTRAFRAUD/status/1771590513973395666"
        File_Hash = "3f4ab98919c1e1191dddcceac3d8962390b2ac9f08f13986b0965bdaa0cff202"

    condition:
        pe.version_info["LegalCopyright"] == "Copyright 2018 Google LLC"
        and pe.number_of_signatures > 0 
        and not (for any sig in pe.signatures:
        (sig.thumbprint == "2673EA6CC23BEFFDA49AC715B121544098A1284C"))
 }





