
import "pe"

rule APT_Patchwork_Code_Signing_Cert_March2024 {
    meta:
        Description = "Detects malware used by Indian APT Patchwork based on the Code Signing Certificate"
        Author = "RustyNoob619"
        Reference = "https://twitter.com/malwrhunterteam/status/1771152296933531982"
        Credits = "@malwrhunterteam for sharing the resuse of the certificate and references. @__0XYC__ and @ginkgo_g for sharing the malware hashes and attribution to APT"
        File_Hash = "8f4cf379ee2bef6b60fec792d36895dce3929bf26d0533fbb1fdb41988df7301"

    condition:
        for any signature in pe.signatures:
            (signature.thumbprint == "424ef52be7acac19da5b8203494959a30b818f8d"
            or signature.issuer contains "CN=RUNSWITHSCISSORS LTD")
 }
