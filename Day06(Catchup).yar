import "pe"

rule TTP_Signed_Impersonating_Microsoft_Feb2024
{
  meta:
    author = "RustyNoob619"
    description = "Detects Signed Binaries that are impersonating Microsoft"
    false_positives = "15 FPs, due to revoked or expired certificates"
    FPs_hashes = "11c1e4ec665c73b23a1dffca63ee21d92a652897c4a9f5e09fb94aa4c1557049, 3700abcbbf39b248cd91ca758c045b8b2bb4b727b525ab778c7643aa8f45f91c, ad0169ece400fb7e288042fc3c4c8885d4d87889f608bbc355b98df9be147810, 5f0dc440394648d0deb5f6546723088f444098deace2e4eecefe5d9b2beae345, 307c8b8b7ea5a49a723d8b3d6fb01391870ef0722327046653a9ea342eb85394, 60d84af37c8c7dde68e4162b1689748538b3124f406627d9ab8ec3d50d939606, e166692a96ca4ec597f6209b0965e5b156cdd3bc8db145e29e18803b64018398, 843981496f3ad301d865a0ede93f41f6f028703f69f70175f510fc86adb9fbaf, f14d40afd7faf62596858226b0700c7fdfe24dab0c9406eba7b341d662051a76, 0274c745681ce8afad1b1c60ee5c6403a608c2f2f5ffa90e7bddd7bc779095e5, 27238000e1c55f58b67bf2752b0ea2692d0e984ded3eeba883dde329800fb79a, 75746d7990a0923a8d262636d941ef19085387188a474f05a77a5deae9600edd, 2d5a5e2f5802a0d8f788f32428d2534140f667d2fe7e9eeb436fc822e36f39ad, 81f12259ad2008a05e80b735700783a973e97c8882321995665e78c49cf38006, 7b051bebba279d2ae83e3857fd952a9d09c04740fd4203364cfed669ade75d59"
  condition:
    pe.number_of_signatures == 1
    and not pe.signatures[0].issuer contains "Microsoft"
    and pe.version_info["LegalCopyright"] == "\xa9 Microsoft Corporation. All rights reserved."
}




