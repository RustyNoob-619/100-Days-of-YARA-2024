import "pe"

rule EXE_Stealer_CryptBot_March2024 {
    meta:
        Description = "Detects a new version of CryptBot Stealer"
        Author = "RustyNoob619"
        Credits = "@RussianPanda9xx for identifying the new version of the malware"
        Reference = "https://twitter.com/RussianPanda9xx/status/1766163567873593476"
        Hash = "490625afa4de3eac3b03d1ca3e81afab07b5e748423319ee6e08f58c40d20250"

    condition:
        pe.imphash() == "48d4a6a3111a18b082fa3638b1568f64"
        and pe.number_of_sections == 8
        and pe.number_of_resources == 6
        and for 4 resource in pe.resources:
        (resource.type == pe.RESOURCE_TYPE_ICON)
}
