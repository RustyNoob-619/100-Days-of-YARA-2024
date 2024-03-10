rule TTP_Weird_symbols_In_Exports_Feb2024 {
    meta:
        Description = "Leverages a specific sequence of symbols in the export names as a TTP"
        Procedure_Examples = "Currently seen with the Go Bear Backdoor used by Kimsuky"
        Author = "RustyNoob619"
        Hash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"

    condition:
        pe.export_details[0].name contains "._:|"

}
