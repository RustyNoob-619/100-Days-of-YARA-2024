
rule TTP_File_Padding_March2024
{
    meta:
        author = "RustyNoob619"
        description = "Detects suspicious padding in Windows Executables"
        sample_tested = "ad9cd122ee6347fb6710c0f10165c9a71576cd52c79fee243f880496cad5abb8"
        usage = "please use in combination with other YARA rules to avoid matching on false positives"

    strings:
        $pad1 = "PADDINGX"
        $pad2 = "XPADDING"
   condition:
        uint16(0) == 0x5a4d
        and #pad1 > 15
        and #pad2 > 15

}




