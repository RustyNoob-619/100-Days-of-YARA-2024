
rule TTP_File_Padding_March2024
{
    meta:
        author = "RustyNoob619"
        description = "Detects suspicious padding in Windows Executables"

    strings:
        $pad1 = "PADDINGX"
        $pad2 = "XPADDING"
   condition:
        uint16(0) == 0x5a4d
        and #pad1 > 15
        and #pad2 > 15

}




