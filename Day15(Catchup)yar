import "pe"

rule TTP_Rare_Import_Libraries_March2024
{
    meta:
        author = "RustyNoob619"
        description = "Detects Import Libraries ending with a different extension apart from .dll"

    condition:
       for any lib in pe.import_details:
       (lib.library_name contains "." and (not lib.library_name endswith "dll"))

}
