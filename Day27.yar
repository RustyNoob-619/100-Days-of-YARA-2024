import "pe"
import "math"

rule EXE_Python_Stealer_Jan2024 {
    meta:
        Description = "Detects Python Stealer based on generic strings and high entropy in resources"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse.php?search=signature%3Apython"
        Hash = "f0b789e7ac0c5eee6f264daeb13620aaf4baaa09a3e519a1c136822b63241c3e"
    strings:
        $s1 = "%TEMP%\\onefile_%PID%_%TIME%" wide
        $s2 = "CACHE_DIR" wide
        $s3 = "%PROGRAM%" wide
        $s4 = ".%HOME%" wide
        $s5 = "else_( ,, ,_s. =;_=if == 'METADATA'el.txte_os..("
    condition:
        3 of them
        and for any section in pe.sections:
        (math.entropy(section.raw_data_offset, section.raw_data_size) >= 7.7 and section.name == ".rsrc")
 }

 //Requires further testing on more samples