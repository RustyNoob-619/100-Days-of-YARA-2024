
import "pe"

rule EXE_Stealer_Strela_March2024 {
    meta:
        Description = "Detects Strela Stealer malware primarily based on the PE Imphash"
        Author = "RustyNoob619"
        Hash = "3b1b5dfb8c3605227c131e388379ad19d2ad6d240e69beb858d5ea50a7d506f9"

    strings:
        $str1 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r3) 13.2.0"
        $str2 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders) 13.2.0"
        
    condition:
        pe.imphash() == "f9e3bc32d194f624b25a23d75badfcf"
        and any of them
        
}





 

 


 




 

 
