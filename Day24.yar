import "pe"
rule Lib_Function_WinHttpCrackUrl_Jan2024 {
    meta:
        Description = "Detects an uncommon function of WINHTTP Dll, found  in the SysJoker June 2022 Variant malware sample"
        Author = "RustyNoob619"
        Bias = "Matched 2 malware samples (SysJoker) out of collection of 1000 samples. Collection size is still small"
        Reference = "https://intezer.com/blog/research/wildcard-evolution-of-sysjoker-cyber-threat/"
        FileHashes = "e076e9893adb0c6d0c70cd7019a266d5fd02b429c01cfe51329b2318e9239836, 6c8471e8c37e0a3d608184147f89d81d62f9442541a04d15d9ead0b3e0862d95"
    condition:
        for any library in pe.import_details: // We first iterate and search for the WinHTTP Dll Library and then use the second iterator to check for import function names in that library matching the uncommon function 
        (library.library_name == "WINHTTP.dll" and for any function in library.functions: (function.name == "WinHttpCrackUrl"))    
 }




