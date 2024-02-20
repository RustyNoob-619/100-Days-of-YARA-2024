import "pe"

rule DLL_TinyTurla_PE_Properties_Feb2024 {
    meta:
        Description = "Detects Tiny Turla Implant used by Turla APT based on PE import and export properties"
        Author = "RustyNoob619"
        Reference = "https://blog.talosintelligence.com/tinyturla-next-generation/"
        Hash = "267071df79927abd1e57f57106924dd8a68e1c4ed74e7b69403cdcdf6e6a453b"
    condition:
        pe.imphash() == "2240ae6f0dcbc0537836dfd9205a1f2b"
        or
        (pe.imports("KERNEL32.dll","RtlPcToFileHeader")
        and pe.imports("KERNEL32.dll","GetUserDefaultLCID")
        and pe.imports("KERNEL32.dll","GetOEMCP")
        and pe.imports("ADVAPI32.dll","RegisterServiceCtrlHandlerW")
        and pe.imports("ADVAPI32.dll","SetServiceStatus")  
        and pe.imports("WINHTTP.dll","WinHttpQueryDataAvailable")
        and pe.imports("WINHTTP.dll","WinHttpWriteData"))
        and pe.export_details[0].name == "ServiceMain"
       
 }

 //String based YARA rule for TinyTurla was added to the Day1.yar which can be found on my GitHub
