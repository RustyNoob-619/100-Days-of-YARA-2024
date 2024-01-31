import "pe"

rule DLL_Loader_BlackWood_Jan2024 {
    meta:
        Description = "Detects the Dll Loader for the NSPX30 implant used by the Black Wood APT"
        Author = "RustyNoob619"
        Reference = "https://blog.sonicwall.com/en-us/2024/01/blackwood-apt-group-has-a-new-dll-loader/"
        Hash = "72b81424d6235f17b3fc393958481e0316c63ca7ab9907914b5a737ba1ad2374"
    strings:
        $s1 = "Update.ini"
        $s2 = "333333333333333.txt"
    condition:
        pe.dll_name == "agent.dll"
        and pe.number_of_exports == 1
        and pe.export_details[0].ordinal == 1
        and any of them    
       
 }