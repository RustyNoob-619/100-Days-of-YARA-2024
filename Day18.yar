rule LimeRAT
{
    meta:
        description = "Detects Lime RAT malware samples based on the strings matched"
        author = "RustyNoob619"
        source = "https://valhalla.nextron-systems.com/info/rule/MAL_LimeRAT_Mar23"
        hash = "b62f72df91cffe7861b84a38070e25834ca32334bea0a0e25274a60a242ea669"
    strings:
        $main = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr" wide 
        $cmd1 = "Flood!" wide
        $cmd2 = "!PSend" wide  
        $cmd3 = "!PStart" wide  
        $cmd4 = "SELECT * FROM AntivirusProduct" wide  
        $cmd5 = "Select * from Win32_ComputerSystem" wide  
        $cmd6 = "_USB Error!" wide
        $cmd7 = "_PIN Error!" wide
        
        
    condition:
        uint16(0) == 0x5A4D
        and $main
        and 4 of ($cmd*)
}