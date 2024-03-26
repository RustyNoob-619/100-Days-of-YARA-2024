
import "pe"

rule EXE_Stealer_Azorult_March2024 {
    meta:
        Description = "Detects Azorult infostealer malware based on matched strings and PE Properties"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/sample/3168696d51a82d3bd1dc41477ea7a5688e1dcf3ca3a045391247b6270ccd5251/"
        File_Hash = "3168696d51a82d3bd1dc41477ea7a5688e1dcf3ca3a045391247b6270ccd5251"

    strings: 
        $str1 = "MachineGuid"  fullword wide 
        $str2 = "UserName"   fullword wide 
        $str3 = "HostName"  fullword wide 
        $str4 = "PortNumber"  fullword wide 
        $str5 = "SteamPath"  fullword wide 
        $str6 = "Telegram"  fullword wide 

        $path1 = "\\accounts.xml"  fullword wide
        $path2 = "\\Cookies" fullword wide
        $path3 = "\\History" fullword wide
        $path4 = "\\*.coo" fullword wide
        $path5 = "%APPDATA%\\Skype" wide
        $path6 = "%appdata%\\Telegram Desktop\\tdata\\" wide
        $path7 = "Software\\Valve\\Steam" wide 
        $path8 = "PasswordsList.txt"

        $usragnt1 = "HTTP/1.0"  fullword ascii 
        $usragnt2 = "Mozilla/4.0" 
        $usragnt3 = "Content-Length:" fullword ascii
        
        $delphi = "SOFTWARE\\Borland\\Delphi\\RTL"

    condition:
        pe.imphash() == "6d1f2b41411eacafcf447fc002d8cb00"
        and $delphi
        and 2 of ($str*)
        and 4 of ($path*)
        and any of ($usragnt*)
        and filesize < 3MB
 }








































