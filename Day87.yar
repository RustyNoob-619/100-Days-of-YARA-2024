
rule EXE_Backdoor_OceanMap_March2024 {
    meta:
        Description = "Detects Ocean Map Backdoor used by Russian Threat Group APT28"
        Author = "RustyNoob619"
        Reference = "https://medium.com/@knight0x07/analyzing-apt28s-oceanmap-backdoor-exploring-its-c2-server-artifacts-db2c3cb4556b"
        File_Hash = "24fd571600dcc00bf2bb8577c7e4fd67275f7d19d852b909395bebcbb1274e04"

    strings: 
        $pdb = "C:\\WORK\\Source\\tgnews\\tgnews\\obj\\x64\\Release\\VMSearch.pdb"

        $wide1 = "$ LOGIN"  fullword wide 
        $wide2 = "$ SELECT INBOX.Drafts"   fullword wide 
        $wide3 = "$ SELECT Drafts"  fullword wide 
        $wide4 = "$ UID SEARCH subject \""  fullword wide 
        $wide5 = "$ UID STORE"  fullword wide 
        $wide6 = "$ EXPUNGE"  fullword wide 
        $wide7 = "$ UID FETCH"  fullword wide

        $cmd1 = "taskkill /F /PID" fullword wide
        $cmd2 = "URL=file:///" fullword wide

        $get1 = "get_CurrentDomain" fullword
        $get2 = "get_OSVersion" fullword
        $get3 = "get_Location" fullword
        $get4 = "get_MachineName" fullword
        $get5 = "get_UserName" fullword
        $get6 = "GetProcessesByName" fullword
        $get7 = "get_FriendlyName" fullword
        $get8 = "get_Message" fullword
        $get9 = "get_Id" fullword

        $othr1 = "IndexOf" fullword
        $othr2 = "set_UseShellExecute" fullword
        $othr3 = "new_creds" fullword
        $othr4 = "new_r_creds" fullword
        $othr5 = "fcreds" fullword

    condition:
        uint16(0) == 0x5a4d
        and $pdb 
        or (
            3 of ($wide*)
            and any of ($cmd*)
            and 5 of ($get*)
            and 2 of ($othr*)
        )
 }
