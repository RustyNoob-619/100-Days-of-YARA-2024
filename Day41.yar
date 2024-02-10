rule EXE_Stealer_Phemedrone_Feb2024 {
    meta:
        Description = "Detects Phemedrone Stealer malware samples"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/PhemedroneStealer/"
        Hash = "6bccfdbe392cf2eef8a337fbb8af90a662773d8cd73cec1ac1e0f51686840215, 58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f"
    strings:
        $pheme1 = "Phemedrone"
        $pheme2 = "Phemedrone.Services"
        $pheme3 = "Phemedrone.Classes"
        $pheme4 = "Phemedrone.Protections"
        $pheme5 = "Phemedrone.Extensions"

        //Sandbox Detection 
        $vm1 = "AntiVM"
        $vm2 = "IsVM"
        $vm3 = "KillDebuggers"
        $vm4 = "debuggers"

        $pswd1 = "get_MasterPassword" 
        $pswd2 = "FormatPassword"
        $pswd3 = "ParsePasswords"
        $pswd4 = "DiscordList"
        $pswd5 = "PasswordList"
        $pswd6 = "masterPassword"
        $pswd7 = "password"
        $pswd8 = "masterPass"

        $crypto1 = "ParseColdWallets"
        $crypto2 = "CryptoWallets"
        $crypto3 = "ParseDatWallets"

        //Import Libraries found in strings but absent in PE Imports
        $unref1 = "kernel32.dll" 
        $unref2 = "rstrtmgr.dll"
        
       
    condition:
        any of ($pheme*)
        and 2 of ($vm*)
        and 4 of ($pswd*)
        and any of ($crypto*)
        and any of ($unref*)
       
 }
