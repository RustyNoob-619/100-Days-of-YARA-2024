import "dotnet"
rule EXE_Stealer_WhiteSnake_Jan2024 {
    meta:
        Description = "Detects White Snake Stealer samples based on network strings and dotnet resources"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/WhiteSnakeStealer/"
        Hash = "cc9e5bfeb86b7fe80b33a4004eb0912820f09dec29a426a8a4136f7306c08d04"
    strings: 
        $net1 = "get_beaconService" 
        $net2 = "set_beaconService" 
        $net3 = "get_HttpMethod" 
        $net4 = "HttpListenerRequest" 
        $net5 = "HttpListenerContext" 
        $net6 = "DownloadData" 
        $net7 = "UploadData" 
        $net8 = "WebClient" 
        $net9 = "TcpClient" 
        $s = "_HELLO_BITCH"

    condition:
       5 of ($net*)
       and #s > 10
       or for any resource in dotnet.resources:
       (resource.name endswith ".jpg")
       
 }

