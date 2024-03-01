import "pe"

rule DLL_PyPi_Comebacker_Lazarus_March2024 {
    meta:
        Description = "Detects the Combacker malware used in Malicious PyPi Packages by Lazarus"
        Author = "RustyNoob619"
        Reference = "https://blogs.jpcert.or.jp/en/2024/02/lazarus_pypi.html"
        Hash = "63fb47c3b4693409ebadf8a5179141af5cf45a46d1e98e5f763ca0d7d64fb17c, e05142f8375070d1ea25ed3a31404ca37b4e1ac88c26832682d8d2f9f4f6d0ae"

    strings:
        $nop = {66 66 66 66}

        $c2url1 = "https://blockchain-newtech.com/download/download.asp" wide
        $c2url2 = "https://fasttet.com/user/agency.asp" wide

        $usragnt1 = "HTTP/1.0" wide
        $usragnt2 = "Content-Type: application/x-www-form-urlencoded" wide
        $usragnt3 = "Connection: Keep-Alive" wide

    condition:
        pe.imports("urlmon.dll","ObtainUserAgentString")
        and pe.imports("USER32.dll","wsprintfW")
        and pe.imports("WININET.dll","DeleteUrlCacheEntryW")
        and for all export in pe.export_details:
        (export.name startswith "GetWindowSized")
        and #nop > 25
        and all of ($usragnt*)
        and (any of ($c2url*) or true) 
          
 }




 

 