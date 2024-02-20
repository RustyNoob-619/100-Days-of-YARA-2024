rule DLL_TinyTurla_Strings_Feb2024 {
    meta:
        Description = "Detects Ov3r Stealer spread through FaceBook Ads"
        Author = "RustyNoob619"
        Reference = "https://www.trustwave.com/hubfs/Web/Library/Documents_pdf/FaceBook_Ad_Spreads_Novel_Malware.pdf"
        Hash = "c6765d92e540af845b3cbc4caa4f9e9d00d5003a36c9cb548ea79bb14c7e8f66"
    strings:
        $URLs1 = "https://thefinetreats.com/wp-content/themes/twentyseventeen/rss-old.php"
        $URLs2 = "https://hanagram.jp/wp/wp-content/themes/hanagram/rss-old.php"
        $URLsUnknown = /https:.{2,100}php/ //hardcoded PHP URLs in the samples

        $cmd1 = "changeshell"
        $cmd2 = "Set-PSReadLineOption -HistorySaveStyle SaveNothing"
        $cmd3 = "powershell.exe -nologo"
        $cmd4 = "chcp 437 > $null"
        $cmd5 = "reg dexplorer.exe"
        $cmd6 = "delkill /F /IM explENT_USER"
        $cmd7 = "if exist {C2796011-81BA-4148-8FCA-C664324elete"
        $cmd8 = "task\"%s\" goto d"

        $usragnt1 = "Mozilla/5.0 (Windows NT 6.1"
        $usragnt2 = "rv:2.0.1) Gecko/20100101 Firefox/4.0.1"
        $usragnt3 = "Content-Disposition: form-data"
        $usragnt4 = "name=\"gettask\""
        $usragnt5 = "name=\"id\""
        $usragnt6 = "name=\"file\""
        $usragnt7 = "Content-Type: application/octet-stream"
        $usragnt8 = "filename=\"%s\""

    condition:
        any of ($URLs*)
        and 4 of ($cmd*)
        and 5 of ($usragnt*)
       
 }

// Day51.yar has the YARA rule based on the PE imports and exports
