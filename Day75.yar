
import "pe"

rule EXE_RAT_vxRAT_March2024 {
    meta:
        Description = "Detects the Open Source RAT known as vxRAT"
        Author = "RustyNoob619"
        Credits = "@naumovax for sharing the sample here https://twitter.com/naumovax/status/1768612117429567536 "
        Reference = "https://github.com/f3di006/vxRat"
        Hash = "74f7bb1eb33afb53108923519c35474c91283823b7e1c7ea965c2a7a7cc44db"

    strings:
        $email = "Global\\f3di006@gmail.com"

        $cmd1 = "gSeShutdownPrivilege" wide
        $cmd2 = "@C:\\Windows\\System32\\cmd.exe" wide
        $cmd3 = "/c timeout 5 && del" wide

        $thrd1 = "_Thrd_id"
        $thrd2 = "_Thrd_join"

        $mtx = "_Mtx_"
        $cnd = "_Cnd_"
        
    condition:
        (pe.imphash() == "45060af466c55ef1ac1f0569be7ab744"
        or pe.pdb_path == "C:\\Users\\admin\\source\\repos\\vRat_Client\\Release\\vRat_Client.pdb"
        or $email)
        and any of ($cmd*)
        and any of ($thrd*)
        and #mtx > 3
        and #cnd > 3
        
}





 

 


 




 

 
