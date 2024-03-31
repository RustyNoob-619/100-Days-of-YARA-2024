
import "pe"

rule EXE_Loader_XDealer_March2024 {
    meta:
        Description = "Detects Loader used to deliver the XDealer Malware which is used by Chinese APT Earth Krahang "
        Author = "RustyNoob619"
        Reference = "https://www.trendmicro.com/en_us/research/24/c/earth-krahang.html"
        Credits = "@smica83 for uploading the malware sample to Malware Bazaar"
        File_Hash_1 = "2e3645c8441f2be4182869db5ae320da00c513e0cb643142c70a833f529f28aa"
        File_Hash_2 = "8218c23361e9f1b25ee1a93796ef471ca8ca5ac672b7db69ad05f42eb90b0b8d"

    strings: 
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" wide
        $exe = "\\calc.exe" wide
        $str = "okernel32" wide
        $dll = "gntdll.dll" wide
        
    condition:
        all of them
        and (pe.imphash() == "79ed833f90b585ce7dfa89a34d1b1961"
        or for any signature in pe.signatures:
            (signature.thumbprint == "be9de0d818b4096d80ce7d88110917b2a4e8273f"       // Chinese Certs 上海笑聘网络科技有限公司
            or signature.thumbprint == "be31e841820586e9106407d78ae190915f2c012d"))  //                上海指聚网络科技有限公司
        
 }

