import "elf"

rule ELF_Backdoor_ZipLine_Feb2024 {
    meta:
        Description = "Detects Zipline backdoor malware samples based on ELF properties and strings"
        Author = "RustyNoob619"
        Credits = "Is Now on VT! for the notification of the malware sample"
        Reference = "https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation"
        Hash = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    
    strings:
    $dir1 = "/tmp/data/root/home/lib/%s"
    $dir2 = "/tmp/data/root/etc/ld.so.preload"
    $dir3 = "/tmp/data/root/home/etc/manifest/exclusion_list"
    $dir4 = "/proc/self/exe"
    $dir5 = "/proc/self/cmdline"
    $dir6 = "/home/etc/manifest/exclusion_list"

    $cmd1 = "./installer/bom_files"
    $cmd2 = "./installer/scripts"
    $cmd3 = "/retval=$(exec $installer $@)/d' /pkg/do-install"

    $ssh = "SSH-2.0-OpenSSH_0.3xx"

    condition:
       for 3 sym in elf.dynsym:
       (sym.name == "_ITM_deregisterTMCloneTable" 
       or sym.name == "_ITM_registerTMCloneTable" 
       or sym.name == "__cxa_finalize")
       and 3 of ($dir*)
       and any of ($cmd*) 
       and $ssh
       
 }


 