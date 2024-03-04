rule ELF_RAT_Bifrost_March2024 {
    meta:
        Description = "Detects x86 based Version of Bifrost RAT Targeting Linux"
        Author = "RustyNoob619"
        Reference = "https://unit42.paloaltonetworks.com/new-linux-variant-bifrost-malware/"
        Hash = "8e85cb6f2215999dc6823ea3982ff4376c2cbea53286e95ed00250a4a2fe4729"
   
   strings:
        $msg1 = "begin st=socket(..)"
        $msg2 = "ip=%s dns_server=%s"
        $msg3 = "sleep sleeptime_1 %ds"
        $msg4 = "recvData timeout :%d"
        $msg5 = "send data %d : %s"
        $msg6 = "restlen=%d"

        $cmd1 = "getpwuid_r"
        $cmd2 = "passwd"
        $cmd3 = "shadow"
        $cmd4 = "search cache=%s"
        $cmd5 = "lookup in file=%s"

        $dir1 = "/proc/self/maps"
        $dir2 = "/usr/share/zoneinfo"
        $dir3 = "/etc/nsswitch.conf"
        $dir4 = "/var/run/.nscd_socket"
        $dir5 = "/etc/suid-debug"
        $dir6 = "/usr/lib/gconv"
        $dir7 = "/usr/lib/locale/locale-archive"
        $dir8 = "/etc/resolv.conf"
        $dir9 = "/etc/ld.so.cache"
        $dir10 = "/proc/self/exe"

        $_c2 = "168.95.1.1"
        $wide = "jjjjjj" wide
        
   condition:
         uint32be(0) == 0x7F454C46 //ELF
         and 4 of ($msg*)
         and 3 of ($cmd*)
         and 6 of ($dir*)
         and $wide

 }
