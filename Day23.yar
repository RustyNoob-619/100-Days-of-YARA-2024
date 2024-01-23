rule SoCatStrings
{
    meta:
        description = "Detects SoCat tool A modified version of SoCat tool used by Sea Turtle to setup a command-and-control channel. "
        author = "RustyNoob619"
        source = "https://www.huntandhackett.com/blog/turkish-espionage-campaigns"
        hash = "f1a4abd70f8e56711863f9e7ed0a4a865267ec7"
    strings:

        $cat1 = "SOCAT_MAIN_WAIT" 
        $cat2 = "SOCAT_DEFAULT_LISTEN_IP"
        $cat3 = "SOCAT_PREFERRED_RESOLVE_IP"
        $cat4 = "SOCAT_FORK_WAIT"
        $cat5 = "socat"

        $abst1 = "abstract-client"
        $abst2 = "abstract-connect"
        $abst3 = "abstract-listen"
        $abst4 = "abstract-recv"
        $abst5 = "abstract-recvfrom"
        $abst6 = "abstract-sendto"

        $sock1 = "socket-connect"
        $sock2 = "socket-datagram"
        $sock3 = "socket-listen"
        $sock4 = "socket-recv"
        $sock5 = "socket-recvfrom"
        $sock6 = "socket-sendto"

        $int1 = "/usr/share/zoneinfo/" 
        $int2 = "/share/zoneinfo/"
        $int3 = "/etc/zoneinfo/"
        $int4 = "/etc/hosts"
        $int5 = "/etc/services"
        $int6 = "/etc/resolv.conf"
        $int7 = "/etc/group"
        $int8 = "/etc/passwd"
        $int9 = "/var/run/nscd/socket"
        $int10 = "/usr/local/bin"

        
    condition:
        3 of ($cat*) 
        and 4 of ($abst*)
        and 4 of ($sock*)
        and 6 of ($int*) //remove this and unreference all $int for possible broader matching
}