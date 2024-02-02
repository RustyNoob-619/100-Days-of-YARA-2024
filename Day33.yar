import "pe"

rule DLL_DiceLoader_Fin7_Feb2024 {
    meta:
        Description = "Detects Dice Loader malware used by Fin7 APT based on the export properties"
        Author = "RustyNoob619"
        Credits = "Sekoia for providing the intel and malware sample"
        Reference = "https://blog.sekoia.io/unveiling-the-intricacies-of-diceloader/"
        Hash = "8a287fbd024544c34b5db983af093504d25be864a821010f4cd2d00a2a6ad435"
    strings:
       $exp_func = /[a-zA-z]{16}\x00/ //Random name of the export function 
       $s1 = "GetQueuedCompletionStatus"
       $s2 = "PostQueuedCompletionStatus"
       $s3 = "CreateIoCompletionPort"
       $s4 = "ResetEvent"
       $s5 = "CreateMutexA"
       $s6 = "ReleaseMutex"
       $s7 = "GetComputerNameExA"
       $net1 = "gethostbyname"
       $net2 = "closesocket"
       $net3 = "recv"
       $net4 = "htons"
       $net5 = "inet_addr"
       $net6 = "connect"
       $other = "GetAdaptersInfo"
    condition:
        pe.imphash() == "37af5cd8fc35f39f0815827f7b80b304" //matches on 7 Dice Loader Samples
        or 
        (pe.number_of_exports == 1
        and pe.export_details[0].ordinal == 1  
        and ($exp_func at (0x2888) or $exp_func at (0x2338))) //Checking for export function name 
        and 5 of ($s*) and 4 of ($net*) and $other
            
 }

