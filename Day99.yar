
import "pe"

rule EXE_ICS_Triton_April2024 {
    meta:
        Description = "Detects Triton ICS malware used to target SIS (Safety Instrumentation Systems)"
        Author = "RustyNoob619"
        Reference = "https://www.mandiant.com/resources/blog/attackers-deploy-new-ics-attack-framework-triton"
        File_Hash = "e8542c07b2af63ee7e72ce5d97d91036c5da56e2b091aa2afe737b224305d230"

    strings:
        $python = "PYTHONSCRIPT" wide fullword

        $antivm1 = "QueryPerformanceCounter"
        $antivm2 = "GetTickCount"
        $antivm3 = "IsDebuggerPresent"

        $lib = "library.zip" fullword // Custom communication library for interaction with Triconex controller
        $payload = "payload"
        $inject = "inject.bin"

        $str1 = "Blackhole"
        $str2 = "GetCpStatus" fullword
        $str3 = "UploadDummyForce" fullword

        $info1 = "countdown: %di" fullword
        $info2 = "time left = s" fullword
        $info3 = "DebugInfo:s" fullword

    condition:
        pe.imphash() == "b28c641d753fb51b62a00fe6115070ae"
        and $python
        and $lib
        and $payload
        and $inject
        and any of ($antivm*)
        and any of ($str*)
        and any of ($info*)
        and filesize < 100KB
        
 }
