import "pe"
rule EXE_Stealer_RisePro_Jan2024 {
    meta:
        Description = "Detects Rise Pro Stealer samples based on properties in the resources, manifest settings and PE Rich Header"
        Author = "RustyNoob619"
        Reference = "https://bazaar.abuse.ch/browse/signature/RiseProStealer/"
        Hash = "957ca1ae2bbb01a37d1108b314160716643933ec9ef9072a4c50c39b224662df"
        SampleSize = "Tested against 3 RisePro samples and wider malware collection"
    strings: 
        $s1 = "'1.0' encoding" 
        $s2 = "'UTF-8' standalone" 
        $s3 = "'yes'?" 
        $s4 = "'urn:schemas-microsoft-com:asm.v1' manifestVersion" 
        $s5 = "trustInfo xmlns" 
        $s6 = "urn:schemas-microsoft-com:asm.v3" 
        $s7 = "security" 
        $s8 = "requestedPrivileges" 
        $s9 = "requestedExecutionLevel level" 
        $s10 = "'asInvoker' uiAccess" 
        $s11 = "'false' /" 
// The above strings need to be adjusted to only pick dynamic XML parameters 
    condition:
       pe.rich_signature.key== 3099257863  //can be removed for broader matching
       and pe.RESOURCE_TYPE_ICON == 3
       and for 5 resource in pe.resources: 
       (resource.language == 1049) // Checking for Russian Language related resources
       and  pe.resources[pe.number_of_resources-1].type == 24 // Searching for XML Manifest Type
       and all of them in (filesize-700000..filesize) // Checking for the XML Manifest settings near the end
 }

