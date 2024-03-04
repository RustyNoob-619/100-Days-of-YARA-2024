rule TTP_Hardcoded_IP_Addresses_Feb2024
{
    meta:
        author = "RustyNoob619"
        description = "Detects IP Addresses that are hardcoded in the malware sample"
        false_positves = "might match on other strings that are not IP addresses such as version numbers"
   
   strings:
      $ip = /^([0-9]{1,3}\.){3}[0-9]{1,3}$/
      //$ip = /([0-2]{0,1}[0-9]{0,1}[0-9]\.){3}[0-2]{0,1}[0-9]{0,1}[0-9]/
      $ver = /[0-9]\.[0-9]\.[0-9]\.[0-9]/
      $fp = "127.0.0.1"
   condition:
       $ip 
       and not ($fp or $ver)

}
