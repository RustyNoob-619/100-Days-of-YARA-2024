import "elf"

rule ELF_Rust_Executable_Feb2024 {
    meta:
        Description = "Detects ELF executables written in Rust and complied using GNU GCC compiler"
        Author = "RustyNoob619"
        Credits = "Awesome analysis by Synacktiv which includes an extractor script and YARA rule based on Hex Sequences"
        Reference = "https://www.synacktiv.com/publications/krustyloader-rust-malware-linked-to-ivanti-connectsecure-compromises"
        Suggested_Reading = "Good source on ELF Headers: https://www.sco.com/developers/gabi/latest/ch4.eheader.html"
        Hash = "030eb56e155fb01d7b190866aaa8b3128f935afd0b7a7b2178dc8e2eb84228b0"
    strings:
        $rust1 = "/rustc/"
        $rust2 = "/cargo/registry/src/index.crates.io"
        $config1 = "/etc/hosts"
        $config2 = "/etc/resolv.conf"
        $config3 = "/etc/services"
    condition:
        elf.type == 3 //Executable File Type
        and elf.machine == 62 //AMD x86-64 architecture
        and for any section in elf.sections:
        (section.name startswith ".gnu" or section.name startswith ".gcc") //GNU/GCC complier Usage
        and any of ($rust*) 
        and any of ($config*)  
    
 }
