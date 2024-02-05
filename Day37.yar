import "pe"

rule Ransomware_Nevada_Feb2024 {
    meta:
        Description = "Detects Nevada ransomware aka Nokoyawa ransomware 2.1"
        Author = "RustyNoob619"
        Reference = "https://www.zscaler.com/blogs/security-research/nevada-ransomware-yet-another-nokoyawa-variant"
        Hash = "855f411bd0667b650c4f2fd3c9fbb4fa9209cf40b0d655fa9304dcdd956e0808"
    strings:
        $rust1 = "RustBacktraceMutex"
        $rust2 = "RUST_BACKTRACE=full"
        $rust3 = "/rustc/4b91a6ea7258a947e59c6522cd5898e7c0a6a88f"
        $nevada1 = "nevada_locker"
        $nevada2 = "nevadaServiceSYSTEM"
        $nevada3 = "NEVADA.Failed to rename file"
        $ransom1 = "ntuser.exe.ini.dll.url.lnk.scr"
        $ransom2 = "drop of the panic payload panicked"
        $ransom3 = "Shadow copies deleted from"
        $ransom4 = "Failed to create ransom note"
        $Git = "github.com-1ecc6299db9ec823"
        $note = "R3JlZXRpbmdzISBZb3VyIGZpbGVzIHdlcmUgc3RvbGVuIGFuZCBlbmNyeXB0ZWQ" //Greetings! Your files were stolen and encrypted
        
    condition:
        pe.imports("KERNEL32.dll","AcquireSRWLockExclusive")
        and pe.imports("bcrypt.dll","BCryptGenRandom")
        and pe.imports("MPR.dll","WNetEnumResourceW")
        and 2 of ($rust*)
        and 2 of ($ransom*)
        and (pe.pdb_path == "C:\\Users\\user\\Desktop\\new\\nevada_locker\\target\\release\\deps\\nevada.pdb" 
        or any of ($nevada*))
        and $note
        and $Git //optional (can be removed)

 }
