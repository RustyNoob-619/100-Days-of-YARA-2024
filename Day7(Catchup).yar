import "pe"

rule DLL_PyPi_Loader_Lazarus_March2024 {
    meta:
        Description = "Detects the Loader component of the Malicious PyPi Packages distributed by Lazarus Group based on PDB Paths"
        Author = "RustyNoob619"
        Reference = "https://blogs.jpcert.or.jp/en/2024/02/lazarus_pypi.html"
        Hash = "01c5836655c6a4212676c78ec96c0ac6b778a411e61a2da1f545eba8f784e980"

    condition:
        for all export in pe.export_details:
        (export.name startswith "CalculateSum")
        or (pe.pdb_path == "F:\\workspace\\CBG\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb"
        or pe.pdb_path == "F:\\workspace\\CBG\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb"
        or pe.pdb_path == "D:\\workspace\\CBG\\Windows\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb"
        or pe.pdb_path == "F:\\workspace\\CBG\\Loader\\publicLoaderFirst\\x64\\Release\\publicLoaderFirst.pdb")
       
 }




 

 
