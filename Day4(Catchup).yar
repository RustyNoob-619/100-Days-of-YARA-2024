import "pe"

rule TTP_Anti_Analysis_Imports
{
  meta:
    author = "RustyNoob619"
    description = "Detects suspicious KERNEL32 DLL Imports which are typically associated to Anti Analysis Techniques"
    Instruction = "Do not use as a standalone Rule, combine with other YARA Rules"
  condition:
    pe.imports("KERNEL32.dll","GetTickCount")
    or pe.imports("KERNEL32.dll","QueryPerformanceCounter")

}
