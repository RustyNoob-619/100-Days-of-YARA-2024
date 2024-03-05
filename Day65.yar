import "pe"

rule DLL_Banking_Trojan_Chavecloak_March2024 {
    meta:
        Description = "Detects the lightshot DLL (Final Payload) which is the Chavecloak Banking Trojan which was used to target banks in Brazil"
        Author = "RustyNoob619"
        Reference = "https://www.fortinet.com/blog/threat-research/banking-trojan-chavecloak-targets-brazil"
        Hash = "131d2aa44782c8100c563cd5febf49fcb4d26952d7e6e2ef22f805664686ffff"

   condition:
          pe.number_of_signatures == 0

          and pe.imports("user32.dll","ActivateKeyboardLayout")
          and pe.imports("user32.dll","KillTimer")
          and pe.imports("user32.dll","OpenClipboard")
          and pe.imports("user32.dll","AdjustWindowRectEx")

          and pe.imports("advapi32.dll","RegUnLoadKeyW")
          and pe.imports("advapi32.dll","RegFlushKey")

          and pe.imports("comctl32.dll","_TrackMouseEvent")
          and pe.imports("comctl32.dll","InitCommonControls")

          and pe.imports("ole32.dll","IsEqualGUID")
          and pe.imports("winmm.dll","timeGetTime")
          and pe.imports("winspool.drv","DocumentPropertiesW")
          and pe.imports("shell32.dll","Shell_NotifyIconW")
          and pe.imports("netapi32.dll","NetWkstaGetInfo")
          and pe.imports("version.dll","VerQueryValueW")

          and pe.exports("DeinitLightshot")
          and pe.exports("InitLightshot")
          and pe.exports("MakeScreenshotByCommand")
          and pe.exports("MakeScreenshot")

 }
