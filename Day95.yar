
rule APT_Muddy_Water_MSI_RMM_Atera_April2024 {
    meta:
        Description = "Detects suspicious use of MSI Packages serving RMM Tool Atera used by APT Muddy Water in their Iron Swords Campaign"
        Author = "RustyNoob619"
        Reference = "https://www.malwation.com/blog/new-muddywater-campaigns-after-operation-swords-of-iron"
        File_Hash = "ffbe988fd797cbb9a1eedb705cf00ebc8277cdbd9a21b6efb40a8bc22c7a43f0"
        Info = "Since RMM tools are legit, it might generate raise False Positives in your environment"
    
    strings:
        $header = {d0	cf	11	e0	a1	b1	1a	e1} //MSI Header

        $msi1 = "msi.dll" fullword 
        $msi2 = "AVRemoteMsiSession@@" fullword

        $atera1 = "AteraAgent.exe" fullword
        $atera2 = "AteraAgentWD.exe" fullword
        $atera3 = "AteraNLogger.exe" fullword
        $atera4 = "AteraAgent" fullword

        $integrator = "eTuple.dll{38F01010-E311-4A27-8CA1-7D47222D9F74}BouncyCastle.Crypto.dll{B4CD9D10-FD72-430C-B045-A3113DECEB70}SetCustomActionPropertyValuesPostUninstallCleanupSKIPCLEANUP=[SKIPCLEANUP]PormptInstallationDialogShouldContinueInstallationPormptPreventUninstallDialogShouldPreventUninstallMyProcess.TaskKillCAQuietExecStopAteraServiceQuietWixQuietExecKillAteraTaskQuietKillAteraServicesc delete AteraAgentoldVersionUninstallunins000.exe /VERYSILENTinstall/i /IntegratorLogin=\"[INTEGRATORLOGIN]\" /CompanyId=\"[COMPANYID]\" /IntegratorLoginUI=\"[INTEGRATORLOGINUI]\" /CompanyIdUI=\"[COMPANYIDUI]\" /FolderId=\"[FOLDERID]\" /AccountId=\"[ACCOUNTID]\"uninstall/uDeleteTaskSchedulerSCHTASKS.EXE /delete /tn \"Monitoring Recovery\" /fWindowsFolderWINDOWSATERAwb3zdtk"
        
        $more1 = "AteraAgentProgramFilesFolder2rohim_f"
        $more2 = "ATERA Networks.SourceDirINSTALLFOLDER_files_Featureculrpfxg.exe"
        $more3 = "AteraAgent.exe1.8.6.707uho0yn3.con"
        $more4 = "AteraAgent.exe.configfd-i8f6f.dll"

    condition:
        $header at 0 
        and any of ($msi*)
        and any of ($atera*)
        and $integrator
        and any of ($more*)
        

 }
