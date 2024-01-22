rule HydraAndroidStrings
{
    meta:
        description = "Detects Hydra Android malware samples based on the strings matched"
        author = "RustyNoob619"
        hash = "789d04c93488adf85d8d7988c0d050648cd91ad469f9e63e04d290523dfb1d93"
    strings:
        $anrd = "AndroidManifest.xml"

        $per1 = "android.permission.FOREGROUND_SERVICE" 
        $per2 = "android.permission.REORDER_TASKS"
        $per3 = "android.permission.RECEIVE_SMS"
        $per4 = "android.permission.SEND_SMS"
        $per5 = "android.permission.CALL_PHONE"
        $per6 = "android.permission.WAKE_LOCK"
        $per7 = "android.permission.SYSTEM_ALERT_WINDOW"
        $per8 = "android.permission.ACCESS_WIFI_STATE"
        $per9 = "android.permission.CAPTURE_VIDEO_OUTPUT"
        $per10 = "android.permission.DISABLE_KEYGUARD"
        $per11 = "android.permission.ACCESS_NETWORK_STATE"
        $per12 = "android.permission.INTERNET"
        $per13 = "android.permission.READ_EXTERNAL_STORAGE"
        $per14 = "android.permission.WRITE_EXTERNAL_STORAGE"
        $per15 = "android.permission.REQUEST_INSTALL_PACKAGES"
        $per17 = "android.permission.REQUEST_DELETE_PACKAGES"
        $per18 = "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION"
        $per19 = "android.permission.QUERY_ALL_PACKAGES"
        $per20 = "android.permission.WRITE_SETTINGS"

        $int1 = "android.intent.action.USER_PRESENT" 
        $int2 = "android.intent.action.PACKAGE_ADDED"
        $int3 = "android.intent.action.PACKAGE_REMOVED"
        $int4 = "android.intent.action.SCREEN_ON"
        $int5 = "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE"
        $int6 = "android.intent.action.QUICKBOOT_POWERON"
        $int7 = "android.intent.action.DREAMING_STOPPED"
        $int8 = "android.intent.action.RESPOND_VIA_MESSAGEprovider"
        $int9 = "android.intent.action.SCREEN_ON"

        $instr1 = "Uninstall"
        $instr2 = "Your ID"
        $instr3 = "lock screen"
        $instr4 = "protection"
        $instr5 = "turn off"
        $instr6 = "volume down"
        $instr7 = "instruction_step_"
        $instr8 = "permissions_dialog_message"
        $instr9 = "permissions_dialog_title"
        $instr10 = "volume up"

        $grnd1 = "com.grand.brothan" wide
        $grnd2 = "com.grand.snail.core.injects_core.CHandler"
        $grnd3 = "com.grand.snail.core.injects_core.Worker"
        $grnd4 = "com.grand.snail.core.injects_core.Screen"
        $grnd5 = "com.grand.snail.WebViewActivity"
        $grnd6 = "com.grand.snail.MainActivity"
        $grnd7 = "com.grand.snail.bot.components.locker.LockerActivity"
        $grnd8 = "com.grand.snail.bot.HelperAdmin"
        $grnd9 = "com.grand.snail.bot.components.injects.system.FullscreenOverlayService"
        $grnd10 = "com.grand.snail.bot.components.commands.NLService"
        $grnd11 = "com.grand.snail.bot.receivers.MainReceiver"
        $grnd12 = "com.grand.snail.core.PeriodicJobService"
        $grnd13 = "com.grand.snail.bot.sms.MmsReceiver"
        $grnd14 = "com.grand.snail.bot.sms.HeadlessSmsSendService"
        $grnd15 = "com.grand.snail.provider"
        
    condition:
        $anrd
        and 15 of ($per*) 
        and 6 of ($int*)
        and 6 of ($instr*)
        and 10 of ($grnd*)
}