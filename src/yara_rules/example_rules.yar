rule Windows_Trojan_Generic {
    meta:
        description = "Detects common Windows trojan characteristics"
        author = "Security Team"
        severity = "high"
        date = "2023-07-15"
    
    strings:
        $a1 = "CreateRemoteThread" ascii wide
        $a2 = "VirtualAllocEx" ascii wide
        $a3 = "WriteProcessMemory" ascii wide
        $a4 = "ShellExecute" ascii wide
        $a5 = "WScript.Shell" ascii wide
        
        $b1 = "cmd.exe /c " ascii wide
        $b2 = "powershell -enc" ascii wide
        $b3 = "powershell.exe -w hidden" ascii wide
        $b4 = "certutil -decode" ascii wide
        
        $c1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $c2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($a*)) or
            (2 of ($b*)) or
            (1 of ($c*) and (1 of ($a*) or 1 of ($b*)))
        )
}

rule Suspicious_Base64_PE {
    meta:
        description = "Detects base64 encoded PE files"
        author = "Security Team"
        severity = "medium"
        date = "2023-07-15"
    
    strings:
        $b64_pe = /TV(oA|pB|pQ|qA|ro)/
        
    condition:
        $b64_pe at 0 or
        $b64_pe in (0..100)
}

rule Webshell_Generic {
    meta:
        description = "Detects generic web shell characteristics"
        author = "Security Team"
        severity = "high"
        date = "2023-07-15"
    
    strings:
        $php_short = "<?php" ascii
        $asp_short = "<%" ascii
        
        $cmd1 = "shell_exec" ascii
        $cmd2 = "passthru" ascii
        $cmd3 = "system" ascii
        $cmd4 = "exec" ascii
        $cmd5 = "popen" ascii
        $cmd6 = "proc_open" ascii
        
        $asp_cmd1 = "Response.Write" ascii
        $asp_cmd2 = "CreateObject" ascii
        $asp_cmd3 = "WScript.Shell" ascii
        
        $input1 = "$_GET" ascii
        $input2 = "$_POST" ascii
        $input3 = "$_REQUEST" ascii
        $input4 = "Request" ascii
        
        $sus1 = "eval(" ascii
        $sus2 = "base64_decode(" ascii
        $sus3 = "cmd" ascii
        $sus4 = "upload" ascii
        $sus5 = "FileSave" ascii
        
    condition:
        (
            ($php_short or $asp_short) and
            (
                (1 of ($cmd*) and 1 of ($input*)) or
                (1 of ($asp_cmd*) and 1 of ($input*)) or
                (1 of ($sus*) and 1 of ($input*))
            )
        )
}

rule Ransomware_Generic {
    meta:
        description = "Detects generic ransomware characteristics"
        author = "Security Team"
        severity = "critical"
        date = "2023-07-15"
    
    strings:
        $ransom1 = "your files have been encrypted" ascii wide nocase
        $ransom2 = "your important files encryption produced" ascii wide nocase
        $ransom3 = "your documents, photos, databases and other" ascii wide nocase
        $ransom4 = "README.txt" ascii wide
        $ransom5 = "HOW_TO_DECRYPT" ascii wide
        $ransom6 = "HOW_TO_UNLOCK" ascii wide
        $ransom7 = "restore your files" ascii wide nocase
        $ransom8 = "bitcoin" ascii wide nocase
        $ransom9 = "BTC" ascii wide
        $ransom10 = "decrypt" ascii wide nocase
        $ransom11 = "encrypt" ascii wide nocase
        
        $crypto1 = "AES" ascii wide
        $crypto2 = "RSA" ascii wide
        $crypto3 = "crypto" ascii wide
        
        $ext1 = ".locked" ascii wide
        $ext2 = ".crypt" ascii wide
        $ext3 = ".encrypted" ascii wide
        $ext4 = ".encrypt" ascii wide
        $ext5 = ".wallet" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($ransom*) and 1 of ($crypto*)) or
            (2 of ($ransom*) and 1 of ($ext*)) or
            (1 of ($crypto*) and 2 of ($ext*)) or
            (3 of ($ransom*))
        )
}

rule Keylogger_Generic {
    meta:
        description = "Detects generic keylogger characteristics"
        author = "Security Team"
        severity = "high"
        date = "2023-07-15"
    
    strings:
        $api1 = "GetAsyncKeyState" ascii wide
        $api2 = "GetKeyboardState" ascii wide
        $api3 = "GetRawInputData" ascii wide
        $api4 = "RegisterRawInputDevices" ascii wide
        $api5 = "SetWindowsHookEx" ascii wide
        $api6 = "WH_KEYBOARD" ascii wide
        $api7 = "WH_KEYBOARD_LL" ascii wide
        
        $log1 = "keylog" ascii wide nocase
        $log2 = "keystroke" ascii wide nocase
        $log3 = "keyboard hook" ascii wide nocase
        $log4 = "typed" ascii wide nocase
        $log5 = "typing" ascii wide nocase
        
        $file1 = "log.txt" ascii wide
        $file2 = "keylog.txt" ascii wide
        $file3 = "keys.log" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and
        (
            (2 of ($api*)) or
            (1 of ($api*) and 1 of ($log*)) or
            (1 of ($api*) and 1 of ($file*)) or
            (2 of ($log*) and 1 of ($file*))
        )
} 