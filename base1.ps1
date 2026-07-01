    Write-Host "[!] A REBOOT is recommended to fully apply SMB1 / NetBIOS changes." -ForegroundColor Yellow
    Write-Host "    Verify afterwards by re-running Check-SmbNetbiosExposure.ps1" -ForegroundColor Gray

    if ($RebootToRecovery) {
        Write-Section "Restart into Windows Recovery Environment"
        Write-Host "[!!!] The system will RESTART into the recovery menu in $RebootDelaySeconds seconds." -ForegroundColor Red
        Write-Host "      Save your work now. To CANCEL, run:  shutdown /a" -ForegroundColor Yellow
        # /r restart, /o boot to Advanced Startup Options (WinRE), /t delay, /c comment
        shutdown.exe /r /o /t $RebootDelaySeconds /c "Reboot to recovery after SMB/NetBIOS hardening"
        Write-Host "      Reboot-to-recovery scheduled. (cancel: shutdown /a)" -ForegroundColor Gray
    } else {
        Write-Host ""
        Write-Host "[INFO] Re-run with -RebootToRecovery to restart into the recovery menu automatically." -ForegroundColor Gray
    }
} else {
    Write-Host "DRY-RUN complete. No changes made." -ForegroundColor White
    Write-Host "Re-run with -Apply to harden (add -IncludeServices to also disable legacy services)." -ForegroundColor Gray
    if ($RebootToRecovery) {
        Write-Host "[NOTE] -RebootToRecovery is ignored in dry-run; it only fires with -Apply." -ForegroundColor Yellow
    }
}
