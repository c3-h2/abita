# Anti Forensic Scripti
# Bu script sistem izlerini ve dijital kalıntıları yönetmeye yardımcı olur
# Lütfen yasal çerçeve içinde kullanınız

function Write-LogInfo {
    param (
        [string]$Message
    )
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-LogWarning {
    param (
        [string]$Message
    )
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-LogError {
    param (
        [string]$Message
    )
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Administrator olarak çalıştırılıp çalıştırılmadığını kontrol et
function Test-Administrator {
    $user = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $user
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-LogError "Bu script administratör yetkileri gerektirir. Lütfen PowerShell'i yönetici olarak başlatıp tekrar deneyin."
    exit
}

Write-LogWarning "Bu tool yasal amaçlı adli bilişim çalışmaları için tasarlanmıştır."
Write-LogWarning "Devam etmek için herhangi bir tuşa basın veya çıkmak için CTRL+C tuşlarına basın..."
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

function Unload-SysmonDriver {
    Write-LogInfo "Sysmon sürücüsü kaldırılıyor..."
    try {
        $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
        if ($sysmonService) {
            Stop-Service -Name "Sysmon" -Force
            sc.exe delete Sysmon | Out-Null
            Write-LogInfo "Sysmon sürücüsü başarıyla kaldırıldı."
        }
        else {
            Write-LogWarning "Sysmon servisi bulunamadı."
        }
    }
    catch {
        Write-LogError "Sysmon sürücüsü kaldırma hatası: $_"
    }
}

function Shred-File {
    param (
        [string]$FilePath,
        [int]$Passes = 35
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-LogWarning "Dosya bulunamadı: $FilePath"
            return
        }
        
        $fileInfo = Get-Item $FilePath
        $fileSize = $fileInfo.Length
        
        # Dosya boyutunu al
        Write-LogInfo "Dosya parçalanıyor: $FilePath ($fileSize bayt)"
        
        # Gutmann metoduna göre (35 geçiş) dosyayı üzerine yaz
        $fileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
        $writer = New-Object System.IO.BinaryWriter($fileStream)
        
        # Rastgele veri oluşturmak için Random sınıfını kullan
        $random = New-Object System.Random
        $buffer = New-Object byte[] $fileSize
        
        for ($pass = 1; $pass -le $Passes; $pass++) {
            # Her geçiş için farklı doldurma desenini seç (Gutmann yöntemi)
            if ($pass -le 4) {
                # İlk 4 geçiş rastgele veri
                $random.NextBytes($buffer)
            }
            elseif ($pass -le 10) {
                # 5-10 geçişler için spesifik desenler
                [Array]::Fill($buffer, [byte]($pass % 256))
            }
            else {
                # Geri kalan geçişler için rastgele veri
                $random.NextBytes($buffer)
            }
            
            $fileStream.Position = 0
            $writer.Write($buffer)
            $fileStream.Flush()
            
            Write-Progress -Activity "Dosya parçalanıyor (Gutmann Metodu)" -Status "Geçiş $pass / $Passes" -PercentComplete (($pass / $Passes) * 100)
        }
        
        $writer.Close()
        $fileStream.Close()
        
        # Dosyayı sil
        Remove-Item -Path $FilePath -Force
        Write-LogInfo "Dosya başarıyla parçalandı ve silindi: $FilePath"
    }
    catch {
        Write-LogError "Dosya parçalama hatası: $_"
    }
}

function Disable-USNJournal {
    Write-LogInfo "USN Journal devre dışı bırakılıyor..."
    
    try {
        $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($drive in $drives) {
            $driveLetter = $drive.DeviceID
            Write-LogInfo "USN Journal kapatılıyor: $driveLetter"
            fsutil usn deletejournal /d $driveLetter | Out-Null
            Write-LogInfo "$driveLetter için USN Journal başarıyla devre dışı bırakıldı."
        }
    }
    catch {
        Write-LogError "USN Journal devre dışı bırakma hatası: $_"
    }
}

function Disable-Prefetch {
    Write-LogInfo "Prefetch devre dışı bırakılıyor..."
    
    try {
        # Prefetch servisini devre dışı bırak
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -Value 0
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnableSuperfetch" -Value 0
        
        # Prefetch dosyalarını temizle
        $prefetchPath = "$env:SystemRoot\Prefetch"
        if (Test-Path $prefetchPath) {
            Get-ChildItem -Path $prefetchPath -Filter "*.pf" | ForEach-Object {
                Shred-File -FilePath $_.FullName -Passes 3
            }
        }
        
        Write-LogInfo "Prefetch başarıyla devre dışı bırakıldı ve dosyalar temizlendi."
    }
    catch {
        Write-LogError "Prefetch devre dışı bırakma hatası: $_"
    }
}

function Clear-EventLogs {
    Write-LogInfo "Olay günlükleri temizleniyor ve devre dışı bırakılıyor..."
    
    try {
        # Tüm olay günlüklerini temizle
        wevtutil el | ForEach-Object {
            Write-LogInfo "Olay günlüğü temizleniyor: $_"
            wevtutil cl "$_" 2>$null
        }
        
        # Olay günlüğü servisini devre dışı bırak
        Set-Service -Name "eventlog" -StartupType Disabled
        Stop-Service -Name "eventlog" -Force
        
        Write-LogInfo "Olay günlükleri başarıyla temizlendi ve devre dışı bırakıldı."
    }
    catch {
        Write-LogError "Olay günlüklerini temizleme hatası: $_"
    }
}

function Disable-UserAssistUpdateTime {
    Write-LogInfo "UserAssist güncelleme zamanı devre dışı bırakılıyor..."
    
    try {
        # HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
        $userAssistPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        
        if (Test-Path $userAssistPath) {
            # UserAssist alt anahtarlarını temizle
            Get-ChildItem -Path $userAssistPath | ForEach-Object {
                $subKey = $_.PSChildName
                $countPath = "$userAssistPath\$subKey\Count"
                
                if (Test-Path $countPath) {
                    # Tüm değerleri sil
                    Remove-Item -Path $countPath -Recurse -Force
                    Write-LogInfo "UserAssist kayıtları temizlendi: $countPath"
                }
            }
        }
        
        Write-LogInfo "UserAssist güncelleme zamanı başarıyla devre dışı bırakıldı."
    }
    catch {
        Write-LogError "UserAssist güncelleme zamanını devre dışı bırakma hatası: $_"
    }
}

function Disable-AccessTime {
    Write-LogInfo "Erişim zamanı kaydı devre dışı bırakılıyor..."
    
    try {
        # NTFS dosya sistemi özelliklerini ayarla
        fsutil behavior set disablelastaccess 1 | Out-Null
        
        Write-LogInfo "Erişim zamanı kaydı başarıyla devre dışı bırakıldı."
    }
    catch {
        Write-LogError "Erişim zamanı kaydını devre dışı bırakma hatası: $_"
    }
}

function Clear-RecentItems {
    Write-LogInfo "Son kullanılan öğeler temizleniyor..."
    
    try {
        # Son kullanılan dosyaları temizle
        $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
        
        if (Test-Path $recentPath) {
            Get-ChildItem -Path $recentPath -Include *.* -Recurse | ForEach-Object {
                Shred-File -FilePath $_.FullName -Passes 3
            }
        }
        
        # Jump List'leri temizle
        $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
        if (Test-Path $jumpListPath) {
            Get-ChildItem -Path $jumpListPath -Include *.* -Recurse | ForEach-Object {
                Shred-File -FilePath $_.FullName -Passes 3
            }
        }
        
        $jumpListPath2 = "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
        if (Test-Path $jumpListPath2) {
            Get-ChildItem -Path $jumpListPath2 -Include *.* -Recurse | ForEach-Object {
                Shred-File -FilePath $_.FullName -Passes 3
            }
        }
        
        Write-LogInfo "Son kullanılan öğeler başarıyla temizlendi."
    }
    catch {
        Write-LogError "Son kullanılan öğeleri temizleme hatası: $_"
    }
}

function Clear-ShimCache {
    Write-LogInfo "Shim Cache temizleniyor..."
    
    try {
        # AppCompatCache (Shim Cache) kayıt defteri anahtarını temizle
        $shimCachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
        
        if (Test-Path $shimCachePath) {
            # AppCompatCache değerini sil
            Remove-ItemProperty -Path $shimCachePath -Name "AppCompatCache" -Force -ErrorAction SilentlyContinue
            Write-LogInfo "Shim Cache başarıyla temizlendi."
        }
        else {
            Write-LogWarning "Shim Cache kayıt defteri anahtarı bulunamadı."
        }
    }
    catch {
        Write-LogError "Shim Cache temizleme hatası: $_"
    }
}

function Clear-RecentFileCache {
    Write-LogInfo "RecentFileCache.bcf temizleniyor..."
    
    try {
        $recentFileCachePath = "$env:SystemRoot\AppCompat\Programs\RecentFileCache.bcf"
        
        if (Test-Path $recentFileCachePath) {
            Shred-File -FilePath $recentFileCachePath -Passes 3
            Write-LogInfo "RecentFileCache.bcf başarıyla temizlendi."
        }
        else {
            Write-LogWarning "RecentFileCache.bcf dosyası bulunamadı."
        }
    }
    catch {
        Write-LogError "RecentFileCache.bcf temizleme hatası: $_"
    }
}

function Clear-ShellBag {
    Write-LogInfo "ShellBag kayıtları temizleniyor..."
    
    try {
        # ShellBag kayıtlarını temizle
        $shellBagPaths = @(
            "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
            "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags",
            "HKCU:\Software\Microsoft\Windows\Shell\BagMRU",
            "HKCU:\Software\Microsoft\Windows\Shell\Bags"
        )
        
        foreach ($path in $shellBagPaths) {
            if (Test-Path $path) {
                Remove-Item -Path $path -Recurse -Force
                Write-LogInfo "ShellBag kayıtları temizlendi: $path"
            }
        }
        
        Write-LogInfo "ShellBag kayıtları başarıyla temizlendi."
    }
    catch {
        Write-LogError "ShellBag kayıtlarını temizleme hatası: $_"
    }
}

function Delete-DefenderQuarantineFiles {
    Write-LogInfo "Windows Defender karantina dosyaları siliniyor..."
    
    try {
        $quarantinePath = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
        
        if (Test-Path $quarantinePath) {
            Get-ChildItem -Path $quarantinePath -Recurse | ForEach-Object {
                Shred-File -FilePath $_.FullName -Passes 3
            }
            Write-LogInfo "Windows Defender karantina dosyaları başarıyla silindi."
        }
        else {
            Write-LogWarning "Windows Defender karantina klasörü bulunamadı."
        }
    }
    catch {
        Write-LogError "Windows Defender karantina dosyalarını silme hatası: $_"
    }
}

function Melt-File {
    param (
        [string]$FilePath
    )
    
    try {
        if (-not (Test-Path $FilePath)) {
            Write-LogWarning "Dosya bulunamadı: $FilePath"
            return
        }
        
        # Dosyayı shred et
        Shred-File -FilePath $FilePath -Passes 3
        
        # Dosya ismini değiştir
        $directory = Split-Path -Parent $FilePath
        $tempName = [System.IO.Path]::GetRandomFileName()
        $tempPath = Join-Path $directory $tempName
        
        if (Test-Path $FilePath) {
            Rename-Item -Path $FilePath -NewName $tempName -Force
            
            # Dosyayı sil
            Remove-Item -Path $tempPath -Force
        }
        
        Write-LogInfo "Dosya başarıyla eritildi: $FilePath"
    }
    catch {
        Write-LogError "Dosya eritme hatası: $_"
    }
}

function Execute-USNJournalOnAllDrives {
    Write-LogInfo "Tüm sürücülerde USN Journal çalıştırılıyor..."
    
    try {
        $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($drive in $drives) {
            $driveLetter = $drive.DeviceID
            Write-LogInfo "USN Journal oluşturuluyor ve temizleniyor: $driveLetter"
            
            # Önce mevcut journal'ı sil
            fsutil usn deletejournal /d $driveLetter | Out-Null
            
            # Yeni bir journal oluştur ve hemen sil (iz bırakma)
            fsutil usn createjournal m=1024 a=1024 $driveLetter | Out-Null
            fsutil usn deletejournal /d $driveLetter | Out-Null
            
            Write-LogInfo "$driveLetter için USN Journal işlemi tamamlandı."
        }
    }
    catch {
        Write-LogError "Tüm sürücülerde USN Journal çalıştırma hatası: $_"
    }
}

function Rewrite-UnallocatedSpace {
    Write-LogInfo "Ayrılmamış alan üzerine yazılıyor..."
    
    try {
        $drives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($drive in $drives) {
            $driveLetter = $drive.DeviceID
            Write-LogInfo "Sürücüdeki ayrılmamış alan üzerine yazılıyor: $driveLetter"
            
            # Geçici bir dosya oluştur ve disk dolana kadar yaz
            $tempFile = "$driveLetter\tempfile.tmp"
            
            try {
                $fileStream = [System.IO.File]::OpenWrite($tempFile)
                $buffer = New-Object byte[] 1048576  # 1 MB buffer
                $random = New-Object System.Random
                
                # Sürücü dolana kadar yaz
                Write-LogInfo "Sürücüye veri yazılıyor: $driveLetter (Ctrl+C ile durdurabilirsiniz)"
                
                while ($true) {
                    try {
                        $random.NextBytes($buffer)
                        $fileStream.Write($buffer, 0, $buffer.Length)
                    }
                    catch {
                        # Disk dolu veya başka bir hata oluştu
                        break
                    }
                }
            }
            catch {
                Write-LogWarning "Sürücüde ayrılmamış alan yazma hatası: $_"
            }
            finally {
                if ($fileStream) {
                    $fileStream.Close()
                }
                
                # Geçici dosyayı sil
                if (Test-Path $tempFile) {
                    Remove-Item -Path $tempFile -Force
                }
            }
            
            Write-LogInfo "$driveLetter için ayrılmamış alan üzerine yazma işlemi tamamlandı."
        }
    }
    catch {
        Write-LogError "Ayrılmamış alan üzerine yazma hatası: $_"
    }
}

# Ana menü ve işlevleri çalıştır
function Show-Menu {
    Clear-Host
    Write-Host "===== Adli Bilişim İzleri Temizleme Aracı ====="
    Write-Host "1. Sysmon Sürücüsünü Kaldır"
    Write-Host "2. Dosya Parçala (Gutmann Metodu)"
    Write-Host "3. USN Journal Devre Dışı Bırak"
    Write-Host "4. Prefetch Devre Dışı Bırak"
    Write-Host "5. Olay Günlüklerini Temizle ve Devre Dışı Bırak"
    Write-Host "6. UserAssist Güncelleme Zamanını Devre Dışı Bırak"
    Write-Host "7. Erişim Zamanı Kaydını Devre Dışı Bırak"
    Write-Host "8. Son Kullanılan Öğeleri Temizle"
    Write-Host "9. Shim Cache Temizle"
    Write-Host "10. RecentFileCache Temizle"
    Write-Host "11. ShellBag Temizle"
    Write-Host "12. Windows Defender Karantina Dosyalarını Sil"
    Write-Host "13. Dosya Erit"
    Write-Host "14. Tüm Sürücülerde USN Journal Çalıştır"
    Write-Host "15. Ayrılmamış Alan Üzerine Yaz"
    Write-Host "16. Tüm İşlemleri Otomatik Çalıştır"
    Write-Host "0. Çıkış"
    Write-Host "==========================================="
    
    $choice = Read-Host "Lütfen bir seçenek numarası girin"
    
    switch ($choice) {
        "1" { Unload-SysmonDriver; pause }
        "2" { 
            $filePath = Read-Host "Parçalanacak dosyanın yolunu girin"
            Shred-File -FilePath $filePath; 
            pause 
        }
        "3" { Disable-USNJournal; pause }
        "4" { Disable-Prefetch; pause }
        "5" { Clear-EventLogs; pause }
        "6" { Disable-UserAssistUpdateTime; pause }
        "7" { Disable-AccessTime; pause }
        "8" { Clear-RecentItems; pause }
        "9" { Clear-ShimCache; pause }
        "10" { Clear-RecentFileCache; pause }
        "11" { Clear-ShellBag; pause }
        "12" { Delete-DefenderQuarantineFiles; pause }
        "13" { 
            $filePath = Read-Host "Eritilecek dosyanın yolunu girin"
            Melt-File -FilePath $filePath; 
            pause 
        }
        "14" { Execute-USNJournalOnAllDrives; pause }
        "15" { Rewrite-UnallocatedSpace; pause }
        "16" { 
            Write-LogWarning "Tüm işlemler otomatik olarak çalıştırılacak. Bu işlem uzun sürebilir."
            Write-LogWarning "Devam etmek için herhangi bir tuşa basın veya çıkmak için CTRL+C tuşlarına basın..."
            $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            
            Unload-SysmonDriver
            Disable-USNJournal
            Disable-Prefetch
            Clear-EventLogs
            Disable-UserAssistUpdateTime
            Disable-AccessTime
            Clear-RecentItems
            Clear-ShimCache
            Clear-RecentFileCache
            Clear-ShellBag
            Delete-DefenderQuarantineFiles
            Execute-USNJournalOnAllDrives
            Rewrite-UnallocatedSpace
            
            Write-LogInfo "Tüm işlemler tamamlandı."
            pause
        }
        "0" { return $false }
        default { Write-LogWarning "Geçersiz seçenek. Lütfen tekrar deneyin."; pause }
    }
    
    return $true
}

# Ana döngü
$continue = $true
while ($continue) {
    $continue = Show-Menu
}

Write-LogInfo "Program sonlandırıldı."
