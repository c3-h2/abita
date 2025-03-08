# Adli Bilişim İzleri Temizleme Aracı 

Bu PowerShell scripti, adli bilişim araştırmalarında dijital izleri yönetmek ve temizlemek için tasarlanmıştır. **Yasal amaçlarla kullanım için uygundur**. Sistem izlerini, olay günlüklerini ve dijital kalıntıları temizlemeye yönelik çeşitli araçlar içerir.

---

## 🌟 Öne Çıkan Özellikler
1. **Sysmon Sürücüsünü Kaldırma**: Sysmon izleme sürücüsünü durdurur ve kaldırır.
2. **Gutmann Metoduyla Dosya Parçalama**: 35 geçişli veri üzerine yazma ile dosyaları geri dönüşümsüz siler.
3. **USN Journal Temizleme**: Dosya sistemindeki değişiklik kayıtlarını devre dışı bırakır.
4. **Prefetch ve ShellBag Temizliği**: Sistem performans izlerini siler.
5. **Olay Günlüklerini Temizleme**: Tüm Windows olay günlüklerini sıfırlar ve servisi devre dışı bırakır.
6. **Ayrılmamış Alanı Temizleme**: Disk üzerinde kalan izleri rastgele veriyle doldurur.
7. **Windows Defender Karantina Temizliği**: Virüs karantina dosyalarını siler.

---

## 🛠️ Kurulum
1. PowerShell'i **Yönetici olarak** başlatın.
2. Scripti indirin ve dizinine gidin:
   ```powershell
   cd C:\Script\Dizin
   ```
3. Çalıştırma politikasını geçici olarak değiştirin:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   ```
4. Scripti çalıştırın:
   ```powershell
   .\AdliTemizleme.ps1
   ```

---

## 🖥️ Kullanım
Script çalıştırıldığında menü tabanlı arayüz sunar:

### Ana Menü Seçenekleri:
| Seçenek | Açıklama |
|---------|----------|
| 1       | Sysmon sürücüsünü kaldır |
| 2       | Dosyayı Gutmann metoduyla parçala |
| 3       | USN Journal'ı devre dışı bırak |
| 4       | Prefetch'i temizle ve devre dışı bırak |
| 5       | Olay günlüklerini sıfırla |
| ...     | ... |
| 16      | Tüm işlemleri otomatik çalıştır |

### Örnek Kullanım:
```powershell
# Tek dosya parçalama (35 geçiş)
Seçenek 2 > "C:\topsecret.docx"

# Tüm izleri otomatik temizle (Seçenek 16)
```

---

## 📌 Teknik Detaylar
- **Gutmann Metodu**: 35 geçişli veri üzerine yazma ile NSA standartlarında silme.
- **USN Journal**: NTFS dosya sistemindeki tüm değişiklik kayıtlarını siler.
- **ShellBag**: Windows klasör gezinme önbelleğini temizler.
- **ShimCache**: Uygulama uyumluluk önbelleğini sıfırlar.

---

## ⚠️ Önemli Uyarılar
- **Geri Dönüşü Yoktur**: Temizlenen veriler kurtarılamaz.
- **Yedek Alın**: Kritik verilerin yedeğini almadan kullanmayın.
- **Test Ortamında Deneyin**: Üretim sistemlerinde doğrudan kullanmayın.

---

## ⚠️ Yasal Uyarı
- Bu araç **yalnızca yasal çerçevede ve yetkili kurumlar tarafından** kullanılmalıdır.
- Yetkisiz kullanım, veri kaybına veya yasal yaptırımlara yol açabilir.
- Geliştirici, bu aracın kötüye kullanımından sorumlu değildir.

---
## 📜 Lisans
Bu proje [MIT Lisansı](LICENSE) altında dağıtılmaktadır.
