# ByteLock V1

**ByteLock V1** (a.k.a. *USB Security Guard Pro*) takılı USB aygıtlarını gerçek zamanlı izleyen, tarayan ve kuşkulu dosyaları karantinaya alan basit ama güçlü bir Windows tabanlı USB güvenlik aracıdır.
---

## 📌 Özellikler

- Gerçek zamanlı USB izleme (tak / çıkar olaylarını algılar)
- Otomatik veya manuel tarama (derin tarama/başlık imzası analizi)
- Tehlikeli uzantı / şüpheli isim / magic-bytes (dosya imzası) kontrolü
- Bilinen kötü hash'lerle karşılaştırma (hash veritabanı desteklenebilir)
- Karantina modu (taşınan dosyalar `USB_Quarantine` klasörüne alınır)
- Whitelist / Blacklist ile USB cihaz kontrolü (seri numarasına göre)
- Aktivite/günlük ve tespit edilen tehditler için arayüz
- Basit ayarlar: otomatik tarama, otomatik temizlik, bildirim, autorun engelleme vb.

---

## ⚙️ Gereksinimler

- **Sistem:** Windows (win32 API kullanımı var)
- **Python:** 3.8+
- Kütüphaneler:
  - `pywin32`
  - `psutil`
  - (standart kütüphaneler: `tkinter`, `hashlib`, `json`, `shutil`, vb.)

Yükleme örneği:
```bash
pip install pywin32 psutil
```

> Not: `tkinter` genellikle Python ile birlikte gelir; gelmezse Python yükleyicinden ekleyin.

---

## 🚀 Kurulum & Çalıştırma

1. Repo / dosyaları bir klasöre koy.
2. Gerekli paketleri yükleyin (`pip install pywin32 psutil`).
3. `bytelock_config.json`, `usb_whitelist.json`, `usb_blacklist.json` dosyaları otomatik oluşturulur (kod çalıştırıldığında).
4. Programı çalıştır:
```bash
python bytelock.py
```
veya Windows için GUI olmadan arka planda çalıştırmak istersen `pythonw` kullanılabilir (otomatik başlatma ayarı ile birlikte).

---

## 🧭 Kullanım (GUI)

- **İzlemeyi Başlat / Durdur:** Ana ekrandaki butonlarla.
- **Manuel Tarama:** Tüm bağlı USB sürücüler taranır.
- **Karantina Göster:** Karantina klasöründeki dosyaları listeler; silme mümkündür.
- **Whitelist / Blacklist Yönet:** Seri numarası bazlı kontrol ve düzenleme.
- **USB Detayları:** Seçili sürücü hakkında hızlı bilgi.
- **Ayarlar:** Otomatik tarama, autorun engelleme, derin tarama, hash kontrol, bildirimler vb.

---

## 📁 Konfigürasyon dosyaları

Program şu json dosyalarını kullanır/oluşturur:

- `bytelock_config.json` — ayarlar
```json
{
  "auto_start": false,
  "auto_scan": true,
  "auto_clean": false,
  "deep_scan": true,
  "quarantine_mode": true,
  "hash_check": true,
  "size_limit": 100,
  "notifications": true,
  "block_autorun": true
}
```

- `usb_whitelist.json` ve `usb_blacklist.json` — örnek içerik:
```json
["1234-ABCD-5678", "SERIAL-EXAMPLE-0001"]
```
(Program seri numarası ile kontrol yapar; gerçek seri formatı Windows tarafından döndürülen değere bağlıdır.)

---

## 🔒 Karantina

- Karantinaya alınan dosyalar `USB_Quarantine/` klasörüne taşınır ve zaman damgası ile adlandırılır.
- Karantina yöneticisi penceresinden dosya silme mümkün, geri yükleme şu an **devre dışı** (güvenlik kararı).

---

## 🧪 Test & Örnek Senaryolar

- USB tak -> otomatik tarama (ayarlıysa) -> tehlike tespit edilirse karantina veya kullanıcıya bildirim.
- Büyük dosya atlama: `size_limit` MB üzerindeki dosyalar taranmadan atlanır (performans için).
- Whitelist/Blacklist test: aynı USB seri numarası ile ekleyip tekrar bağlayarak davranışı doğrula.

---

## 🛑 Güvenlik & Etik Uyarısı

- Bu araç yalnızca **izinli sistemlerde** kullanılmalıdır. Başkalarının verilerine zarar verilecek, gizliliğini ihlal edecek veya kötü amaçlı kullanım kesinlikle yasaktır.
- Karantina/otomatik silme işlevleri veri kaybına yol açabilir — kritik veriye sahip cihazlarda dikkatli kullan.

---

## 📦 Katkı & Lisans

- Katkılar (bug fix, geliştirme) hoş karşılanır.  
- README ve kodu kullanmadan önce lisans/dağıtım şartlarını kendi politikanla uyumlu hale getir.

---

## 📝 Kısa Demo (Hızlı Başlangıç)

1. Gerekli paketleri kur:
```bash
pip install pywin32 psutil
```
2. Script'i çalıştır:
```bash
python bytelock.py
```
3. GUI açıldıktan sonra `İzlemeyi Başlat` butonuna bas, bir USB tak ve logları izle.

--------------------------------------------------------------------------------------

# ByteLock V1

**ByteLock V1** (a.k.a. *USB Security Guard Pro*) is a simple yet powerful Windows-based USB security tool that monitors connected USB devices in real-time, scans them, and quarantines suspicious files.

---

## Features

* Real-time USB monitoring (detects plug/unplug events)
* Automatic or manual scanning (deep scan / file signature analysis)
* Checks for dangerous extensions / suspicious names / magic bytes (file signature)
* Compares against known malicious hashes (hash database supported)
* Quarantine mode (moved files are stored in `USB_Quarantine` folder)
* Whitelist / Blacklist USB device control (based on serial number)
* Activity/logs and detected threats interface
* Simple settings: auto-scan, auto-clean, notifications, autorun blocking, etc.

---

## ⚙️ Requirements

* **System:** Windows (uses Win32 API)
* **Python:** 3.8+
* Libraries:

  * `pywin32`
  * `psutil`
  * (standard libraries: `tkinter`, `hashlib`, `json`, `shutil`, etc.)

Installation example:

```bash
pip install pywin32 psutil
```

> Note: `tkinter` usually comes with Python; if not, add it via the Python installer.

---

## Installation & Running

1. Place the repo/files into a folder.
2. Install required packages (`pip install pywin32 psutil`).
3. `bytelock_config.json`, `usb_whitelist.json`, and `usb_blacklist.json` are auto-created when the code runs.
4. Run the program:

```bash
python bytelock.py
```

Or, for background execution without GUI on Windows, use `pythonw` (works with auto-start settings).

---

## Usage (GUI)

* **Start / Stop Monitoring:** Use the buttons on the main screen.
* **Manual Scan:** Scans all connected USB drives.
* **Show Quarantine:** Lists files in the quarantine folder; deletion possible.
* **Manage Whitelist / Blacklist:** Control and edit based on serial numbers.
* **USB Details:** Quick info about the selected drive.
* **Settings:** Auto-scan, autorun blocking, deep scan, hash checking, notifications, etc.

---

## Configuration Files

The program uses/creates the following JSON files:

* `bytelock_config.json` — settings

```json
{
  "auto_start": false,
  "auto_scan": true,
  "auto_clean": false,
  "deep_scan": true,
  "quarantine_mode": true,
  "hash_check": true,
  "size_limit": 100,
  "notifications": true,
  "block_autorun": true
}
```

* `usb_whitelist.json` and `usb_blacklist.json` — sample content:

```json
["1234-ABCD-5678", "SERIAL-EXAMPLE-0001"]
```

(The program checks based on the serial number; the actual format depends on Windows.)

---

## Quarantine

* Files moved to quarantine are stored in `USB_Quarantine/` folder and renamed with a timestamp.
* Deletion from the quarantine manager is possible; **restore is currently disabled** (security decision).

---

## Testing & Example Scenarios

* Insert a USB -> auto-scan (if enabled) -> if a threat is detected, it is quarantined or notified to the user.
* Large file skipping: files over `size_limit` MB are skipped (for performance).
* Whitelist/Blacklist test: add the same USB serial and reconnect to verify behavior.

---

## Security & Ethical Warning

* This tool should only be used on **authorized systems**. Using it to damage others’ data, violate privacy, or malicious purposes is strictly prohibited.
* Quarantine / auto-delete functions may cause data loss — use caution on devices containing critical data.

---

## Contributing & License

* Contributions (bug fixes, improvements) are welcome.
* Before using the README and code, make sure to comply with your own licensing/distribution policies.

---

## Quick Demo (Getting Started)

1. Install required packages:

```bash
pip install pywin32 psutil
```

2. Run the script:

```bash
python bytelock.py
```

3. Once the GUI opens, click `Start Monitoring`, insert a USB, and watch the logs.
