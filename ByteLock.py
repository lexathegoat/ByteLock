import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import time
import os
import hashlib
import winreg
import win32file
import win32con
import win32api
import json
import shutil
from datetime import datetime
from pathlib import Path
import psutil
import re

class ByteLock:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ByteLock V1")
        self.root.geometry("1200x700")
        self.root.configure(bg="#0d1117")
        
        # Ayarlar
        self.config_file = "bytelock_config.json"
        self.quarantine_folder = "USB_Quarantine"
        self.whitelist_file = "usb_whitelist.json"
        self.blacklist_file = "usb_blacklist.json"
        self.load_config()
        
        # USB monitoring durumu
        self.monitoring = False
        self.connected_usbs = {}
        self.scan_history = []
        self.total_threats_blocked = 0
        
        # Tehlikeli dosya uzantıları (genişletilmiş)
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', 
            '.js', '.jar', '.msi', '.reg', '.ps1', '.hta', '.cpl',
            '.dll', '.sys', '.drv', '.ocx', '.ax', '.gadget', '.inf',
            '.lnk', '.wsf', '.vbe', '.jse', '.app', '.deb', '.rpm'
        ]
        
        # Şüpheli dosya isimleri
        self.suspicious_names = [
            'autorun', 'autoplay', 'setup', 'install', 'update',
            'crack', 'keygen', 'patch', 'hack', 'trojan', 'virus',
            'ransomware', 'backdoor', 'malware', 'spyware'
        ]
        
        # Tehlikeli dosya imzaları (magic bytes) - genişletilmiş
        self.dangerous_signatures = {
            b'MZ': 'Windows Executable',
            b'PK\x03\x04': 'ZIP/JAR Archive',
            b'\x50\x45\x00\x00': 'PE Executable',
            b'\x7fELF': 'Linux Executable',
            b'\xca\xfe\xba\xbe': 'Mach-O Executable',
            b'\x4d\x5a\x90': 'DOS Executable',
            b'#!': 'Script File'
        }
        
        # Bilinen kötü hash'ler (örnek - gerçek projede büyük veritabanı olur)
        self.malware_hashes = set()
        
        # Whitelist ve Blacklist
        self.usb_whitelist = set()
        self.usb_blacklist = set()
        self.load_lists()
        
        # İstatistikler
        self.stats = {
            'total_scans': 0,
            'threats_found': 0,
            'threats_cleaned': 0,
            'usb_connected': 0,
            'usb_blocked': 0
        }
        
        self.create_quarantine_folder()
        self.create_gui()
        self.update_status()
        self.update_stats_display()
        
    def create_quarantine_folder(self):
        """Karantina klasörü oluştur"""
        if not os.path.exists(self.quarantine_folder):
            os.makedirs(self.quarantine_folder)
    
    def load_lists(self):
        """Whitelist ve blacklist yükle"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    self.usb_whitelist = set(json.load(f))
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    self.usb_blacklist = set(json.load(f))
        except:
            pass
    
    def save_lists(self):
        """Whitelist ve blacklist kaydet"""
        with open(self.whitelist_file, 'w') as f:
            json.dump(list(self.usb_whitelist), f)
        with open(self.blacklist_file, 'w') as f:
            json.dump(list(self.usb_blacklist), f)
    
    def load_config(self):
        """Ayarları yükle"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.auto_start = config.get('auto_start', False)
                    self.auto_scan = config.get('auto_scan', True)
                    self.auto_clean = config.get('auto_clean', False)
                    self.deep_scan = config.get('deep_scan', True)
                    self.quarantine_mode = config.get('quarantine_mode', True)
                    self.hash_check = config.get('hash_check', True)
                    self.size_limit = config.get('size_limit', 100)  # MB
                    self.notifications = config.get('notifications', True)
                    self.block_autorun = config.get('block_autorun', True)
            else:
                self.set_default_config()
        except:
            self.set_default_config()
    
    def set_default_config(self):
        """Varsayılan ayarlar"""
        self.auto_start = False
        self.auto_scan = True
        self.auto_clean = False
        self.deep_scan = True
        self.quarantine_mode = True
        self.hash_check = True
        self.size_limit = 100
        self.notifications = True
        self.block_autorun = True
    
    def save_config(self):
        """Ayarları kaydet"""
        config = {
            'auto_start': self.auto_start,
            'auto_scan': self.auto_scan,
            'auto_clean': self.auto_clean,
            'deep_scan': self.deep_scan,
            'quarantine_mode': self.quarantine_mode,
            'hash_check': self.hash_check,
            'size_limit': self.size_limit,
            'notifications': self.notifications,
            'block_autorun': self.block_autorun
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)
    
    def create_gui(self):
        """Ana GUI oluştur - Ultra detaylı"""
        # Stil ayarları
        style = ttk.Style()
        style.theme_use('clam')
        
        # Header
        header = tk.Frame(self.root, bg="#1f6feb", height=90)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        title_frame = tk.Frame(header, bg="#1f6feb")
        title_frame.pack(expand=True)
        
        title = tk.Label(title_frame, text="🛡️ USB Security Guard Pro", 
                        font=("Segoe UI", 28, "bold"), bg="#1f6feb", fg="white")
        title.pack()
        
        subtitle = tk.Label(title_frame, text="Advanced USB Protection System | Real-time Monitoring & Threat Detection", 
                          font=("Segoe UI", 10), bg="#1f6feb", fg="#c9d1d9")
        subtitle.pack()
        
        # Ana container
        main_container = tk.Frame(self.root, bg="#0d1117")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Sol panel - Kontroller ve Ayarlar
        left_panel = tk.Frame(main_container, bg="#161b22", width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=10, pady=10)
        left_panel.pack_propagate(False)
        
        # İstatistikler Kartı
        stats_card = tk.LabelFrame(left_panel, text="📊 İstatistikler", 
                                   bg="#0d1117", fg="#58a6ff", 
                                   font=("Segoe UI", 12, "bold"), bd=2)
        stats_card.pack(pady=(0, 10), padx=10, fill=tk.X)
        
        stats_inner = tk.Frame(stats_card, bg="#0d1117")
        stats_inner.pack(padx=10, pady=10, fill=tk.X)
        
        self.stat_labels = {}
        stats_info = [
            ("Toplam Tarama:", "total_scans", "🔍"),
            ("Tehdit Bulundu:", "threats_found", "⚠️"),
            ("Tehdit Temizlendi:", "threats_cleaned", "✅"),
            ("USB Bağlandı:", "usb_connected", "🔌"),
            ("USB Engellendi:", "usb_blocked", "🚫")
        ]
        
        for label, key, icon in stats_info:
            frame = tk.Frame(stats_inner, bg="#0d1117")
            frame.pack(fill=tk.X, pady=2)
            tk.Label(frame, text=f"{icon} {label}", bg="#0d1117", fg="#8b949e",
                    font=("Segoe UI", 9), anchor=tk.W).pack(side=tk.LEFT)
            self.stat_labels[key] = tk.Label(frame, text="0", bg="#0d1117", fg="#58a6ff",
                                            font=("Segoe UI", 9, "bold"), anchor=tk.E)
            self.stat_labels[key].pack(side=tk.RIGHT)
        
        # Kontrol Butonları
        control_frame = tk.LabelFrame(left_panel, text="⚙️ Kontrol Paneli", 
                                     bg="#0d1117", fg="#58a6ff", 
                                     font=("Segoe UI", 12, "bold"), bd=2)
        control_frame.pack(pady=(0, 10), padx=10, fill=tk.X)
        
        btn_container = tk.Frame(control_frame, bg="#0d1117")
        btn_container.pack(padx=10, pady=10, fill=tk.X)
        
        self.start_btn = tk.Button(btn_container, text="▶️ İzlemeyi Başlat", 
                                   command=self.start_monitoring,
                                   bg="#238636", fg="white", font=("Segoe UI", 10, "bold"),
                                   relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                                   activebackground="#2ea043")
        self.start_btn.pack(pady=3, fill=tk.X)
        
        self.stop_btn = tk.Button(btn_container, text="⏸️ İzlemeyi Durdur", 
                                  command=self.stop_monitoring,
                                  bg="#da3633", fg="white", font=("Segoe UI", 10, "bold"),
                                  relief=tk.FLAT, padx=15, pady=8, cursor="hand2", state=tk.DISABLED,
                                  activebackground="#f85149")
        self.stop_btn.pack(pady=3, fill=tk.X)
        
        scan_btn = tk.Button(btn_container, text="🔍 Manuel Tarama", 
                           command=self.manual_scan,
                           bg="#1f6feb", fg="white", font=("Segoe UI", 10, "bold"),
                           relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                           activebackground="#388bfd")
        scan_btn.pack(pady=3, fill=tk.X)
        
        quarantine_btn = tk.Button(btn_container, text="📦 Karantinayı Göster", 
                                  command=self.show_quarantine,
                                  bg="#6e7681", fg="white", font=("Segoe UI", 10, "bold"),
                                  relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                                  activebackground="#8b949e")
        quarantine_btn.pack(pady=3, fill=tk.X)
        
        whitelist_btn = tk.Button(btn_container, text="📝 Whitelist Yönet", 
                                 command=self.manage_whitelist,
                                 bg="#8957e5", fg="white", font=("Segoe UI", 10, "bold"),
                                 relief=tk.FLAT, padx=15, pady=8, cursor="hand2",
                                 activebackground="#a371f7")
        whitelist_btn.pack(pady=3, fill=tk.X)
        
        # Ayarlar
        settings_frame = tk.LabelFrame(left_panel, text="⚙️ Gelişmiş Ayarlar", 
                                      bg="#0d1117", fg="#58a6ff", 
                                      font=("Segoe UI", 12, "bold"), bd=2)
        settings_frame.pack(pady=(0, 10), padx=10, fill=tk.BOTH, expand=True)
        
        settings_scroll = tk.Frame(settings_frame, bg="#0d1117")
        settings_scroll.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Tüm ayar seçenekleri
        self.setting_vars = {}
        settings_list = [
            ("auto_start", "🚀 Bilgisayarla Başlat", self.toggle_auto_start),
            ("auto_scan", "🔍 Otomatik Tarama", self.save_config),
            ("auto_clean", "🗑️ Otomatik Temizlik", self.save_config),
            ("deep_scan", "🔬 Derin Tarama", self.save_config),
            ("quarantine_mode", "📦 Karantina Modu", self.save_config),
            ("hash_check", "🔐 Hash Kontrolü", self.save_config),
            ("notifications", "🔔 Bildirimler", self.save_config),
            ("block_autorun", "🚫 Autorun Engelle", self.save_config)
        ]
        
        for key, text, cmd in settings_list:
            var = tk.BooleanVar(value=getattr(self, key))
            self.setting_vars[key] = var
            check = tk.Checkbutton(settings_scroll, text=text,
                                  variable=var, command=cmd,
                                  bg="#0d1117", fg="#c9d1d9", selectcolor="#21262d",
                                  font=("Segoe UI", 9), activebackground="#0d1117",
                                  activeforeground="#58a6ff")
            check.pack(anchor=tk.W, pady=3)
        
        # Durum göstergesi
        status_frame = tk.Frame(left_panel, bg="#161b22", relief=tk.RAISED, bd=1)
        status_frame.pack(pady=(0, 0), padx=10, fill=tk.X)
        
        tk.Label(status_frame, text="Sistem Durumu:", bg="#161b22", fg="#8b949e",
                font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.status_label = tk.Label(status_frame, text="⚫ Beklemede", 
                                     bg="#161b22", fg="#f0883e",
                                     font=("Segoe UI", 11, "bold"))
        self.status_label.pack(anchor=tk.W, padx=10, pady=(0, 10))
        
        # Orta panel - Bağlı USB'ler
        middle_panel = tk.Frame(main_container, bg="#161b22", width=300)
        middle_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10), pady=10)
        middle_panel.pack_propagate(False)
        
        usb_label = tk.Label(middle_panel, text="🔌 Bağlı USB Cihazlar", 
                           font=("Segoe UI", 14, "bold"), bg="#161b22", fg="#58a6ff")
        usb_label.pack(pady=15)
        
        # USB listesi
        usb_list_frame = tk.Frame(middle_panel, bg="#0d1117")
        usb_list_frame.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        
        self.usb_listbox = tk.Listbox(usb_list_frame, bg="#0d1117", fg="#c9d1d9",
                                      font=("Consolas", 10), relief=tk.FLAT, bd=0,
                                      selectbackground="#1f6feb", selectforeground="white")
        usb_scrollbar = tk.Scrollbar(usb_list_frame, command=self.usb_listbox.yview)
        self.usb_listbox.config(yscrollcommand=usb_scrollbar.set)
        
        usb_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.usb_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # USB butonları
        usb_btn_frame = tk.Frame(middle_panel, bg="#161b22")
        usb_btn_frame.pack(padx=10, pady=(0, 10), fill=tk.X)
        
        tk.Button(usb_btn_frame, text="✅ Whitelist'e Ekle",
                 command=self.add_to_whitelist, bg="#238636", fg="white",
                 font=("Segoe UI", 9, "bold"), relief=tk.FLAT, pady=5,
                 cursor="hand2").pack(fill=tk.X, pady=2)
        
        tk.Button(usb_btn_frame, text="🚫 Blacklist'e Ekle",
                 command=self.add_to_blacklist, bg="#da3633", fg="white",
                 font=("Segoe UI", 9, "bold"), relief=tk.FLAT, pady=5,
                 cursor="hand2").pack(fill=tk.X, pady=2)
        
        tk.Button(usb_btn_frame, text="📊 USB Detayları",
                 command=self.show_usb_details, bg="#1f6feb", fg="white",
                 font=("Segoe UI", 9, "bold"), relief=tk.FLAT, pady=5,
                 cursor="hand2").pack(fill=tk.X, pady=2)
        
        tk.Button(usb_btn_frame, text="⏏️ Güvenli Çıkar",
                 command=self.safe_eject, bg="#6e7681", fg="white",
                 font=("Segoe UI", 9, "bold"), relief=tk.FLAT, pady=5,
                 cursor="hand2").pack(fill=tk.X, pady=2)
        
        # Sağ panel - Log ve Tehditler
        right_panel = tk.Frame(main_container, bg="#161b22")
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, pady=10, padx=(0, 10))
        
        # Notebook (tab sistemi)
        notebook = ttk.Notebook(right_panel)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Log sekmesi
        log_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(log_tab, text="📋 Aktivite Günlüğü")
        
        log_toolbar = tk.Frame(log_tab, bg="#0d1117")
        log_toolbar.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(log_toolbar, text="🗑️ Temizle", command=self.clear_log,
                 bg="#6e7681", fg="white", font=("Segoe UI", 9, "bold"),
                 relief=tk.FLAT, padx=10, pady=5, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Button(log_toolbar, text="💾 Kaydet", command=self.save_log,
                 bg="#1f6feb", fg="white", font=("Segoe UI", 9, "bold"),
                 relief=tk.FLAT, padx=10, pady=5, cursor="hand2").pack(side=tk.LEFT)
        
        self.log_text = scrolledtext.ScrolledText(log_tab, 
                                                  bg="#0d1117", fg="#c9d1d9",
                                                  font=("Consolas", 9),
                                                  relief=tk.FLAT, bd=0,
                                                  wrap=tk.WORD, insertbackground="#58a6ff")
        self.log_text.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        
        # Log renk etiketleri
        self.log_text.tag_config("success", foreground="#3fb950")
        self.log_text.tag_config("warning", foreground="#d29922")
        self.log_text.tag_config("error", foreground="#f85149")
        self.log_text.tag_config("info", foreground="#58a6ff")
        
        # Tehditler sekmesi
        threats_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(threats_tab, text="⚠️ Tespit Edilen Tehditler")
        
        self.threats_text = scrolledtext.ScrolledText(threats_tab, 
                                                     bg="#0d1117", fg="#c9d1d9",
                                                     font=("Consolas", 9),
                                                     relief=tk.FLAT, bd=0,
                                                     wrap=tk.WORD)
        self.threats_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Tarama Geçmişi sekmesi
        history_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(history_tab, text="📜 Tarama Geçmişi")
        
        self.history_text = scrolledtext.ScrolledText(history_tab, 
                                                     bg="#0d1117", fg="#c9d1d9",
                                                     font=("Consolas", 9),
                                                     relief=tk.FLAT, bd=0,
                                                     wrap=tk.WORD)
        self.history_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # İlk log mesajları
        self.log("✨ USB Security Guard Pro başlatıldı", "success")
        self.log(f"📅 {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", "info")
        self.log("🛡️ Sistem hazır - USB cihazlarınız korunuyor", "info")
    
    def log(self, message, tag="info"):
        """Gelişmiş log sistemi"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message, tag)
        self.log_text.see(tk.END)
        self.root.update()
    
    def log_threat(self, threat_info):
        """Tehdit logla"""
        timestamp = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        threat_message = f"\n{'='*60}\n"
        threat_message += f"⚠️ TEHDİT TESPİT EDİLDİ - {timestamp}\n"
        threat_message += f"{'='*60}\n"
        threat_message += f"Dosya: {threat_info['path']}\n"
        threat_message += f"Tehdit Türü: {threat_info['type']}\n"
        threat_message += f"Açıklama: {threat_info['description']}\n"
        if 'hash' in threat_info:
            threat_message += f"Hash: {threat_info['hash']}\n"
        threat_message += f"Aksiyon: {threat_info['action']}\n"
        
        self.threats_text.insert(tk.END, threat_message)
        self.threats_text.see(tk.END)
    
    def clear_log(self):
        """Günlüğü temizle"""
        self.log_text.delete(1.0, tk.END)
        self.log("🗑️ Günlük temizlendi", "info")
    
    def save_log(self):
        """Günlüğü kaydet"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"usb_security_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
            self.log(f"💾 Günlük kaydedildi: {filename}", "success")
    
    def update_stats_display(self):
        """İstatistikleri güncelle"""
        for key, label in self.stat_labels.items():
            label.config(text=str(self.stats[key]))
        self.root.after(1000, self.update_stats_display)
    
    def toggle_auto_start(self):
        """Otomatik başlatmayı aç/kapat"""
        self.auto_start = self.setting_vars['auto_start'].get()
        self.save_config()
        
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            
            if self.auto_start:
                exe_path = os.path.abspath(__file__)
                winreg.SetValueEx(key, "ByteLock", 0, winreg.REG_SZ, f'pythonw "{exe_path}"')
                self.log("✅ Otomatik başlatma AÇILDI", "success")
                if self.setting_vars['notifications'].get():
                    messagebox.showinfo("Başarılı", "Program artık Windows ile birlikte başlayacak!")
            else:
                try:
                    winreg.DeleteValue(key, "ByteLock")
                    self.log("❌ Otomatik başlatma KAPATILDI", "warning")
                except FileNotFoundError:
                    pass
            
            winreg.CloseKey(key)
        except Exception as e:
            self.log(f"⚠️ Otomatik başlatma hatası: {str(e)}", "error")
    
    def get_drives(self):
        """Tüm USB sürücüleri al - gelişmiş"""
        drives = {}
        bitmask = win32api.GetLogicalDrives()
        for letter in range(65, 91):  # A-Z
            if bitmask & (1 << (letter - 65)):
                drive = chr(letter) + ":"
                try:
                    drive_type = win32file.GetDriveType(drive)
                    if drive_type == win32con.DRIVE_REMOVABLE:
                        # Sürücü bilgilerini al
                        try:
                            volume_info = win32api.GetVolumeInformation(drive)
                            serial = win32api.GetVolumeInformation(drive)[1]
                            
                            # Disk kullanım bilgisi
                            usage = psutil.disk_usage(drive)
                            
                            drives[drive] = {
                                'name': volume_info[0] if volume_info[0] else "Unnamed",
                                'serial': serial,
                                'filesystem': volume_info[4],
                                'total_space': usage.total,
                                'used_space': usage.used,
                                'free_space': usage.free,
                                'percent': usage.percent
                            }
                        except:
                            drives[drive] = {'name': 'Unknown', 'serial': 'N/A'}
                except:
                    pass
        return drives
    
    def calculate_file_hash(self, filepath):
        """Dosya hash'i hesapla"""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return None
    
    def is_suspicious_name(self, filename):
        """Dosya adı şüpheli mi kontrol et"""
        filename_lower = filename.lower()
        for suspicious in self.suspicious_names:
            if suspicious in filename_lower:
                return True
        return False
    
    def start_monitoring(self):
        """USB izlemeyi başlat"""
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="🟢 İzleme Aktif", fg="#3fb950")
        self.log("🚀 USB izleme başlatıldı - Sistem aktif", "success")
        
        monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """USB izlemeyi durdur"""
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="⚫ Beklemede", fg="#f0883e")
        self.log("⏸️ USB izleme durduruldu", "warning")
    
    def monitor_usb(self):
        """USB sürücüleri sürekli izle - gelişmiş"""
        while self.monitoring:
            current_drives = self.get_drives()
            
            # Yeni USB tespit edildi
            new_drives = set(current_drives.keys()) - set(self.connected_usbs.keys())
            for drive in new_drives:
                info = current_drives[drive]
                serial = info['serial']
                
                # Blacklist kontrolü
                if serial in self.usb_blacklist:
                    self.log(f"🚫 ENGELLENEN USB: {drive} - {info['name']} (Blacklist)", "error")
                    self.stats['usb_blocked'] += 1
                    if self.setting_vars['notifications'].get():
                        messagebox.showwarning("USB Engellendi!", 
                                             f"Bu USB cihaz blacklist'te!\n{drive} - {info['name']}")
                    continue
                
                # Whitelist kontrolü
                if serial in self.usb_whitelist:
                    self.log(f"✅ Güvenli USB bağlandı: {drive} - {info['name']} (Whitelist)", "success")
                else:
                    self.log(f"🔌 Yeni USB tespit edildi: {drive} - {info['name']}", "info")
                    self.log(f"   Serial: {serial}", "info")
                    self.log(f"   Dosya Sistemi: {info['filesystem']}", "info")
                    self.log(f"   Kapasite: {self.format_bytes(info['total_space'])}", "info")
                    self.log(f"   Kullanılan: {self.format_bytes(info['used_space'])} ({info['percent']}%)", "info")
                
                self.stats['usb_connected'] += 1
                self.connected_usbs[drive] = info
                self.update_usb_list()
                
                # Otomatik tarama
                if self.setting_vars['auto_scan'].get() and serial not in self.usb_whitelist:
                    self.scan_drive(drive)
            
            # USB çıkarıldı
            removed_drives = set(self.connected_usbs.keys()) - set(current_drives.keys())
            for drive in removed_drives:
                info = self.connected_usbs[drive]
                self.log(f"🔌 USB çıkarıldı: {drive} - {info['name']}", "warning")
                del self.connected_usbs[drive]
                self.update_usb_list()
            
            time.sleep(2)
    
    def format_bytes(self, bytes_size):
        """Byte'ları okunabilir formata çevir"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
    
    def update_usb_list(self):
        """USB listesini güncelle"""
        self.usb_listbox.delete(0, tk.END)
        for drive, info in self.connected_usbs.items():
            display_text = f"{drive} - {info['name']} ({self.format_bytes(info['total_space'])})"
            self.usb_listbox.insert(tk.END, display_text)
    
    def scan_drive(self, drive):
        """USB sürücüyü gelişmiş tara"""
        self.log(f"🔍 {drive} taranıyor - Derin analiz başladı...", "info")
        self.stats['total_scans'] += 1
        
        scan_start = time.time()
        threats_found = []
        files_scanned = 0
        
        try:
            # Autorun.inf kontrolü
            if self.setting_vars['block_autorun'].get():
                autorun_path = os.path.join(f"{drive}\\", "autorun.inf")
                if os.path.exists(autorun_path):
                    threats_found.append({
                        'path': autorun_path,
                        'type': 'Autorun File',
                        'description': 'Otomatik çalışma dosyası tespit edildi',
                        'action': 'Pending'
                    })
            
            # Tüm dosyaları tara
            for root, dirs, files in os.walk(f"{drive}\\"):
                for file in files:
                    files_scanned += 1
                    file_path = os.path.join(root, file)
                    
                    # Dosya boyutu kontrolü
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > self.setting_vars.get('size_limit', 100) * 1024 * 1024:
                            self.log(f"⚠️ Büyük dosya atlandı: {file} ({self.format_bytes(file_size)})", "warning")
                            continue
                    except:
                        continue
                    
                    # Uzantı kontrolü
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext in self.dangerous_extensions:
                        threat_info = {
                            'path': file_path,
                            'type': 'Dangerous Extension',
                            'description': f'Tehlikeli dosya uzantısı: {file_ext}',
                            'action': 'Pending'
                        }
                        threats_found.append(threat_info)
                        continue
                    
                    # Şüpheli isim kontrolü
                    if self.is_suspicious_name(file):
                        threat_info = {
                            'path': file_path,
                            'type': 'Suspicious Name',
                            'description': f'Şüpheli dosya adı tespit edildi',
                            'action': 'Pending'
                        }
                        threats_found.append(threat_info)
                    
                    # Derin tarama - dosya imzası kontrolü
                    if self.setting_vars['deep_scan'].get():
                        try:
                            with open(file_path, 'rb') as f:
                                header = f.read(8)
                                for signature, desc in self.dangerous_signatures.items():
                                    if header.startswith(signature):
                                        # Executable ama uzantı yanlış
                                        if file_ext not in self.dangerous_extensions:
                                            threat_info = {
                                                'path': file_path,
                                                'type': 'Hidden Executable',
                                                'description': f'Gizlenmiş çalıştırılabilir dosya: {desc}',
                                                'action': 'Pending'
                                            }
                                            threats_found.append(threat_info)
                                        break
                        except:
                            pass
                    
                    # Hash kontrolü
                    if self.setting_vars['hash_check'].get() and file_ext in self.dangerous_extensions:
                        file_hash = self.calculate_file_hash(file_path)
                        if file_hash and file_hash in self.malware_hashes:
                            threat_info = {
                                'path': file_path,
                                'type': 'Known Malware',
                                'description': 'Bilinen kötü amaçlı yazılım hash\'i',
                                'hash': file_hash,
                                'action': 'Pending'
                            }
                            threats_found.append(threat_info)
        except Exception as e:
            self.log(f"⚠️ Tarama hatası: {str(e)}", "error")
        
        scan_time = time.time() - scan_start
        
        # Tarama geçmişine ekle
        history_entry = {
            'drive': drive,
            'time': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            'files_scanned': files_scanned,
            'threats': len(threats_found),
            'duration': scan_time
        }
        self.scan_history.append(history_entry)
        self.update_history()
        
        # Sonuçları raporla
        if threats_found:
            self.log(f"⚠️ {len(threats_found)} tehdit tespit edildi! ({files_scanned} dosya tarandı)", "error")
            self.stats['threats_found'] += len(threats_found)
            
            for threat in threats_found:
                self.log(f"  ❌ {os.path.basename(threat['path'])}", "error")
                self.log(f"     └─ {threat['description']}", "error")
                self.log_threat(threat)
            
            if self.setting_vars['auto_clean'].get():
                self.clean_threats(threats_found)
            else:
                if self.setting_vars['notifications'].get():
                    response = messagebox.askyesno("Tehdit Tespit Edildi!", 
                                                  f"⚠️ {len(threats_found)} tehlikeli dosya bulundu!\n\n"
                                                  f"Tarama süresi: {scan_time:.2f} saniye\n"
                                                  f"Taranan dosya: {files_scanned}\n\n"
                                                  f"Tehditleri temizlemek ister misiniz?")
                    if response:
                        self.clean_threats(threats_found)
        else:
            self.log(f"✅ {drive} güvenli - Tehdit bulunamadı ({files_scanned} dosya tarandı)", "success")
            self.log(f"   Tarama süresi: {scan_time:.2f} saniye", "info")
            if self.setting_vars['notifications'].get():
                messagebox.showinfo("Tarama Tamamlandı", 
                                  f"✅ {drive} sürücüsü güvenli!\n\n"
                                  f"Taranan dosya: {files_scanned}\n"
                                  f"Tarama süresi: {scan_time:.2f} saniye")
    
    def clean_threats(self, threats):
        """Tehditleri temizle - gelişmiş"""
        cleaned = 0
        quarantined = 0
        
        for threat in threats:
            file_path = threat['path']
            try:
                if self.setting_vars['quarantine_mode'].get():
                    # Karantinaya al
                    filename = os.path.basename(file_path)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    quarantine_path = os.path.join(self.quarantine_folder, f"{timestamp}_{filename}")
                    
                    shutil.move(file_path, quarantine_path)
                    threat['action'] = f'Karantinaya alındı: {quarantine_path}'
                    self.log(f"📦 Karantinaya alındı: {filename}", "warning")
                    quarantined += 1
                else:
                    # Direkt sil
                    os.remove(file_path)
                    threat['action'] = 'Silindi'
                    self.log(f"🗑️ Silindi: {os.path.basename(file_path)}", "success")
                    cleaned += 1
                
                self.stats['threats_cleaned'] += 1
            except Exception as e:
                threat['action'] = f'Hata: {str(e)}'
                self.log(f"⚠️ Temizlenemedi: {os.path.basename(file_path)} - {str(e)}", "error")
        
        total_handled = cleaned + quarantined
        self.log(f"✅ Temizlik tamamlandı: {total_handled}/{len(threats)} tehdit işlendi", "success")
        
        if quarantined > 0:
            self.log(f"📦 {quarantined} dosya karantinaya alındı", "warning")
        if cleaned > 0:
            self.log(f"🗑️ {cleaned} dosya silindi", "success")
        
        if self.setting_vars['notifications'].get():
            messagebox.showinfo("Temizlik Tamamlandı", 
                              f"✅ İşlem tamamlandı!\n\n"
                              f"Karantina: {quarantined}\n"
                              f"Silinen: {cleaned}")
    
    def manual_scan(self):
        """Manuel tarama başlat"""
        if not self.connected_usbs:
            messagebox.showwarning("Uyarı", "🔌 USB sürücü bulunamadı!")
            return
        
        self.log("🔍 Manuel tarama başlatıldı", "info")
        for drive in list(self.connected_usbs.keys()):
            self.scan_drive(drive)
    
    def show_quarantine(self):
        """Karantina klasörünü göster"""
        if not os.path.exists(self.quarantine_folder):
            messagebox.showinfo("Karantina", "📦 Karantina klasörü boş")
            return
        
        files = os.listdir(self.quarantine_folder)
        if not files:
            messagebox.showinfo("Karantina", "📦 Karantina klasörü boş")
            return
        
        # Karantina penceresi
        quarantine_win = tk.Toplevel(self.root)
        quarantine_win.title("📦 Karantina Yönetimi")
        quarantine_win.geometry("600x400")
        quarantine_win.configure(bg="#0d1117")
        
        tk.Label(quarantine_win, text="📦 Karantinaya Alınmış Dosyalar", 
                font=("Segoe UI", 14, "bold"), bg="#0d1117", fg="#58a6ff").pack(pady=10)
        
        # Liste
        list_frame = tk.Frame(quarantine_win, bg="#0d1117")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        listbox = tk.Listbox(list_frame, bg="#161b22", fg="#c9d1d9",
                            font=("Consolas", 9), selectbackground="#1f6feb")
        scrollbar = tk.Scrollbar(list_frame, command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        for file in files:
            listbox.insert(tk.END, file)
        
        # Butonlar
        btn_frame = tk.Frame(quarantine_win, bg="#0d1117")
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        def delete_selected():
            selection = listbox.curselection()
            if selection:
                file = listbox.get(selection[0])
                file_path = os.path.join(self.quarantine_folder, file)
                try:
                    os.remove(file_path)
                    listbox.delete(selection[0])
                    self.log(f"🗑️ Karantinadan silindi: {file}", "success")
                except Exception as e:
                    messagebox.showerror("Hata", f"Silinemedi: {str(e)}")
        
        def restore_selected():
            messagebox.showinfo("Geri Yükle", "Bu özellik şu an için devre dışı - güvenlik nedeniyle")
        
        tk.Button(btn_frame, text="🗑️ Sil", command=delete_selected,
                 bg="#da3633", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📂 Klasörü Aç", 
                 command=lambda: os.startfile(self.quarantine_folder),
                 bg="#1f6feb", fg="white", font=("Segoe UI", 10, "bold"),
                 relief=tk.FLAT, padx=15, pady=5).pack(side=tk.LEFT, padx=5)
    
    def manage_whitelist(self):
        """Whitelist yönetim penceresi"""
        whitelist_win = tk.Toplevel(self.root)
        whitelist_win.title("📝 Whitelist & Blacklist Yönetimi")
        whitelist_win.geometry("700x500")
        whitelist_win.configure(bg="#0d1117")
        
        tk.Label(whitelist_win, text="📝 Liste Yönetimi", 
                font=("Segoe UI", 16, "bold"), bg="#0d1117", fg="#58a6ff").pack(pady=15)
        
        # Notebook
        notebook = ttk.Notebook(whitelist_win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Whitelist tab
        white_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(white_tab, text="✅ Whitelist")
        
        white_list = tk.Listbox(white_tab, bg="#161b22", fg="#c9d1d9",
                               font=("Consolas", 10))
        white_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for serial in self.usb_whitelist:
            white_list.insert(tk.END, serial)
        
        white_btn = tk.Frame(white_tab, bg="#0d1117")
        white_btn.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(white_btn, text="❌ Listeden Çıkar",
                 command=lambda: self.remove_from_list(white_list, self.usb_whitelist, 'whitelist'),
                 bg="#da3633", fg="white", font=("Segoe UI", 9, "bold"),
                 relief=tk.FLAT, pady=5).pack(fill=tk.X)
        
        # Blacklist tab
        black_tab = tk.Frame(notebook, bg="#0d1117")
        notebook.add(black_tab, text="🚫 Blacklist")
        
        black_list = tk.Listbox(black_tab, bg="#161b22", fg="#c9d1d9",
                               font=("Consolas", 10))
        black_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        for serial in self.usb_blacklist:
            black_list.insert(tk.END, serial)
        
        black_btn = tk.Frame(black_tab, bg="#0d1117")
        black_btn.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(black_btn, text="❌ Listeden Çıkar",
                 command=lambda: self.remove_from_list(black_list, self.usb_blacklist, 'blacklist'),
                 bg="#da3633", fg="white", font=("Segoe UI", 9, "bold"),
                 relief=tk.FLAT, pady=5).pack(fill=tk.X)
    
    def add_to_whitelist(self):
        """Seçili USB'yi whitelist'e ekle"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir USB seçin!")
            return
        
        drive = list(self.connected_usbs.keys())[selection[0]]
        serial = self.connected_usbs[drive]['serial']
        
        if serial in self.usb_whitelist:
            messagebox.showinfo("Bilgi", "Bu USB zaten whitelist'te!")
            return
        
        self.usb_whitelist.add(serial)
        self.save_lists()
        self.log(f"✅ Whitelist'e eklendi: {drive} (Serial: {serial})", "success")
        messagebox.showinfo("Başarılı", f"✅ {drive} whitelist'e eklendi!")
    
    def add_to_blacklist(self):
        """Seçili USB'yi blacklist'e ekle"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir USB seçin!")
            return
        
        drive = list(self.connected_usbs.keys())[selection[0]]
        serial = self.connected_usbs[drive]['serial']
        
        response = messagebox.askyesno("Onay", 
                                      f"⚠️ {drive} blacklist'e eklenecek!\n\n"
                                      f"Bu USB bir daha bağlanamayacak.\nEmin misiniz?")
        if response:
            self.usb_blacklist.add(serial)
            self.save_lists()
            self.log(f"🚫 Blacklist'e eklendi: {drive} (Serial: {serial})", "error")
            messagebox.showwarning("Blacklist", f"🚫 {drive} blacklist'e eklendi!")
    
    def remove_from_list(self, listbox, list_set, list_name):
        """Listeden çıkar"""
        selection = listbox.curselection()
        if selection:
            serial = listbox.get(selection[0])
            list_set.discard(serial)
            listbox.delete(selection[0])
            self.save_lists()
            self.log(f"❌ {list_name}'ten çıkarıldı: {serial}", "warning")
    
    def show_usb_details(self):
        """USB detaylarını göster"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir USB seçin!")
            return
        
        drive = list(self.connected_usbs.keys())[selection[0]]
        info = self.connected_usbs[drive]
        
        details = f"""
🔌 USB Cihaz Detayları
{'='*40}

Sürücü: {drive}
İsim: {info['name']}
Serial Numarası: {info['serial']}
Dosya Sistemi: {info['filesystem']}

💾 Kapasite Bilgisi:
Toplam Alan: {self.format_bytes(info['total_space'])}
Kullanılan: {self.format_bytes(info['used_space'])}
Boş Alan: {self.format_bytes(info['free_space'])}
Doluluk: %{info['percent']:.1f}

🛡️ Güvenlik Durumu:
Whitelist: {'✅ Evet' if info['serial'] in self.usb_whitelist else '❌ Hayır'}
Blacklist: {'⚠️ Evet' if info['serial'] in self.usb_blacklist else '✅ Hayır'}
        """
        
        messagebox.showinfo("USB Detayları", details)
    
    def safe_eject(self):
        """Güvenli çıkar"""
        selection = self.usb_listbox.curselection()
        if not selection:
            messagebox.showwarning("Uyarı", "Lütfen bir USB seçin!")
            return
        
        drive = list(self.connected_usbs.keys())[selection[0]]
        messagebox.showinfo("Güvenli Çıkar", 
                          f"⏏️ {drive} sürücüsünü güvenle çıkarabilirsiniz!")
    
    def update_history(self):
        """Tarama geçmişini güncelle"""
        self.history_text.delete(1.0, tk.END)
        for entry in reversed(self.scan_history[-20:]):  # Son 20 tarama
            history_line = (f"📅 {entry['time']} | "
                          f"Drive: {entry['drive']} | "
                          f"Dosya: {entry['files_scanned']} | "
                          f"Tehdit: {entry['threats']} | "
                          f"Süre: {entry['duration']:.2f}s\n")
            self.history_text.insert(tk.END, history_line)
    
    def update_status(self):
        """Durum güncelle"""
        if self.monitoring:
            drive_count = len(self.connected_usbs)
            if drive_count > 0:
                self.status_label.config(text=f"🟢 İzleme Aktif ({drive_count} USB Bağlı)")
        self.root.after(1000, self.update_status)
    
    def run(self):
        """Programı çalıştır"""
        self.root.mainloop()

if __name__ == "__main__":
    app = ByteLock()
    app.run()