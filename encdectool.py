import sys
import os
# import threading # QThread kullanıldığı için buna gerek kalmadı
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QRadioButton, QVBoxLayout, QHBoxLayout, QGridLayout, # QGridLayout eklendi
    QFileDialog, QMessageBox, QTextEdit, QProgressBar, QStyleFactory, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, QObject, Slot
from PySide6.QtGui import QPalette, QColor

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import traceback

# --- Şifreleme/Şifre Çözme Mantığı (Değişiklik Yok) ---
def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def unpad(data):
    return data.rstrip(b"\0")

def encrypt_filename(filename, key):
    try:
        cipher = AES.new(key, AES.MODE_GCM)
        encrypted_name, tag = cipher.encrypt_and_digest(pad(filename.encode('utf-8')))
        # Nonce ve tag'in geçerli olduğunu kontrol et
        if not isinstance(cipher.nonce, bytes) or not isinstance(tag, bytes):
            # Bu durum normalde oluşmamalı, ama bir sorun olursa None döndür
            print(f"DEBUG: encrypt_filename - Nonce veya Tag alınamadı. Nonce: {type(cipher.nonce)}, Tag: {type(tag)}")
            return None
        return cipher.nonce + tag + encrypted_name
    except Exception as e:
        print(f"DEBUG: encrypt_filename hatası: {e}")
        # traceback.print_exc()
        return None


def decrypt_filename(encrypted_name_bytes, key):
    try:
        if len(encrypted_name_bytes) < 32: # Nonce(16) + Tag(16) minimum
            return None
        nonce = encrypted_name_bytes[:16]
        tag = encrypted_name_bytes[16:32]
        encrypted_data = encrypted_name_bytes[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_name = unpad(cipher.decrypt_and_verify(encrypted_data, tag))
        return decrypted_name.decode('utf-8')
    except (ValueError, KeyError, IndexError, UnicodeDecodeError) as e:
        # print(f"DEBUG: decrypt_filename hatası: {e}")
        return None


# --- Dosya İşleme Sınıfı (Worker) ---
class Worker(QObject):
    status_updated = Signal(str)
    progress_updated = Signal(int, int)
    finished = Signal()
    error_occurred = Signal(str)

    def __init__(self, folder_path, key, mode):
        super().__init__()
        self.folder_path = folder_path
        self.key = key
        self.mode = mode
        self._is_running = True

    @Slot()
    def run(self):
        total_files = 0
        files_to_process = []
        action_func = self._encrypt_file if self.mode == "encrypt" else self._decrypt_file

        try:
            if not os.path.exists(self.folder_path):
                 self.status_updated.emit(f"Uyarı: Klasör '{self.folder_path}' doğrudan bulunamadı, erişim deneniyor...")

            for root, dirs, files in os.walk(self.folder_path, topdown=True):
                 files = [f for f in files if f != "encryption.key"] # Anahtar dosyasını atla
                 for file in files:
                      file_path = os.path.join(root, file)
                      files_to_process.append(file_path)
                      total_files += 1

        except FileNotFoundError:
            self.error_occurred.emit(f"Hata: Klasör bulunamadı: {self.folder_path}")
            self.finished.emit()
            return
        except OSError as e:
            self.error_occurred.emit(f"Hata: Klasöre erişilemiyor: {self.folder_path}. İzinleri/yolu kontrol edin.\nDetay: {e}")
            self.finished.emit()
            return
        except Exception as e:
            self.error_occurred.emit(f"Hata: Dosyalar listelenirken sorun oluştu.\nDetay: {e}")
            self.finished.emit()
            return

        if total_files == 0 and self._is_running:
             self.status_updated.emit("Belirtilen klasörde işlenecek dosya bulunamadı.")

        processed_files = 0
        self.progress_updated.emit(processed_files, total_files)

        for file_path in files_to_process:
            if not self._is_running:
                self.status_updated.emit("İşlem kullanıcı tarafından iptal edildi.")
                break
            try:
                action_func(file_path)
            except Exception as e:
                 self.status_updated.emit(f"Beklenmedik İşlem Hatası ({os.path.basename(file_path)}): {e}")
                 # traceback.print_exc()
            finally:
                 processed_files += 1
                 # Her dosya işlendiğinde ilerlemeyi güncelle
                 if self._is_running or processed_files == total_files: # İptal edilse bile son durumu göster
                      self.progress_updated.emit(processed_files, total_files)


        # İşlem bittiğinde (iptal edilmediyse) son mesajı gönder
        if self._is_running:
             self.status_updated.emit("İşlem tamamlandı.")
        self.finished.emit()


    def _encrypt_file(self, file_path):
        try:
            # 1. Encrypt filename first
            basename = os.path.basename(file_path)
            encrypted_name_bytes = encrypt_filename(basename, self.key)
            if encrypted_name_bytes is None:
                 self.status_updated.emit(f"Hata: Dosya adı şifrelenemedi: {basename}. Atlanıyor.")
                 return
            new_filename_hex = encrypted_name_bytes.hex()
            new_file_path = os.path.join(os.path.dirname(file_path), new_filename_hex)

            if os.path.exists(new_file_path):
                self.status_updated.emit(f"Hata: Hedef dosya zaten var: {new_filename_hex}. Atlanıyor: {basename}")
                return

            # 2. Read original file content
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
            except Exception as e:
                 self.status_updated.emit(f"Hata: Orijinal dosya okunamadı ({basename}): {e}")
                 return

            # 3. Encrypt file content
            try:
                content_cipher = AES.new(self.key, AES.MODE_GCM)
                # Anahtar kontrolü (ekstra güvenlik)
                if not isinstance(self.key, bytes) or len(self.key) not in [16, 24, 32]:
                     self.status_updated.emit(f"Hata: Geçersiz anahtar (İçerik Şifreleme: {basename}). Atlanıyor.")
                     return

                encrypted_data, tag = content_cipher.encrypt_and_digest(pad(data))

                # !! ÖNEMLİ KONTROL !!
                if not isinstance(content_cipher.nonce, bytes) or not isinstance(tag, bytes):
                     self.status_updated.emit(f"Kritik Hata: Şifreleme sonrası nonce/tag alınamadı ({basename}). Atlanıyor.")
                     # Gerekirse detaylı loglama:
                     # print(f"DEBUG: _encrypt_file Nonce={content_cipher.nonce}, Tag={tag}")
                     return

            except Exception as crypto_err:
                 self.status_updated.emit(f"Kripto Hatası (İçerik Şifreleme: {basename}): {crypto_err}")
                 return

            # 4. Write encrypted file (nonce + tag + data)
            try:
                with open(new_file_path, 'wb') as f:
                    # content_cipher'dan alınan nonce ve tag kullanılır
                    f.write(content_cipher.nonce + tag + encrypted_data)
            except Exception as write_err:
                 self.status_updated.emit(f"Hata: Şifreli dosya yazılamadı ({new_filename_hex}): {write_err}")
                 # Yazma hatası olduysa orijinali silme!
                 return

            # 5. Remove original file *only if* write was successful
            try:
                 os.remove(file_path)
                 self.status_updated.emit(f"Şifrelendi: {basename} -> {new_filename_hex}")
            except Exception as remove_err:
                 self.status_updated.emit(f"Uyarı: Şifreli dosya yazıldı ({new_filename_hex}) ancak orijinal silinemedi ({basename}): {remove_err}")

        except Exception as e:
            # Bu fonksiyondaki diğer beklenmedik hatalar için
            self.status_updated.emit(f"Beklenmedik Hata (_encrypt_file: {os.path.basename(file_path)}): {e}")
            # traceback.print_exc()


    def _decrypt_file(self, file_path):
        basename = os.path.basename(file_path)
        try:
            try:
                 encrypted_name_bytes = bytes.fromhex(basename)
            except ValueError:
                 self.status_updated.emit(f"Uyarı: Geçersiz dosya adı formatı (hex değil?): {basename}. Atlanıyor.")
                 return

            original_name = decrypt_filename(encrypted_name_bytes, self.key)
            if original_name is None:
                # Dosya adı çözülemediyse veya hex değilse (veya anahtar yanlışsa)
                # decrypt_filename None döndürür, burada özel bir mesaj vermeye gerek yok
                # sadece atlayalım, çünkü geçerli şifreli bir dosya olmayabilir.
                # self.status_updated.emit(f"Bilgi: Dosya adı çözülemedi/geçersiz: {basename}. Atlanıyor.")
                return

            new_file_path = os.path.join(os.path.dirname(file_path), original_name)

            if os.path.exists(new_file_path):
                self.status_updated.emit(f"Hata: Hedef dosya zaten var: {original_name}. Atlanıyor: {basename}")
                return

            try:
                 with open(file_path, 'rb') as f:
                      data = f.read()
            except Exception as read_err:
                 self.status_updated.emit(f"Hata: Şifreli dosya okunamadı ({basename}): {read_err}")
                 return

            # Nonce+Tag+Data için minimum boyutu kontrol et
            if len(data) < 32:
                 self.status_updated.emit(f"Hata: Geçersiz dosya boyutu (çok küçük): {basename}. Atlanıyor.")
                 return

            nonce = data[:16]
            tag = data[16:32]
            encrypted_data = data[32:]

            try:
                 cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
                 decrypted_data = unpad(cipher.decrypt_and_verify(encrypted_data, tag))
            except ValueError: # decrypt_and_verify hatası
                 self.status_updated.emit(f"Hata (Doğrulama: {basename}): Anahtar yanlış veya dosya bozuk.")
                 return
            except Exception as crypto_err:
                 self.status_updated.emit(f"Kripto Hatası (İçerik Çözme: {basename}): {crypto_err}")
                 return

            try:
                with open(new_file_path, 'wb') as f:
                    f.write(decrypted_data)
            except Exception as write_err:
                 self.status_updated.emit(f"Hata: Çözülmüş dosya yazılamadı ({original_name}): {write_err}")
                 # Yazma hatası olursa şifreli dosyayı silme!
                 return

            try:
                 os.remove(file_path)
                 self.status_updated.emit(f"Çözüldü: {basename} -> {original_name}")
            except Exception as remove_err:
                 self.status_updated.emit(f"Uyarı: Dosya çözüldü ({original_name}) ancak şifreli dosya silinemedi ({basename}): {remove_err}")


        except Exception as e:
            # Bu fonksiyondaki diğer beklenmedik hatalar
            self.status_updated.emit(f"Beklenmedik Hata (_decrypt_file: {basename}): {e}")
            # traceback.print_exc()


    def stop(self):
        self._is_running = False


# --- Ana GUI Penceresi ---
class EncryptorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cryptolocker - Şifreleme/Şifre Çözme Aracı")
        self.setGeometry(200, 200, 700, 500) # Boyut ayarı

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self._thread = None
        self._worker = None

        self._create_ui() # UI oluşturma fonksiyonunu çağır

    def _create_ui(self):
        # 1. Kontrol Alanı (İşlem Seçimi)
        control_layout = QHBoxLayout()
        control_layout.addWidget(QLabel("İşlem Seçin:"))
        self.encrypt_radio = QRadioButton("Şifrele")
        self.encrypt_radio.setChecked(True)
        self.decrypt_radio = QRadioButton("Şifre Çöz")
        self.encrypt_radio.toggled.connect(self.update_ui_for_operation) # Sinyal bağlama
        control_layout.addWidget(self.encrypt_radio)
        control_layout.addWidget(self.decrypt_radio)
        control_layout.addStretch()
        self.main_layout.addLayout(control_layout)

        # Ayırıcı Çizgi
        line1 = QFrame()
        line1.setFrameShape(QFrame.Shape.HLine)
        line1.setFrameShadow(QFrame.Shadow.Sunken)
        self.main_layout.addWidget(line1)

        # 2. Yol Giriş Alanları (QGridLayout ile)
        path_layout = QGridLayout() # GridLayout kullanılıyor

        # Klasör Yolu
        path_layout.addWidget(QLabel("Klasör Yolu:"), 0, 0)
        self.folder_path_edit = QLineEdit()
        self.folder_path_edit.setPlaceholderText("İşlem yapılacak klasörün yolunu girin (örn: C:\\...) veya ağ yolu (\\\\Sunucu\\...)")
        path_layout.addWidget(self.folder_path_edit, 0, 1)
        self.browse_folder_button = QPushButton("Gözat...")
        self.browse_folder_button.clicked.connect(self.browse_folder) # Sinyal bağlama
        path_layout.addWidget(self.browse_folder_button, 0, 2)

        # Anahtar Yolu (Başlangıçta gizli)
        self.key_label = QLabel("Anahtar Dosyası:")
        self.key_path_edit = QLineEdit()
        self.key_path_edit.setPlaceholderText(".key uzantılı anahtar dosyasını seçin")
        self.browse_key_button = QPushButton("Gözat...")
        self.browse_key_button.clicked.connect(self.browse_key) # Sinyal bağlama

        path_layout.addWidget(self.key_label, 1, 0)
        path_layout.addWidget(self.key_path_edit, 1, 1)
        path_layout.addWidget(self.browse_key_button, 1, 2)

        path_layout.setColumnStretch(1, 1) # Ortadaki giriş alanının genişlemesini sağla
        self.main_layout.addLayout(path_layout)

        # Ayırıcı Çizgi
        line2 = QFrame()
        line2.setFrameShape(QFrame.Shape.HLine)
        line2.setFrameShadow(QFrame.Shadow.Sunken)
        self.main_layout.addWidget(line2)

        # 3. Eylem Butonları
        action_layout = QHBoxLayout()
        self.start_button = QPushButton("İşlemi Başlat")
        self.start_button.clicked.connect(self.start_processing) # Sinyal bağlama
        self.cancel_button = QPushButton("İptal Et")
        self.cancel_button.clicked.connect(self.cancel_processing) # Sinyal bağlama
        self.cancel_button.setEnabled(False)
        action_layout.addStretch()
        action_layout.addWidget(self.start_button)
        action_layout.addWidget(self.cancel_button)
        self.main_layout.addLayout(action_layout)

        # 4. Durum Alanı
        self.status_label = QLabel("Durum:")
        self.main_layout.addWidget(self.status_label)
        self.status_textedit = QTextEdit()
        self.status_textedit.setReadOnly(True)
        self.main_layout.addWidget(self.status_textedit, 1) # Yüksekliği genişlesin

        # 5. İlerleme Çubuğu
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Bekleniyor...") # Başlangıç formatı
        self.main_layout.addWidget(self.progress_bar)

        # Başlangıç UI durumunu ayarla
        self.update_ui_for_operation()

    # browse_folder, browse_key, update_ui_for_operation,
    # append_status, update_progress, finish_processing,
    # show_error_message, set_ui_enabled, start_processing,
    # cancel_processing, closeEvent metodları önceki kodla aynı.
    # Tekrar yazmaya gerek yok.

    @Slot()
    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Klasör Seç", self.folder_path_edit.text())
        if folder:
            folder = os.path.normpath(folder)
            self.folder_path_edit.setText(folder)
            self.append_status(f"Klasör seçildi: {folder}")

    @Slot()
    def browse_key(self):
        key_file, _ = QFileDialog.getOpenFileName(self, "Anahtar Dosyasını Seç", "", "Anahtar Dosyaları (*.key);;Tüm Dosyalar (*.*)")
        if key_file:
             key_file = os.path.normpath(key_file)
             self.key_path_edit.setText(key_file)
             self.append_status(f"Anahtar dosyası seçildi: {key_file}")

    @Slot()
    def update_ui_for_operation(self):
        is_decrypt = self.decrypt_radio.isChecked()
        self.key_label.setVisible(is_decrypt)
        self.key_path_edit.setVisible(is_decrypt)
        self.browse_key_button.setVisible(is_decrypt)
        # Eğer UI etkinse, key alanlarının etkinliğini de ayarla
        if self.start_button.isEnabled(): # Genel UI etkinliğini kontrol et
            self.key_path_edit.setEnabled(is_decrypt)
            self.browse_key_button.setEnabled(is_decrypt)


    @Slot(str)
    def append_status(self, message):
        self.status_textedit.append(message)
        # Scrollbar'ı en alta kaydırmak için küçük bir gecikmeyle yapabiliriz:
        # self.status_textedit.verticalScrollBar().setValue(self.status_textedit.verticalScrollBar().maximum())
        QApplication.processEvents() # Arayüzün güncellenmesini sağla (özellikle çok hızlı mesajlarda)
        self.status_textedit.ensureCursorVisible() # İmlecin göründüğü yere git (genellikle son satır)

    @Slot(int, int)
    def update_progress(self, value, maximum):
        if maximum > 0:
            self.progress_bar.setMaximum(maximum)
            self.progress_bar.setValue(value)
            percent = int((value / maximum) * 100)
            self.progress_bar.setFormat(f"%p% ({value}/{maximum})")
        else:
            # Eğer işlenecek dosya yoksa veya başlangıç durumuysa
             self.progress_bar.setMaximum(1) # 0'a bölme hatasını önle
             self.progress_bar.setValue(0)
             self.progress_bar.setFormat("Başlatılıyor..." if value==0 else f"0/0")


    @Slot()
    def finish_processing(self):
        # Thread bittiğinde UI elemanlarını tekrar aktif et
        self.set_ui_enabled(True)
        # self.append_status("Arayüz tekrar aktif.") # İsteğe bağlı mesaj
        if self._thread:
             # Thread'in işini tamamen bitirmesini bekle (quit sinyali gönderildi)
             self._thread.wait(1000) # Maks 1 sn bekle
             if self._thread.isRunning():
                  print("Uyarı: Thread beklendiği gibi sonlanmadı.")
                  # self._thread.terminate() # Son çare, riskli olabilir
        self._thread = None
        self._worker = None
        QApplication.processEvents()

    @Slot(str)
    def show_error_message(self, message):
        QMessageBox.critical(self, "İşlem Hatası", message)
        # Hata sonrası da arayüzü aktif et (eğer zaten edilmediyse)
        if not self.start_button.isEnabled():
            self.finish_processing()

    def set_ui_enabled(self, enabled):
         """Arayüz elemanlarının etkinliğini ayarlar."""
         self.encrypt_radio.setEnabled(enabled)
         self.decrypt_radio.setEnabled(enabled)
         self.folder_path_edit.setEnabled(enabled)
         self.browse_folder_button.setEnabled(enabled)
         # Anahtar alanları sadece decrypt modu aktifken ve UI genelde aktifken etkin olmalı
         is_decrypt = self.decrypt_radio.isChecked()
         self.key_path_edit.setEnabled(enabled and is_decrypt)
         self.browse_key_button.setEnabled(enabled and is_decrypt)

         self.start_button.setEnabled(enabled)
         self.cancel_button.setEnabled(not enabled) # İptal, başlatmanın tersi

    @Slot()
    def start_processing(self):
        folder_path = self.folder_path_edit.text().strip()
        if not folder_path:
            QMessageBox.warning(self, "Eksik Bilgi", "Lütfen bir klasör yolu girin.")
            return

        is_decrypt = self.decrypt_radio.isChecked()
        key = None
        key_path = ""

        self.status_textedit.clear()
        self.update_progress(0, 0) # İlerlemeyi sıfırla

        if is_decrypt:
            key_path = self.key_path_edit.text().strip()
            if not key_path or not os.path.isfile(key_path):
                QMessageBox.critical(self, "Hata", "Lütfen geçerli bir anahtar dosyası seçin.")
                return
            try:
                with open(key_path, 'rb') as key_file:
                    key = key_file.read()
                if len(key) not in [16, 24, 32]:
                    QMessageBox.critical(self, "Hata", f"Geçersiz anahtar boyutu ({len(key)} byte). Anahtar 16, 24 veya 32 byte olmalıdır.")
                    return
                self.append_status(f"Anahtar yüklendi: {key_path}")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Anahtar dosyası okunamadı:\n{e}")
                return
        else: # Encrypt
            key = get_random_bytes(32)
            key_save_path, _ = QFileDialog.getSaveFileName(self, "Şifreleme Anahtarını Kaydet", "encryption.key", "Anahtar Dosyaları (*.key)")
            if not key_save_path:
                self.append_status("Anahtar kaydetme iptal edildi. İşlem başlatılmadı.")
                return
            try:
                 key_save_path = os.path.normpath(key_save_path)
                 with open(key_save_path, 'wb') as key_file:
                     key_file.write(key)
                 self.append_status(f"Anahtar oluşturuldu ve şuraya kaydedildi: {key_save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Hata", f"Anahtar dosyası kaydedilemedi:\n{e}")
                return

        if self._thread is not None and self._thread.isRunning():
             QMessageBox.warning(self, "Uyarı", "Zaten devam eden bir işlem var.")
             return

        self._thread = QThread(self) # Parent olarak self vermek daha iyi olabilir
        self._worker = Worker(folder_path, key, "decrypt" if is_decrypt else "encrypt")
        self._worker.moveToThread(self._thread)

        # Sinyalleri bağla
        self._worker.status_updated.connect(self.append_status)
        self._worker.progress_updated.connect(self.update_progress)
        # finished sinyali hem finish_processing'i hem de thread'i sonlandırmayı tetiklemeli
        self._worker.finished.connect(self.finish_processing)
        self._worker.finished.connect(self._thread.quit) # Worker bitince thread'i durdur
        self._worker.error_occurred.connect(self.show_error_message)

        # Thread sinyallerini bağla
        self._thread.started.connect(self._worker.run)
        # Bellek yönetimi: Thread bittikten sonra objeleri sil
        # quit sinyali verildikten sonra finished sinyali beklenir.
        self._thread.finished.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater) # Thread kendini de silebilir

        self.set_ui_enabled(False) # Arayüzü pasif yap
        self.append_status(f"{'Şifre Çözme' if is_decrypt else 'Şifreleme'} işlemi başlatılıyor...")
        self._thread.start()


    @Slot()
    def cancel_processing(self):
         if self._worker and self._thread and self._thread.isRunning():
             self.append_status("İptal isteği gönderildi...")
             self._worker.stop()
             self.cancel_button.setEnabled(False)
         else:
             self.append_status("İptal edilecek aktif bir işlem yok.")

    def closeEvent(self, event):
         if self._thread and self._thread.isRunning():
             reply = QMessageBox.question(self, 'Çıkış Onayı',
                                          "Devam eden bir işlem var. Çıkmak istediğinize emin misiniz?\n(İşlem yarıda kalabilir)",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                          QMessageBox.StandardButton.No)
             if reply == QMessageBox.StandardButton.Yes:
                  if self._worker:
                      self._worker.stop()
                  # Thread'in bitmesini beklemek yerine doğrudan çıkalım
                  # self._thread.quit()
                  # self._thread.wait(500) # Kısa bir süre bekle
                  event.accept()
             else:
                  event.ignore()
         else:
             event.accept()


# --- Uygulamayı Başlat ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptorApp()
    window.show()
    sys.exit(app.exec())