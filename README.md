# 🛡️ Dosya Şifreleme ve Şifre Çözme Testi

Bu program, bir klasörde bulunan tüm dosyaları güçlü bir şifreleme algoritması olan **AES-256 (Advanced Encryption Standard)** ile şifreler. Aynı zamanda şifrelenmiş dosyaların orijinal hallerine geri döndürülebilmesi için bir şifre çözme mekanizması sunar. 

---

![image](https://github.com/user-attachments/assets/ac9b6a28-ba31-495c-9972-4b29d23ae39d)


## 🎯 Programın Temel Amacı

### 🔒 **Dosya Şifreleme:**
- 📁 Klasördeki dosyaların içeriklerini ve dosya isimlerini şifreler.
- 🔐 Şifreleme işlemi sırasında **GCM (Galois/Counter Mode)** kullanılarak hem veri gizliliği hem de bütünlük kontrolü sağlanır.
- 🗝️ Rastgele bir **256-bit anahtar** (`key.bin`) oluşturularak dosyaları şifreler ve anahtar güvenli bir şekilde kaydedilir.

### 🔓 **Dosya Şifre Çözme:**
- 🔄 Şifrelenmiş dosyalar, aynı `key.bin` anahtarı ile orijinal hallerine döndürülür.
- 📝 Şifre çözme sırasında dosya isimleri ve içerikleri tam olarak eski haline getirilir.

---

## 🛡️ **Antivirüs Algılama Testi:**
- 🧐 Programın antivirüs yazılımları tarafından algılanıp algılanmadığını test etmek için kullanılabilir.
- ⚙️ Bu test, güvenlik sistemlerinin güçlü bir AES şifreleme işlemine nasıl yanıt verdiğini anlamaya yardımcı olur.

---

## 💼 **Kullanım Alanları:**
- ✅ Güvenlik sistemlerini test etmek ve **EDR (Endpoint Detection and Response)** çözümlerinin etkinliğini ölçmek.
- 📊 Şifreleme işlemlerinin gerçek bir ortamda nasıl davrandığını analiz etmek.

---

## 🧪 **Test Yapılan Antivirüs ve EDR'lar:**
1. 🛡️ **Crowdstrike** - No Detected
2. 🛡️ **Kaspersky Premium**  - No Detected
3. 🛡️ **Microsoft Defender for Endpoint**  - No Detected
4. 🛡️ **Forti EDR** - No Detected
5. 🛡️ **Trendmicro** - Detected
6. 🛡️ **Acronis Cyber Protect** - Detected
7. 🛡️ **Bitdefender Gravity Zone** - No Detected
8. 🛡️ **Avast Premium Security** - Detected
