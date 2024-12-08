Dosya Şifreleme ve Şifre Çözme Testi
Bu program, bir klasörde bulunan tüm dosyaları güçlü bir şifreleme algoritması olan AES-256 (Advanced Encryption Standard) ile şifreler. Aynı zamanda şifrelenmiş dosyaların orijinal hallerine geri döndürülebilmesi için bir şifre çözme mekanizması sunar. Programın temel amacı:

Dosya Şifreleme:

Klasördeki dosyaların içeriklerini ve dosya isimlerini şifreler.
Şifreleme işlemi sırasında GCM (Galois/Counter Mode) kullanılarak hem veri gizliliği hem de bütünlük kontrolü sağlanır.
Rastgele bir 256-bit anahtar (key.bin) oluşturularak dosyaları şifreler ve anahtar kaydedilir.
Dosya Şifre Çözme:

Şifrelenmiş dosyalar, aynı key.bin anahtarı ile orijinal hallerine döndürülür.
Şifre çözme sırasında dosya isimleri ve içerikleri tam olarak eski haline getirilir.
Antivirüs Algılama Testi:

Programın antivirüs yazılımları tarafından algılanıp algılanmadığını test etmek için kullanılabilir.
Bu test, güvenlik sistemlerinin güçlü bir AES şifreleme işlemine nasıl yanıt verdiğini anlamaya yardımcı olur.
Kullanım Alanları:

Güvenlik sistemlerini test etmek ve EDR (Endpoint Detection and Response) çözümlerinin etkinliğini ölçmek.
Şifreleme işlemlerinin gerçek bir ortamda nasıl davrandığını analiz etmek.

Test Yapılan Antivirüs ve EDR'lar

Crowdstrike
Kaspersky Premium
