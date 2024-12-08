import os
from Cryptodome.Cipher import AES


def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    encrypted_data = cipher.encrypt(pad(data))
    with open(file_path + ".enc", 'wb') as f:
        f.write(encrypted_data)
    os.remove(file_path)

def encrypt_folder(folder_path, key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Şifreleniyor: {file_path}")
            encrypt_file(file_path, key)

def main():
    key = os.urandom(32)  # Rastgele 256-bit şifreleme anahtarı
    folder_path = "C:\\Users\\Pairs\\Desktop\\temp\\OVPNGenerator"  # Şifrelenecek klasör yolu
    encrypt_folder(folder_path, key)
    with open("key.bin", 'wb') as key_file:
        key_file.write(key)
    print("Şifreleme tamamlandı! Anahtar 'key.bin' dosyasına kaydedildi.")

if __name__ == "__main__":
    main()
