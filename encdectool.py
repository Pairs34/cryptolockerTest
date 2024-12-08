import os
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def pad(data):
    return data + b"\0" * (16 - len(data) % 16)

def unpad(data):
    return data.rstrip(b"\0")

def encrypt_filename(filename, key):
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted_name, tag = cipher.encrypt_and_digest(pad(filename.encode()))
    return cipher.nonce + tag + encrypted_name

def decrypt_filename(encrypted_name, key):
    nonce = encrypted_name[:16]
    tag = encrypted_name[16:32]
    encrypted_data = encrypted_name[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_name = unpad(cipher.decrypt_and_verify(encrypted_data, tag))
    return decrypted_name.decode()

def encrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    cipher = AES.new(key, AES.MODE_GCM)
    encrypted_data, tag = cipher.encrypt_and_digest(pad(data))
    new_filename = encrypt_filename(os.path.basename(file_path), key)
    with open(os.path.join(os.path.dirname(file_path), new_filename.hex()), 'wb') as f:
        f.write(cipher.nonce + tag + encrypted_data)
    os.remove(file_path)

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    nonce = data[:16]
    tag = data[16:32]
    encrypted_data = data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = unpad(cipher.decrypt_and_verify(encrypted_data, tag))
    original_name = decrypt_filename(bytes.fromhex(os.path.basename(file_path)), key)
    with open(os.path.join(os.path.dirname(file_path), original_name), 'wb') as f:
        f.write(decrypted_data)
    os.remove(file_path)

def encrypt_folder(folder_path, key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Şifreleniyor: {file_path}")
            encrypt_file(file_path, key)

def decrypt_folder(folder_path, key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            try:
                file_path = os.path.join(root, file)
                print(f"Çözülüyor: {file_path}")
                decrypt_file(file_path, key)
            except Exception as e:
                print(f"Hata çözülemeyen dosya: {file_path}. Hata: {e}")

def main():
    print("1. Şifreleme\n2. Şifre Çözme")
    choice = input("Seçiminizi yapın (1/2): ")

    folder_path = input("Klasör yolunu girin: ")
    if choice == '1':
        key = get_random_bytes(32)  # 256-bit anahtar oluştur
        encrypt_folder(folder_path, key)
        with open("key.bin", 'wb') as key_file:
            key_file.write(key)
        print("Şifreleme tamamlandı! Anahtar 'key.bin' dosyasına kaydedildi.")
    elif choice == '2':
        if not os.path.exists("key.bin"):
            print("Anahtar dosyası bulunamadı! Şifre çözme işlemi yapılamaz.")
            return
        with open("key.bin", 'rb') as key_file:
            key = key_file.read()
        decrypt_folder(folder_path, key)
        print("Şifre çözme tamamlandı!")
    else:
        print("Geçersiz seçim. Lütfen 1 veya 2'yi seçin.")

if __name__ == "__main__":
    main()
