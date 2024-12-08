import os

from Cryptodome.Cipher import AES


def unpad(data):
    return data.rstrip(b"\0")

def decrypt_file(file_path, key):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    cipher = AES.new(key, AES.MODE_CBC, key[:16])
    decrypted_data = unpad(cipher.decrypt(encrypted_data))
    original_file_path = file_path.replace(".enc", "")
    with open(original_file_path, 'wb') as f:
        f.write(decrypted_data)
    os.remove(file_path)

def decrypt_folder(folder_path, key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".enc"):
                file_path = os.path.join(root, file)
                print(f"Çözülüyor: {file_path}")
                decrypt_file(file_path, key)

def main():
    folder_path = "C:\\Users\\Pairs\\Desktop\\temp\\OVPNGenerator"  # Şifresi çözülecek klasör yolu
    with open("key.bin", 'rb') as key_file:
        key = key_file.read()
    decrypt_folder(folder_path, key)
    print("Şifre çözme tamamlandı!")

if __name__ == "__main__":
    main()
