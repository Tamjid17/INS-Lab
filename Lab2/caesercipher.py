#!/usr/bin/env python3

def encode_caesar_cipher(text, key):
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + key) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + key) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def decode_caesar_cipher(text, key):
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') - key) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') - key) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def read_from_file(filename):
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[-] File not found: {filename}")
        return None
    except Exception as e:
        print(f"[-] Error reading {filename}: {e}")
        return None


def save_to_file(filename, content):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Output saved to: {filename}")
    except Exception as e:
        print(f"[-] Error writing {filename}: {e}")


def input_key():
    """Prompt user for key and validate it's an integer between 0 and 25."""
    while True:
        s = input("Enter key (0–25): ").strip()
        try:
            k = int(s)
            if 1 <= k <= 25:
                return k
            else:
                print("[-] Key must be between 0 and 25. Try again.")
        except ValueError:
            print("[-] Invalid key. Enter an integer between 0 and 25.")


def main():
    print("=== Caesar Cipher File Tool ===")
    print("1) Encrypt text file")
    print("2) Decrypt text file")
    print("0) Exit")

    while True:
        choice = input("\nSelect an option: ").strip()

        # ENCRYPT
        if choice == "1":
            input_file = input("Enter plaintext file name (e.g., plain.txt): ").strip()
            output_file = input("Enter output encrypted file name (e.g., encrypted.txt): ").strip()
            key = input_key()

            text = read_from_file(input_file)
            if text is None:
                continue

            cipher = encode_caesar_cipher(text, key)
            save_to_file(output_file, cipher)
            print("[+] Encryption complete.")

        # DECRYPT
        elif choice == "2":
            input_file = input("Enter encrypted file name (e.g., encrypted.txt): ").strip()
            output_file = input("Enter output decrypted file name (e.g., decrypted.txt): ").strip()
            key = input_key()

            cipher = read_from_file(input_file)
            if cipher is None:
                continue

            plain = decode_caesar_cipher(cipher, key)
            save_to_file(output_file, plain)
            print("[+] Decryption complete.")

        # EXIT
        elif choice == "0":
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
