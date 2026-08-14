def caesar_cipher(text, shift):
    result = ""

    for char in text:
        if char.isupper():
            result += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))

        elif char.islower():
            result += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

        else:
            result += char

    return result


def get_shift():
    while True:
        try:
            shift = int(input("Enter the shift value (0-25): "))

            if 0 <= shift <= 25:
                return shift

            print("Please enter a number between 0 and 25.")

        except ValueError:
            print("Invalid input! Please enter a number.")


def main():
    print("=" * 50)
    print("        CAESAR CIPHER - CYBERSECURITY TOOL")
    print("=" * 50)

    while True:
        print("\nChoose an option:")
        print("1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")

        choice = input("\nEnter your choice (1-3): ").strip()

        if choice == "1":
            text = input("\nEnter the text to encrypt: ")
            shift = get_shift()

            encrypted_text = caesar_cipher(text, shift)

            print("\nEncrypted Text:", encrypted_text)

        elif choice == "2":
            text = input("\nEnter the text to decrypt: ")
            shift = get_shift()

            decrypted_text = caesar_cipher(text, -shift)

            print("\nDecrypted Text:", decrypted_text)

        elif choice == "3":
            print("\nThank you for using Caesar Cipher!")
            break

        else:
            print("\nInvalid choice! Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()