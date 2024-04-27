from cryptography.fernet import Fernet
import base64
import streamlit as st

def pad_and_encode_key(user_key):
    # Pad the key with spaces or zeros to reach 32 bytes
    padded_key = user_key.ljust(32)[:32]
    # Encode the padded key in base64
    base64_key = base64.urlsafe_b64encode(padded_key.encode())
    return base64_key

def encrypt_message(message, key):
    try:
        # Initialize a Fernet object with the encoded key
        cipher = Fernet(key)
        # Encrypt the message
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message
    except Exception as e:
        st.error(f"Error encrypting message: {e}")
        return None

def decrypt_message(encrypted_message, key):
    try:
        # Initialize a Fernet object with the encoded key
        cipher = Fernet(key)
        # Decrypt the message
        decrypted_message = cipher.decrypt(encrypted_message)
        return decrypted_message.decode()
    except Exception as e:
        st.error(f"Error decrypting message: {e}")
        return None

def main():
    st.title("Encryption and Decryption Tool")

    # Ask the user to choose between encryption and decryption
    choice = st.radio("Choose an operation:", ("Encrypt", "Decrypt"))

    # Ask the user for their key
    user_key = st.text_input("Enter your key:")

    # Pad and encode the key
    encoded_key = pad_and_encode_key(user_key)
    
    if choice == "Encrypt":
        # Ask the user for a message to encrypt
        message = st.text_area("Enter the message to encrypt:")
        if st.button("Encrypt"):
            encrypted_message = encrypt_message(message, encoded_key)
            if encrypted_message:
                st.text("Encrypted message:")
                st.code(encrypted_message.decode())
    elif choice == "Decrypt":
        # Ask the user for the encrypted message to decrypt
        encrypted_message = st.text_area("Enter the encrypted message to decrypt:")
        if st.button("Decrypt"):
            decrypted_message = decrypt_message(encrypted_message.encode(), encoded_key)
            if decrypted_message:
                st.text("Decrypted message:")
                st.code(decrypted_message)

if __name__ == "__main__":
    main()
