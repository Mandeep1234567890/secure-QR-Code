import streamlit as st
import qrcode
import base64
import os
import cv2
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# ---------------- KEY GENERATION ----------------
def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ---------------- STREAMLIT UI ----------------
st.set_page_config(page_title="Secure QR Code Generator", page_icon="🔐")
st.title("🔐 Secure QR Code Generator with Encryption")

tab1, tab2 = st.tabs(["🔒 Generate Secure QR", "🔓 Scan & Decrypt QR"])

# ---------------- TAB 1: GENERATE QR ----------------
with tab1:
    st.subheader("Generate Encrypted QR Code")

    secret_message = st.text_area("Enter Secret Message")
    password = st.text_input("Set Password", type="password")

    if st.button("Generate Secure QR"):
        if secret_message and password:
            salt = os.urandom(16)
            key = generate_key(password, salt)
            cipher = Fernet(key)

            encrypted_data = cipher.encrypt(secret_message.encode())

            # Combine salt + encrypted data
            final_data = base64.b64encode(salt + encrypted_data).decode()

            qr = qrcode.make(final_data)
            qr.save("secure_qr.png")

            st.success("Secure QR Code Generated!")
            st.image("secure_qr.png", caption="Encrypted QR Code")
            st.download_button(
                "Download QR Code",
                data=open("secure_qr.png", "rb"),
                file_name="secure_qr.png"
            )
        else:
            st.error("Please enter both message and password.")

# ---------------- TAB 2: SCAN & DECRYPT ----------------
with tab2:
    st.subheader("Scan & Decrypt Secure QR Code")

    uploaded_file = st.file_uploader("Upload Secure QR Image", type=["png", "jpg"])
    decrypt_password = st.text_input("Enter Password", type="password")

    if st.button("Decrypt QR"):
        if uploaded_file and decrypt_password:
            image = Image.open(uploaded_file)
            img_np = np.array(image)

            detector = cv2.QRCodeDetector()
            data, _, _ = detector.detectAndDecode(img_np)

            if data:
                decoded = base64.b64decode(data.encode())
                salt = decoded[:16]
                encrypted_message = decoded[16:]

                try:
                    key = generate_key(decrypt_password, salt)
                    cipher = Fernet(key)
                    decrypted_message = cipher.decrypt(encrypted_message).decode()

                    st.success("Decryption Successful!")
                    st.text_area("Decrypted Message", decrypted_message)
                except:
                    st.error("Incorrect password or corrupted QR code.")
            else:
                st.error("QR Code not detected.")
        else:
            st.warning("Please upload QR image and enter password.")
