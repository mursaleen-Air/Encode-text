# secure_text_encryptor.py
import streamlit as st
import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

st.set_page_config(page_title="Secure Text Encryptor (AES-GCM)", page_icon="🔐", layout="centered")
st.title("🔐 Secure Text Encryptor / Decryptor")
st.write(
    """
    Encrypt text with AES-GCM using a password-derived key.
    Paste the resulting Base64 ciphertext into WhatsApp.
    The recipient must use the same password to decrypt.
    """
)

mode = st.radio("Mode", ("Encrypt", "Decrypt"), horizontal=True)

text = st.text_area("Text (plaintext to encrypt or Base64 ciphertext to decrypt)", height=160)
password = st.text_input("Password (shared secret) — must be identical for sender and receiver", type="password")
# optional: show/hide salt display
use_custom_salt = st.checkbox("Provide custom salt (advanced)", value=False)
custom_salt = None
if use_custom_salt:
    custom_salt = st.text_input("Custom salt (any text). If left blank a secure random salt will be used)")

INFO = st.info if mode == "Encrypt" else st.warning
INFO("Do NOT share the password over the same channel you're trying to protect. Exchange it securely.")

# --- helpers ---
def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    # PBKDF2-HMAC-SHA256
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(password_bytes)

def encrypt(plaintext: str, password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for AESGCM
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    # package: salt || nonce || ciphertext, then base64 encode
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("utf-8")

def decrypt(b64blob: str, password: str) -> str:
    blob = base64.b64decode(b64blob)
    if len(blob) < (16 + 12 + 16):  # minimal lengths: salt 16 + nonce 12 + tag+something
        raise ValueError("Ciphertext blob too short or corrupted.")
    salt = blob[:16]
    nonce = blob[16:28]
    ct = blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ct, associated_data=None)
    return plaintext_bytes.decode("utf-8")

# --- UI action ---
if st.button("Run"):
    if not password:
        st.error("Enter the shared password.")
    elif not text.strip():
        st.error("Enter text (plaintext or Base64 ciphertext).")
    else:
        try:
            if mode == "Encrypt":
                # allow user to set a reproducible salt if they checked custom (advanced)
                if use_custom_salt and custom_salt:
                    salt_bytes = custom_salt.encode("utf-8")
                    # ensure 16 bytes salt (pad or truncate)
                    if len(salt_bytes) < 16:
                        salt_bytes = salt_bytes.ljust(16, b"\0")
                    else:
                        salt_bytes = salt_bytes[:16]
                else:
                    salt_bytes = None
                ciphertext_b64 = encrypt(text, password, salt=salt_bytes)
                st.success("Encrypted successfully. Copy the Base64 below and send it.")
                st.code(ciphertext_b64, language="text")
                st.caption("Recipient must paste this ciphertext and use the same password to decrypt.")
            else:
                # Decrypt
                try:
                    plaintext = decrypt(text.strip(), password)
                    st.success("Decrypted successfully.")
                    st.code(plaintext, language="text")
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")
                    st.info("Check that the ciphertext and password are correct and that ciphertext is complete.")
        except Exception as e:
            st.error(f"Error: {str(e)}")

