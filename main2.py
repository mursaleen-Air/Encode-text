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

# --- initialize history ---
if "history" not in st.session_state:
    st.session_state.history = []

# --- reset text ---
def reset_text():
    st.session_state["text_input"] = ""

text = st.text_area(
    "Enter text:",
    key="text_input",
    placeholder="Enter text",
    height=160
)

col1, col2 = st.columns([1, 1])
with col1:
    st.button("Clear", on_click=reset_text)
with col2:
    show_history = st.button("📜 Show History")

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
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("utf-8")

def decrypt(b64blob: str, password: str) -> str:
    blob = base64.b64decode(b64blob)
    if len(blob) < (16 + 12 + 16):
        raise ValueError("Ciphertext blob too short or corrupted.")
    salt = blob[:16]
    nonce = blob[16:28]
    ct = blob[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ct, associated_data=None)
    return plaintext_bytes.decode("utf-8")

# --- main action ---
if st.button("Run"):
    if not password:
        st.error("Enter the shared password.")
    elif not text.strip():
        st.error("Enter text (plaintext or Base64 ciphertext).")
    else:
        try:
            if mode == "Encrypt":
                if use_custom_salt and custom_salt:
                    salt_bytes = custom_salt.encode("utf-8")
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

                # save to history
                st.session_state.history.insert(0, ("Encrypt", text, ciphertext_b64))
            else:
                try:
                    plaintext = decrypt(text.strip(), password)
                    st.success("Decrypted successfully.")
                    st.code(plaintext, language="text")

                    # save to history
                    st.session_state.history.insert(0, ("Decrypt", text, plaintext))
                except Exception as e:
                    st.error(f"Decryption failed: {str(e)}")
                    st.info("Check that the ciphertext and password are correct and that ciphertext is complete.")
        except Exception as e:
            st.error(f"Error: {str(e)}")

# --- show history (last 10 only) ---
if show_history:
    if not st.session_state.history:
        st.info("No history yet.")
    else:
        st.subheader("📜 Last 10 Encryption / Decryption Records")
        for i, (action, input_text, result) in enumerate(st.session_state.history[:10], start=1):
            st.markdown(f"**{i}. {action}**")
            with st.expander("Show details"):
                st.markdown(f"**Input:**\n```\n{input_text}\n```")
                st.markdown(f"**Result:**\n```\n{result}\n```")
