import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ---------------------- Configuration ----------------------

# Generate encryption key (in production, store securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # Format: {encrypted_text: {"encrypted_text": ..., "passkey": ...}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# ---------------------- Utility Functions ----------------------

def hash_passkey(passkey: str) -> str:
    """Hash passkey using SHA-256"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str, passkey: str) -> str:
    """Encrypt plain text"""
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str | None:
    """Attempt to decrypt if passkey is correct"""
    hashed = hash_passkey(passkey)

    # Match encrypted data and passkey
    entry = stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()

    # Failed attempt
    st.session_state.failed_attempts += 1
    return None

def reset_auth():
    st.session_state.failed_attempts = 0
    st.session_state.authenticated = True
    st.experimental_rerun()

# ---------------------- Streamlit UI ----------------------

st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# ---------------------- Home Page ----------------------
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using your personal passkey.")
    st.info("Data is stored only in memory and deleted on refresh.")

# ---------------------- Store Data Page ----------------------
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter your secret data:")
    passkey = st.text_input("Choose a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data, passkey)
            hashed_pass = hash_passkey(passkey)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed_pass}
            st.success("✅ Your data has been encrypted and stored securely.")
            st.code(encrypted, language='text')
        else:
            st.warning("⚠️ Please fill in both fields.")

# ---------------------- Retrieve Data Page ----------------------
elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.authenticated:
        st.warning("🔒 Too many failed attempts. Please log in to continue.")
        st.experimental_set_query_params(page="Login")
        st.switch_page("Login")
    else:
        st.subheader("🔍 Retrieve Your Secret Data")
        encrypted_text = st.text_area("Enter your encrypted data:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                result = decrypt_data(encrypted_text, passkey)
                if result:
                    st.success("✅ Decryption successful!")
                    st.code(result, language='text')
                else:
                    remaining = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if remaining <= 0:
                        st.warning("🔒 You've reached the max attempts. Redirecting to login.")
                        st.experimental_rerun()
            else:
                st.warning("⚠️ Please enter both encrypted data and passkey.")

# ---------------------- Login Page ----------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_password == "admin123":  # Replace this with secure logic in production
            reset_auth()
            st.success("✅ Reauthorization successful! You can now retrieve data again.")
        else:
            st.error("❌ Incorrect password!")
