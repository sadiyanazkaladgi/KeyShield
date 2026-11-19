
import base64
import hashlib
import hmac
from datetime import datetime
from pathlib import Path

import streamlit as st
from supabase import create_client, Client
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# =====================================================
# CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="KeyShield | Secure Digital Studio",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

.stApp {
    background:
      radial-gradient(ellipse at 10% 0%, #173a4b70, transparent 34%),
      radial-gradient(ellipse at 94% 15%, #38275d55, transparent 33%),
      #090d18;
    color: #f2f5ff;
    font-family: 'DM Sans', sans-serif;
}
h1,h2,h3 { color:#f3f6ff !important; font-family:'Space Grotesk',sans-serif !important; }
p,label { color:#b1bfd4; }
.block-container {max-width:1200px;padding-top:2rem;padding-bottom:3rem;}
[data-testid="stSidebar"] {display:none;}
#MainMenu,footer {visibility:hidden;}
.brand {
    padding:18px 24px;
    border:1px solid #30425e;
    border-radius:18px;
    background:linear-gradient(120deg,#172b40,#17192f);
    margin-bottom:24px;
    font-size:24px;
    font-weight:700;
}
.brand span {color:#76ead8;}
.hero {
    padding:42px;
    border:1px solid #344767;
    border-radius:26px;
    background:linear-gradient(125deg,#152d43,#15182d 65%,#1b2b3f);
    margin-bottom:25px;
}
.eyebrow {color:#76ead8;letter-spacing:2px;font-size:11px;font-weight:700;}
.feature {
    padding:23px;
    min-height:150px;
    border:1px solid #30425e;
    border-radius:20px;
    background:linear-gradient(145deg,#17243a,#101725);
    transition:all .2s ease;
}
.feature:hover {transform:translateY(-5px);border-color:#76ead8;}
div.stButton>button,div.stDownloadButton>button {
    min-height:46px;
    border:1px solid #52617d;
    border-radius:13px;
    background:linear-gradient(120deg,#25374f,#222641);
    color:#f3f6ff;
    font-weight:700;
    box-shadow:0 7px 20px #0003;
    transition:all .2s ease;
}
div.stButton>button:hover,div.stDownloadButton>button:hover {
    transform:translateY(-3px);
    border-color:#76ead8;
    background:linear-gradient(115deg,#244b55,#34345d);
    color:white;
}
.stTextInput input,.stTextArea textarea {
    background:#0c1422 !important;
    color:#f3f6ff !important;
    border:1px solid #30425e !important;
    border-radius:12px !important;
}
[data-testid="stFileUploader"] {
    background:#101a2a;
    border:1px dashed #4c6385;
    border-radius:16px;
    padding:12px;
}
[data-testid="stMetric"] {
    background:#17243a;
    border:1px solid #30425e;
    padding:15px;
    border-radius:15px;
}
[data-testid="stMetricValue"] {color:#76ead8;}
hr {border-color:#30425e;}
</style>
""", unsafe_allow_html=True)


# =====================================================
# SUPABASE CONNECTION
# =====================================================


def get_supabase():
    url = st.secrets["SUPABASE_URL"]
    key = st.secrets["SUPABASE_KEY"]
    return create_client(url, key)


try:
    supabase: Client = get_supabase()
except Exception:
    st.error(
        "Supabase connection settings are missing. "
        "Check your .streamlit/secrets.toml file."
    )
    st.stop()


# =====================================================
# SESSION STATE
# =====================================================

defaults = {
    "access_token": None,
    "refresh_token": None,
    "user_email": None,
    "page": "Home",
    "decrypted_result": None,
    "encrypted_result": "",
    "integrity_result": None,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value


def save_login(response):
    session = response.session
    user = response.user

    if session is None or user is None:
        return False

    st.session_state.access_token = session.access_token
    st.session_state.refresh_token = session.refresh_token
    st.session_state.user_email = user.email
    return True


def get_logged_in_client():
    if not st.session_state.access_token:
        return None

    try:
        supabase.auth.set_session(
            st.session_state.access_token,
            st.session_state.refresh_token,
        )
        return supabase
    except Exception:
        st.session_state.access_token = None
        st.session_state.refresh_token = None
        st.session_state.user_email = None
        return None


def logout():
    try:
        if st.session_state.access_token:
            supabase.auth.sign_out()
    except Exception:
        pass

    for key in [
        "access_token",
        "refresh_token",
        "user_email",
        "decrypted_result",
        "encrypted_result",
        "integrity_result",
    ]:
        st.session_state[key] = None if key != "encrypted_result" else ""

    st.session_state.page = "Home"
    st.rerun()


# =====================================================
# CRYPTOGRAPHY
# =====================================================

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000,
        dklen=32,
    )


def encrypt_message(message, password):
    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)
    key = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(
        message.encode("utf-8")
    )

    package = salt + nonce + tag + ciphertext
    return base64.b64encode(package).decode("utf-8")


def decrypt_message(encoded_data, password):
    package = base64.b64decode(
        encoded_data.strip(),
        validate=True,
    )

    if len(package) < 44:
        raise ValueError("Invalid encrypted package")

    salt = package[:16]
    nonce = package[16:28]
    tag = package[28:44]
    ciphertext = package[44:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


# =====================================================
# DATABASE ACTIVITY
# =====================================================

def log_event(action, status, details):
    try:
        client = get_logged_in_client()
        if client is None:
            return False

        user_response = client.auth.get_user()
        user = user_response.user

        if user is None:
            return False

        client.table("activity_logs").insert({
            "user_id": user.id,
            "action": action,
            "status": status,
            "details": details,
        }).execute()

        return True

    except Exception as error:
        st.error("Database activity could not be saved. Check your connection and RLS policies.")
        return False


def get_history():
    try:
        client = get_logged_in_client()
        if client is None:
            return []

        response = client.table("activity_logs") \
            .select("id,action,status,details,created_at") \
            .order("created_at", desc=True) \
            .limit(500) \
            .execute()

        return response.data or []

    except Exception:
        st.error("Could not load your activity history.")
        return []


# =====================================================
# HEADER
# =====================================================

st.markdown("""
<div class="brand">◈ <span>Key</span>Shield
<div style="font-size:10px;color:#aabbd2;letter-spacing:2px;">
CRYPTOGRAPHY · PRIVACY · INTEGRITY
</div>
</div>
""", unsafe_allow_html=True)


# =====================================================
# AUTHENTICATION
# =====================================================

if not st.session_state.access_token:

    st.markdown("""
    <div class="hero">
      <div class="eyebrow">YOUR DIGITAL SECURITY STUDIO</div>
      <h1>Welcome to KeyShield 🔐</h1>
      <p>Create an account or sign in to access your personal
      cryptographic workspace.</p>
    </div>
    """, unsafe_allow_html=True)

    login_tab, register_tab = st.tabs([
        "🔑 Sign In",
        "✨ Create Account",
    ])

    with login_tab:
        st.subheader("Welcome back")

        email = st.text_input(
            "Email address",
            key="login_email",
            placeholder="you@example.com",
        )

        password = st.text_input(
            "Password",
            type="password",
            key="login_password",
        )

        if st.button("Sign in securely →", use_container_width=True):
            if not email.strip() or not password:
                st.error("Enter your email and password.")
            else:
                try:
                    response = supabase.auth.sign_in_with_password({
                        "email": email.strip(),
                        "password": password,
                    })

                    if save_login(response):
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("No active session. Please verify your email first.")

                except Exception:
                    st.error(
                        "Login failed. Check your email, password, "
                        "and email verification."
                    )

    with register_tab:
        st.subheader("Create your KeyShield account")

        name = st.text_input(
            "Your name",
            key="register_name",
        )

        email = st.text_input(
            "Email address",
            key="register_email",
        )

        password = st.text_input(
            "Create password",
            type="password",
            key="register_password",
        )

        confirm_password = st.text_input(
            "Confirm password",
            type="password",
            key="register_confirm",
        )

        st.caption("Use at least 12 characters for your password.")

        if st.button("Create my account →", use_container_width=True):
            if not name.strip() or not email.strip():
                st.error("Enter your name and email.")
            elif len(password) < 12:
                st.error("Password must contain at least 12 characters.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            else:
                try:
                    response = supabase.auth.sign_up({
                        "email": email.strip(),
                        "password": password,
                        "options": {
                            "data": {
                                "full_name": name.strip()
                            }
                        },
                    })

                    if save_login(response):
                        st.success("Account created! You are signed in.")
                        st.rerun()
                    else:
                        st.success(
                            "Registration successful! "
                            "Check your email and click the confirmation link. "
                            "Then return here and sign in."
                        )

                except Exception:
                    st.error(
                        "Registration failed. This email may already be "
                        "registered, or the email service may need attention."
                    )

    st.markdown("---")
    st.caption(
        "KeyShield uses Supabase Authentication. "
        "Your password is never stored in the activity history."
    )
    st.stop()


# =====================================================
# AUTHENTICATED USER
# =====================================================

client = get_logged_in_client()

if client is None:
    st.warning("Your session expired. Please sign in again.")
    logout()

# Verify the current token with Supabase.
try:
    current_user = client.auth.get_user().user
    if current_user is None:
        logout()
except Exception:
    logout()

st.caption(f"Signed in as: {st.session_state.user_email}")

# Navigation
PAGES = ["Home", "Encrypt", "Decrypt", "Integrity Lab", "History"]

nav_columns = st.columns(5)

for column, page_name, icon in zip(
    nav_columns,
    PAGES,
    ["⌂", "🔐", "🗝️", "🛡️", "◷"],
):
    with column:
        if st.button(
            f"{icon} {page_name}",
            key=f"nav_{page_name}",
            use_container_width=True,
        ):
            st.session_state.page = page_name
            st.rerun()

page = st.session_state.page

if st.button("↪ Sign out", key="logout_button"):
    logout()

st.divider()


# =====================================================
# HOME
# =====================================================

if page == "Home":

    st.markdown("""
    <div class="hero">
      <div class="eyebrow">YOUR PERSONAL SECURITY STUDIO</div>
      <h1>Make security feel effortless.</h1>
      <p>Protect messages, authenticate encrypted data,
      and verify file integrity in one workspace.</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("## Explore your security tools")

    cols = st.columns(3)

    features = [
        ("🔐", "Message encryption", "Protect private messages with AES-GCM."),
        ("🗝️", "Message decryption", "Authenticate and recover your messages."),
        ("🛡️", "Integrity laboratory", "Calculate and compare SHA-256 fingerprints."),
    ]

    for col, item in zip(cols, features):
        with col:
            st.markdown(f"""
            <div class="feature">
              <div style="font-size:30px">{item[0]}</div>
              <h3>{item[1]}</h3>
              <p>{item[2]}</p>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    a, b, c = st.columns(3)

    with a:
        if st.button("Start encryption →", use_container_width=True):
            st.session_state.page = "Encrypt"
            st.rerun()

    with b:
        if st.button("Open decryption →", use_container_width=True):
            st.session_state.page = "Decrypt"
            st.rerun()

    with c:
        if st.button("Open integrity lab →", use_container_width=True):
            st.session_state.page = "Integrity Lab"
            st.rerun()

    st.markdown("## Recent activity")

    recent = get_history()[:3]

    if not recent:
        st.info("Your security activity will appear here.")
    else:
        for item in recent:
            st.write(
                f"**{item['action']}** · {item['status']}  \n"
                f"{item['created_at']}"
            )
            st.divider()


# =====================================================
# ENCRYPT
# =====================================================

elif page == "Encrypt":

    st.title("🔐 Message encryption")
    st.write("Transform your private message into authenticated ciphertext.")

    message = st.text_area(
        "YOUR PRIVATE MESSAGE",
        height=160,
        placeholder="Type your message...",
        key="plain_message",
    )

    password = st.text_input(
        "CREATE ENCRYPTION PASSWORD",
        type="password",
        key="encrypt_password",
    )

    if st.button("✦ Encrypt message securely", use_container_width=True):

        if not message:
            st.error("Enter a message.")
        elif len(password) < 12:
            st.error("Use a password of at least 12 characters.")
        else:
            try:
                result = encrypt_message(message, password)
                st.session_state.encrypted_result = result

                saved = log_event(
                    "Message encryption",
                    "SUCCESS",
                    "Message encrypted using AES-256-GCM. Message and password not stored.",
                )

                st.success("Encryption completed successfully!")

                if not saved:
                    st.warning("The result was created, but its activity log was not saved.")

            except Exception:
                st.error("Encryption failed.")

    if st.session_state.encrypted_result:

        st.markdown("### ✨ Encrypted output")
        st.caption("Keep your password private. Share it separately.")

        st.code(st.session_state.encrypted_result)

        st.download_button(
            "⬇ Download encrypted message",
            st.session_state.encrypted_result,
            file_name="keyshield_encrypted.txt",
            mime="text/plain",
            use_container_width=True,
        )

        if st.button("Next: Decrypt message →", use_container_width=True):
            st.session_state.encrypted_input = st.session_state.encrypted_result
            st.session_state.page = "Decrypt"
            st.rerun()


# =====================================================
# DECRYPT
# =====================================================

elif page == "Decrypt":

    st.title("🗝️ Message decryption")
    st.write("Authenticate encrypted data and recover the original message.")

    encrypted = st.text_area(
        "ENCRYPTED MESSAGE",
        height=160,
        key="encrypted_input",
        placeholder="Paste encrypted text here...",
    )

    password = st.text_input(
        "ORIGINAL ENCRYPTION PASSWORD",
        type="password",
        key="decrypt_password",
    )

    if st.button("◈ Verify and decrypt", use_container_width=True):

        if not encrypted.strip() or not password:
            st.error("Enter both ciphertext and password.")
        else:
            try:
                original = decrypt_message(encrypted, password)
                st.session_state.decrypted_result = original

                saved = log_event(
                    "Message decryption",
                    "SUCCESS",
                    "AES-GCM authentication passed and plaintext recovered. Message not stored.",
                )

                st.success("Authentication passed. Message recovered!")

                if not saved:
                    st.warning("The activity log could not be saved.")

            except Exception:
                st.session_state.decrypted_result = None

                log_event(
                    "Message decryption",
                    "FAILED",
                    "Authentication failed or encrypted data was invalid.",
                )

                st.error(
                    "Decryption failed. Check your password and encrypted data."
                )

    if st.session_state.decrypted_result is not None:

        st.markdown("### ✓ Recovered plaintext")

        st.text_area(
            "YOUR DECRYPTED MESSAGE",
            value=st.session_state.decrypted_result,
            height=150,
            disabled=True,
            key="recovered_message_display",
        )

        st.success("STEP 2 COMPLETE")

        if st.button("Next: Integrity laboratory →", use_container_width=True):
            st.session_state.page = "Integrity Lab"
            st.rerun()


# =====================================================
# INTEGRITY LAB
# =====================================================

elif page == "Integrity Lab":

    st.title("🛡️ File integrity laboratory")
    st.write("Calculate and compare SHA-256 fingerprints.")

    uploaded_file = st.file_uploader(
        "UPLOAD FILE",
        key="integrity_file",
            )

    trusted_hash = st.text_input(
        "TRUSTED SHA-256 HASH (OPTIONAL)",
        placeholder="Paste a previously saved 64-character hash",
    )

    if uploaded_file is not None:

        file_bytes = uploaded_file.getvalue()
        digest = hashlib.sha256(file_bytes).hexdigest()

        a, b = st.columns(2)

        a.metric("File size", f"{len(file_bytes):,} bytes")
        b.metric("Algorithm", "SHA-256")

        st.markdown("### File fingerprint")
        st.code(digest)

        st.download_button(
            "⬇ Download fingerprint",
            f"{uploaded_file.name}\n{digest}\n",
            file_name="keyshield_sha256.txt",
            mime="text/plain",
            use_container_width=True,
        )

        if st.button("✦ Verify file integrity", use_container_width=True):

            if not trusted_hash.strip():
                st.info(
                    "Fingerprint calculated. Save it and upload the same file "
                    "later to compare against this trusted hash."
                )

                log_event(
                    "SHA-256 calculation",
                    "COMPLETED",
                    f"Fingerprint calculated for {uploaded_file.name}.",
                )

            else:
                candidate = trusted_hash.strip().lower()

                valid_format = (
                    len(candidate) == 64
                    and all(ch in "0123456789abcdef" for ch in candidate)
                )

                if not valid_format:
                    st.warning("Enter a valid 64-character SHA-256 hash.")

                elif hmac.compare_digest(digest, candidate):

                    st.success("✓ Integrity verified — fingerprints match.")

                    log_event(
                        "File integrity verification",
                        "VERIFIED",
                        f"SHA-256 matched for {uploaded_file.name}.",
                    )

                else:

                    st.error("✕ Integrity check failed — fingerprints differ.")

                    log_event(
                        "File integrity verification",
                        "FAILED",
                        f"SHA-256 mismatch for {uploaded_file.name}.",
                    )

        st.success("STEP 3 COMPLETE")

        if st.button("Finish: View activity history →"):
            st.session_state.page = "History"
            st.rerun()


# =====================================================
# HISTORY
# =====================================================

elif page == "History":

    st.title("◷ Your security history")
    st.write("Your activities are retrieved from the Supabase database.")

    if st.button("↻ Refresh history"):
        st.rerun()

    history = get_history()

    successful = sum(
        1 for item in history
        if item["status"] in ("SUCCESS", "VERIFIED", "COMPLETED")
    )

    failed = sum(
        1 for item in history
        if item["status"] == "FAILED"
    )

    a, b, c = st.columns(3)

    a.metric("Total activities", len(history))
    b.metric("Successful", successful)
    c.metric("Failed", failed)

    if history:

        search = st.text_input("Search your activity")

        filtered = [
            item for item in history
            if search.lower() in (
                str(item["action"]) + " " + str(item["details"])
            ).lower()
        ]

        for item in filtered:

            with st.container(border=True):

                left, right = st.columns([3, 1])

                with left:
                    st.markdown(f"### {item['action']}")
                    st.caption(item["created_at"])
                    st.write(item["details"])

                with right:
                    if item["status"] in ("SUCCESS", "VERIFIED", "COMPLETED"):
                        st.success(item["status"])
                    else:
                        st.error(item["status"])

        st.download_button(
            "⬇ Export my activity",
            data=__import__("json").dumps(history, indent=2),
            file_name="keyshield_my_history.json",
            mime="application/json",
            use_container_width=True,
        )

    else:
        st.info("No activity recorded yet. Start using your security tools.")

    st.caption(
        "Privacy: passwords, original messages and encryption keys "
        "are not saved in the activity database."
    )


# =====================================================
# FOOTER
# =====================================================

st.divider()

st.markdown("""
<div style="text-align:center;color:#8495af;font-size:12px;">
◈ KEYSHIELD · CRYPTOGRAPHY AND NETWORK SECURITY
<br><br>
AES-256-GCM · PBKDF2 · SHA-256 · SUPABASE POSTGRESQL
</div>
""", unsafe_allow_html=True)
