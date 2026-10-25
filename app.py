
import base64
import hashlib
import hmac
import html
import json
from pathlib import Path
from datetime import datetime

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# =====================================================
# CONFIGURATION
# =====================================================

st.set_page_config(
    page_title="KeyShield | Secure Workspace",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

HISTORY_FILE = Path(__file__).with_name("keyshield_history.json")
PAGES = ["Home", "Encrypt", "Decrypt", "Integrity Lab", "History"]

defaults = {
    "page": "Home",
    "history": [],
    "encrypted_result": "",
    "decrypted_result": None,
    "encrypt_done": False,
    "decrypt_done": False,
    "integrity_done": False,
}

for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

if not st.session_state.history:
    try:
        if HISTORY_FILE.exists():
            saved_history = json.loads(
                HISTORY_FILE.read_text(encoding="utf-8")
            )
            if isinstance(saved_history, list):
                st.session_state.history = saved_history
    except (OSError, ValueError):
        st.session_state.history = []


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
        raise ValueError("Incomplete encrypted package")

    salt = package[:16]
    nonce = package[16:28]
    tag = package[28:44]
    ciphertext = package[44:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


# =====================================================
# HISTORY
# =====================================================

def log_event(action, status, details):
    entry = {
        "time": datetime.now().astimezone().strftime(
            "%Y-%m-%d %H:%M:%S %Z"
        ),
        "action": action,
        "status": status,
        "details": details,
    }

    st.session_state.history.insert(0, entry)
    st.session_state.history = st.session_state.history[:500]

    try:
        HISTORY_FILE.write_text(
            json.dumps(st.session_state.history, indent=2),
            encoding="utf-8",
        )
    except OSError:
        st.warning("The activity could not be saved to the history file.")


def go_to(page):
    st.session_state.page = page
    st.rerun()


# =====================================================
# PREMIUM DESIGN
# =====================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');

:root {
    --bg: #090d18;
    --panel: #121a2b;
    --line: #283650;
    --cyan: #76ead8;
    --blue: #9cb4ff;
    --muted: #a5b3ca;
}

.stApp {
    background:
      radial-gradient(ellipse at 10% 0%, #173a4b70, transparent 34%),
      radial-gradient(ellipse at 94% 15%, #38275d55, transparent 33%),
      #090d18;
    color: #f2f5ff;
    font-family: 'DM Sans', sans-serif;
}

h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
    color: #f3f6ff !important;
    letter-spacing: -0.6px;
}

p, label, [data-testid="stCaptionContainer"] {
    color: var(--muted);
}

.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3rem;
    max-width: 1250px;
}

[data-testid="stSidebar"] {
    display: none;
}

header[data-testid="stHeader"] {
    background: transparent;
}

#MainMenu, footer {
    visibility: hidden;
}

hr {
    border-color: #26334b;
}

.brand {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 16px 20px;
    margin-bottom: 24px;
    background: #111a2bc9;
    border: 1px solid #2a3a55;
    border-radius: 18px;
    box-shadow: 0 12px 35px #00000020;
}

.brand-name {
    font-family: 'Space Grotesk', sans-serif;
    font-size: 22px;
    font-weight: 700;
    color: #f3f6ff;
}

.brand-name span {
    color: #76ead8;
}

.brand-tag {
    font-size: 10px;
    color: #aabbd2;
    letter-spacing: 1.7px;
    text-align: right;
}

.hero {
    position: relative;
    overflow: hidden;
    padding: 43px 38px;
    border: 1px solid #344767;
    border-radius: 27px;
    background:
      radial-gradient(circle at 90% 20%, #6b66d225, transparent 30%),
      linear-gradient(125deg, #152d43, #15182d 65%, #1b2b3f);
    box-shadow: 0 22px 60px #00000030;
    margin-bottom: 28px;
}

.hero:after {
    content: "◈";
    position: absolute;
    right: 35px;
    top: 2px;
    font-size: 150px;
    color: #76ead8;
    opacity: .07;
    pointer-events: none;
}

.eyebrow, .section-tag {
    color: #76ead8;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 2.4px;
}

.hero h1 {
    font-size: clamp(37px, 5vw, 62px);
    line-height: 1.05;
    margin: 18px 0;
}

.hero p {
    font-size: 16px;
    line-height: 1.8;
    max-width: 690px;
}

.feature-card {
    min-height: 205px;
    padding: 24px;
    border: 1px solid #2b3b56;
    border-radius: 21px;
    background: linear-gradient(145deg, #17243a, #101725);
    box-shadow: 0 14px 32px #00000022;
    transition: transform .22s ease, border-color .22s ease,
                box-shadow .22s ease;
}

.feature-card:hover {
    transform: translateY(-6px);
    border-color: #76ead8;
    box-shadow: 0 18px 42px #00000035, 0 0 20px #76ead81c;
}

.feature-icon {
    font-size: 31px;
    margin-bottom: 15px;
}

.feature-title {
    color: #f4f6ff;
    font-size: 18px;
    font-weight: 700;
    margin-bottom: 9px;
}

.feature-desc {
    color: #a8b7ce;
    font-size: 13px;
    line-height: 1.75;
}

div.stButton > button,
div.stDownloadButton > button {
    min-height: 47px;
    border: 1px solid #52617d;
    border-radius: 14px;
    background: linear-gradient(120deg, #25374f, #222641);
    color: #edf4ff;
    font-weight: 700;
    transition: transform .2s ease, box-shadow .2s ease,
                border-color .2s ease, background .2s ease;
    box-shadow: 0 7px 20px #00000025;
}

div.stButton > button:hover,
div.stDownloadButton > button:hover {
    transform: translateY(-3px);
    border-color: #76ead8;
    background: linear-gradient(115deg, #244b55, #34345d);
    color: #ffffff;
    box-shadow: 0 12px 28px #00000035, 0 0 18px #76ead81b;
}

div.stButton > button:focus,
div.stDownloadButton > button:focus {
    border-color: #76ead8;
    color: #ffffff;
}

.stTextInput input,
.stTextArea textarea {
    background: #0c1422 !important;
    color: #f3f6ff !important;
    border: 1px solid #30425e !important;
    border-radius: 13px !important;
}

[data-testid="stFileUploader"] {
    background: #101a2a;
    border: 1px dashed #4c6385;
    border-radius: 17px;
    padding: 13px;
}

[data-testid="stMetric"] {
    background: linear-gradient(145deg, #17243a, #101725);
    border: 1px solid #2c3c58;
    padding: 17px;
    border-radius: 16px;
}

[data-testid="stMetricValue"] {
    color: #76ead8;
}

div[data-testid="stAlert"] {
    border-radius: 14px;
}

/* HIGH-CONTRAST RECOVERED MESSAGE */

.recovered-card {
    background: linear-gradient(135deg, #102a43, #163b50);
    border: 1px solid #38d9c5;
    border-radius: 18px;
    padding: 24px;
    margin: 18px 0;
    box-shadow: 0 12px 32px #00000035, 0 0 20px #38d9c515;
}

.recovered-label {
    color: #5eead4;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 2px;
    margin-bottom: 14px;
}

.recovered-text {
    color: #ffffff !important;
    font-family: 'DM Sans', sans-serif;
    font-size: 20px;
    font-weight: 600;
    line-height: 1.8;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    word-break: break-word;
    background: transparent;
}

@media (max-width: 700px) {
    .hero {
        padding: 28px 22px;
    }
    .brand {
        padding: 13px;
    }
    .brand-tag {
        font-size: 8px;
    }
    .recovered-text {
        font-size: 17px;
    }
}
</style>
""", unsafe_allow_html=True)


# =====================================================
# HEADER + NAVIGATION
# =====================================================

st.markdown("""
<div class="brand">
  <div class="brand-name">◈ <span>Key</span>Shield</div>
  <div class="brand-tag">CRYPTOGRAPHY · PRIVACY · INTEGRITY</div>
</div>
""", unsafe_allow_html=True)

nav_cols = st.columns(5)
nav_icons = ["⌂", "🔐", "🗝️", "🛡️", "◷"]

for column, page_name, icon in zip(nav_cols, PAGES, nav_icons):
    with column:
        if st.button(
            f"{icon}  {page_name}",
            key=f"nav_{page_name}",
            use_container_width=True,
        ):
            st.session_state.page = page_name
            st.rerun()

st.markdown("---")
page = st.session_state.page


# =====================================================
# HOME
# =====================================================

if page == "Home":
    st.markdown("""
    <div class="hero">
      <div class="eyebrow">◈ YOUR DIGITAL SECURITY STUDIO</div>
      <h1>Make security<br>feel effortless.</h1>
      <p>
        Protect private messages, authenticate encrypted data, and verify
        file integrity in one beautifully simple cryptographic workspace.
      </p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown(
        '<div class="section-tag">EXPLORE YOUR SECURITY TOOLS</div>',
        unsafe_allow_html=True,
    )
    st.write("")

    cols = st.columns(3, gap="medium")
    card_data = [
        ("🔐", "01 / Encrypt", "Turn a readable message into authenticated ciphertext."),
        ("🗝️", "02 / Decrypt", "Authenticate encrypted data and recover your message."),
        ("🛡️", "03 / Integrity", "Calculate and compare SHA-256 file fingerprints."),
    ]

    for col, data in zip(cols, card_data):
        with col:
            st.markdown(f"""
            <div class="feature-card">
              <div class="feature-icon">{data[0]}</div>
              <div class="feature-title">{data[1]}</div>
              <div class="feature-desc">{data[2]}</div>
            </div>
            """, unsafe_allow_html=True)

    st.write("")
    st.markdown("## Your next move")
    st.caption("Choose a tool to begin your security session.")

    a, b, c = st.columns(3)

    with a:
        if st.button("✦  Start encryption  →",
                     key="home_encrypt", use_container_width=True):
            go_to("Encrypt")

    with b:
        if st.button("✦  Open decryption  →",
                     key="home_decrypt", use_container_width=True):
            go_to("Decrypt")

    with c:
        if st.button("✦  Open integrity lab  →",
                     key="home_integrity", use_container_width=True):
            go_to("Integrity Lab")

    st.write("")
    st.markdown("## Recent activity")

    recent = st.session_state.history[:3]

    if not recent:
        st.info("Your activity timeline is waiting for its first security operation.")
    else:
        for event in recent:
            st.markdown(
                f"**{event['action']}** · {event['status']}  \n"
                f"{event['time']} — {event['details']}"
            )
            st.divider()

    if st.button("Explore full activity history  →",
                 use_container_width=True):
        go_to("History")


# =====================================================
# ENCRYPT
# =====================================================

elif page == "Encrypt":
    st.markdown(
        '<div class="section-tag">SECURITY FLOW / STEP 01</div>',
        unsafe_allow_html=True,
    )
    st.title("🔐 Encrypt your message")
    st.write("Start with your message. KeyShield will create authenticated ciphertext.")

    with st.container(border=True):
        message = st.text_area(
            "YOUR PRIVATE MESSAGE",
            placeholder="Type the message you want to protect...",
            height=170,
            key="plain_message",
        )

        password = st.text_input(
            "CREATE AN ENCRYPTION PASSWORD",
            type="password",
            placeholder="At least 12 characters",
            key="encrypt_password",
        )

        if st.button("✦  Encrypt message securely",
                     key="encrypt_action", use_container_width=True):
            if not message:
                st.error("Please enter a message.")
            elif len(password) < 12:
                st.error("Use a password of at least 12 characters.")
            else:
                try:
                    result = encrypt_message(message, password)
                    st.session_state.encrypted_result = result
                    st.session_state.encrypt_done = True
                    st.session_state.decrypt_done = False
                    log_event(
                        "Message encryption",
                        "SUCCESS",
                        "Message encrypted. Message content and password were not saved.",
                    )
                    st.success("Encryption complete! Your ciphertext is ready.")
                    st.toast("Message secured successfully!")
                except Exception:
                    log_event(
                        "Message encryption", "FAILED",
                        "Encryption operation failed.",
                    )
                    st.error("Encryption failed. Please try again.")

    if st.session_state.encrypted_result:
        st.markdown("### ✨ Your encrypted output")
        st.caption(
            "Keep the password private and share it separately from the ciphertext."
        )
        st.code(st.session_state.encrypted_result, language=None)

        st.download_button(
            "⬇  Download encrypted message",
            st.session_state.encrypted_result,
            file_name="keyshield_encrypted.txt",
            mime="text/plain",
            use_container_width=True,
        )

        st.write("")
        st.success("STEP 1 COMPLETE")

        if st.button("Next step: Decrypt your message  →",
                     key="next_to_decrypt", use_container_width=True):
            st.session_state.encrypted_input = st.session_state.encrypted_result
            go_to("Decrypt")


# =====================================================
# DECRYPT
# =====================================================

elif page == "Decrypt":
    st.markdown(
        '<div class="section-tag">SECURITY FLOW / STEP 02</div>',
        unsafe_allow_html=True,
    )
    st.title("🗝️ Authenticate & decrypt")
    st.write("Use the original password to verify and recover the message.")

    with st.container(border=True):
        encrypted_input = st.text_area(
            "ENCRYPTED MESSAGE",
            placeholder="Paste your complete encrypted text here...",
            height=170,
            key="encrypted_input",
        )

        password = st.text_input(
            "ORIGINAL ENCRYPTION PASSWORD",
            type="password",
            key="decrypt_password",
        )

        if st.button("◈  Verify & decrypt",
                     key="decrypt_action", use_container_width=True):
            if not encrypted_input.strip() or not password:
                st.error("Enter both the encrypted message and password.")
            else:
                try:
                    original = decrypt_message(encrypted_input, password)
                    st.session_state.decrypted_result = original
                    st.session_state.decrypt_done = True

                    log_event(
                        "Message decryption",
                        "SUCCESS",
                        "Encrypted data authenticated and decrypted.",
                    )

                    st.success("Authentication passed. Message recovered.")
                    st.toast("Message authenticated!")

                except Exception:
                    st.session_state.decrypted_result = None
                    st.session_state.decrypt_done = False

                    log_event(
                        "Message decryption",
                        "FAILED",
                        "Authentication failed or encrypted data was invalid.",
                    )

                    st.error(
                        "Decryption failed. Check the password and ciphertext. "
                        "The encrypted data may have been changed."
                    )

    # UPDATED DISPLAY: large, readable, white recovered message
    if st.session_state.decrypted_result is not None:
        safe_message = html.escape(
            str(st.session_state.decrypted_result)
        )

        st.markdown(
            f"""
            <div class="recovered-card">
                <div class="recovered-label">
                    ✓ MESSAGE RECOVERED SUCCESSFULLY
                </div>
                <div class="recovered-text">{safe_message}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.success("STEP 2 COMPLETE")

        if st.button("Next step: Verify file integrity  →",
                     key="next_to_integrity", use_container_width=True):
            go_to("Integrity Lab")


# =====================================================
# INTEGRITY LAB
# =====================================================

elif page == "Integrity Lab":
    st.markdown(
        '<div class="section-tag">SECURITY FLOW / STEP 03</div>',
        unsafe_allow_html=True,
    )
    st.title("🛡️ File integrity lab")
    st.write("Generate a SHA-256 fingerprint and compare it with a trusted reference.")

    with st.container(border=True):
        uploaded_file = st.file_uploader(
            "UPLOAD A FILE TO ANALYSE",
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

            with a:
                st.metric("File size", f"{len(file_bytes):,} bytes")

            with b:
                st.metric("Fingerprint", "SHA-256")

            st.markdown("### File fingerprint")
            st.code(digest, language=None)

            st.download_button(
                "⬇  Download SHA-256 fingerprint",
                f"{uploaded_file.name}\n{digest}\n",
                file_name="keyshield_sha256.txt",
                mime="text/plain",
                use_container_width=True,
            )

            if st.button("✦  Verify file integrity",
                         key="verify_integrity", use_container_width=True):
                if not trusted_hash.strip():
                    st.session_state.integrity_done = True

                    log_event(
                        "SHA-256 calculation",
                        "COMPLETED",
                        f"Fingerprint calculated for {uploaded_file.name}.",
                    )

                    st.info(
                        "Fingerprint calculated. Save it as a trusted reference, "
                        "then compare it again later."
                    )
                else:
                    candidate = trusted_hash.strip().lower()
                    valid_format = (
                        len(candidate) == 64
                        and all(ch in "0123456789abcdef" for ch in candidate)
                    )

                    if not valid_format:
                        st.session_state.integrity_done = False
                        st.warning("Enter a valid 64-character SHA-256 hash.")

                    elif hmac.compare_digest(digest, candidate):
                        st.session_state.integrity_done = True

                        log_event(
                            "File integrity verification",
                            "VERIFIED",
                            f"SHA-256 matched for {uploaded_file.name}.",
                        )

                        st.success("✓ Integrity verified — fingerprints match.")

                    else:
                        st.session_state.integrity_done = False

                        log_event(
                            "File integrity verification",
                            "FAILED",
                            f"SHA-256 mismatch for {uploaded_file.name}.",
                        )

                        st.error("✕ Integrity check failed — fingerprints differ.")

    if st.session_state.integrity_done:
        st.write("")
        st.success("STEP 3 COMPLETE")

        if st.button("Finish session: View security history  →",
                     key="finish_to_history", use_container_width=True):
            go_to("History")


# =====================================================
# HISTORY
# =====================================================

elif page == "History":
    st.markdown(
        '<div class="section-tag">YOUR SECURITY TIMELINE</div>',
        unsafe_allow_html=True,
    )
    st.title("◷ Activity history")
    st.write("A local audit trail of the security operations performed in KeyShield.")

    history = st.session_state.history

    successful = sum(
        1 for item in history
        if item["status"] in ("SUCCESS", "VERIFIED", "COMPLETED")
    )
    failed = sum(
        1 for item in history if item["status"] == "FAILED"
    )

    a, b, c = st.columns(3)
    a.metric("Total actions", len(history))
    b.metric("Successful", successful)
    c.metric("Failed", failed)

    st.write("")

    if history:
        search = st.text_input(
            "Search activity",
            placeholder="Search by operation or details...",
        )

        status_filter = st.selectbox(
            "Filter by status",
            ["All", "SUCCESS", "VERIFIED", "COMPLETED", "FAILED"],
        )

        filtered = history

        if search.strip():
            query = search.strip().lower()
            filtered = [
                item for item in filtered
                if query in item.get("action", "").lower()
                or query in item.get("details", "").lower()
            ]

        if status_filter != "All":
            filtered = [
                item for item in filtered
                if item.get("status") == status_filter
            ]

        st.caption(
            f"Showing {len(filtered)} of {len(history)} recorded actions"
        )

        for item in filtered:
            with st.container(border=True):
                a, b = st.columns([3, 1])

                with a:
                    st.markdown(f"### {item.get('action', 'Activity')}")
                    st.caption(item.get("time", ""))
                    st.write(item.get("details", ""))

                with b:
                    status = item.get("status", "UNKNOWN")
                    if status in ("SUCCESS", "VERIFIED", "COMPLETED"):
                        st.success(status)
                    else:
                        st.error(status)

        st.download_button(
            "⬇  Export activity history",
            json.dumps(history, indent=2),
            file_name="keyshield_history_export.json",
            mime="application/json",
            use_container_width=True,
        )

        st.divider()

        if st.button("Clear history", key="clear_history"):
            st.session_state.confirm_clear_history = True

        if st.session_state.get("confirm_clear_history", False):
            st.warning(
                "This will permanently clear the local activity history."
            )

            a, b = st.columns(2)

            with a:
                if st.button("Confirm clear history"):
                    st.session_state.history = []

                    try:
                        HISTORY_FILE.write_text("[]", encoding="utf-8")
                    except OSError:
                        st.error("Could not clear the history file.")

                    st.session_state.confirm_clear_history = False
                    st.rerun()

            with b:
                if st.button("Cancel"):
                    st.session_state.confirm_clear_history = False
                    st.rerun()

    else:
        st.info("No activity recorded yet. Start by encrypting a message.")

    st.caption(
        "Privacy: the history records operations and timestamps, "
        "not passwords or original message contents."
    )


# =====================================================
# FOOTER
# =====================================================

st.markdown("---")
st.markdown(
    "<div style='text-align:center;color:#8495af;font-size:12px;'>"
    "◈ KEYSHIELD &nbsp; · &nbsp; CRYPTOGRAPHY AND NETWORK SECURITY"
    "<br><br>AES-GCM &nbsp; · &nbsp; PBKDF2 &nbsp; · &nbsp; SHA-256"
    "</div>",
    unsafe_allow_html=True,
)
