import streamlit as st
from datetime import datetime
import platform, os, shutil

from database import *
from database import freeze_user, unfreeze_user, request_unfreeze, get_user_status, get_frozen_users
from database import create_broadcast, get_broadcasts, get_user_pref, set_user_pref
from database import record_failed_login, reset_failed_logins, check_lockout
from database import add_reaction, get_reactions
from database import save_admin_note, get_admin_notes
from database import log_login_device, get_login_devices
from auth import is_strong_password, register_user, login_user, change_password
from crypto_utils import double_encrypt, double_decrypt, hash_message
from tamper_detection import verify_integrity
from logger import log_action, get_logs, get_user_logs
import pandas as pd
import plotly.express as px
from secure_messaging import generate_keys
from secure_messaging import *
from database import *
from create_admin import *


# -------------------------
# DURESS PIN HELPER
# -------------------------
def is_duress_pin(entered_pin: str, real_pin: str) -> bool:
    """Return True if the entered PIN is the reverse of the real PIN (duress signal)."""
    return entered_pin == real_pin[::-1] and entered_pin != real_pin


def check_pin(entered_pin: str, user_data: dict, context: str, current_user: str) -> str:
    """
    Validate PIN.  Returns:
      'ok'     – correct PIN
      'duress' – duress (reversed) PIN  → silent alert logged, behave normally
      'wrong'  – wrong PIN
    """
    real_pin = str(user_data["pin"])
    if entered_pin == real_pin:
        return "ok"
    if is_duress_pin(entered_pin, real_pin):
        log_action(current_user,
                   f"[DURESS ALERT] User entered reversed PIN during: {context}",
                   "CRITICAL")
        return "duress"
    return "wrong"


def get_public_key_func(username):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    return load_public_key(result[0])


def is_admin(role: str) -> bool:
    return role == "admin"



# -------------------------
# INIT
# -------------------------
init_db()
from secure_messaging import init_secure_messages_table
init_secure_messages_table()

st.set_page_config(
    page_title="Secure Chat System",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Secure Chat System with Breach Detection")

# -------------------------
# SESSION STATE
# -------------------------
if "user" not in st.session_state:
    st.session_state.user = None
if "last_active" not in st.session_state:
    st.session_state.last_active = datetime.now()

# ── Session timeout check ────────────────────────────────────────────────────
if st.session_state.user:
    timeout_minutes = int(get_user_pref(st.session_state.user["username"], "session_timeout", "15"))
    idle_seconds = (datetime.now() - st.session_state.last_active).total_seconds()
    if idle_seconds > timeout_minutes * 60:
        st.session_state.user = None
        st.warning("⏱️ Your session expired due to inactivity. Please log in again.")
        st.stop()
    else:
        st.session_state.last_active = datetime.now()
# ────────────────────────────────────────────────────────────────────────────

# -------------------------
# SIDEBAR AUTH
# -------------------------
st.sidebar.title("🔑 Authentication")

auth_mode = st.sidebar.radio("Choose Action", ["Login", "Register"])

# if auth_mode == "Register":
#     # ── First-time Admin Setup (one-time only) ──────────────────────────────
#     if not admin_exists():
#         st.sidebar.subheader("🛡️ Admin Account Setup")
#         st.sidebar.info(
#             "No admin account exists yet. "
#             "Set up the single administrator account first."
#         )
#         reg_username = st.sidebar.text_input("Admin Username", key="reg_user")
#         reg_password = st.sidebar.text_input("Admin Password", type="password", key="reg_pass")
#         reg_key      = st.sidebar.text_input("Personal Encryption Key", type="password", key="reg_key")
#         reg_pin      = st.sidebar.text_input(
#             "4-digit PIN (decryption & duress detection)", type="password", key="reg_pin"
#         )

#         if st.sidebar.button("Create Admin Account"):
#             error = False
#             if not (reg_username and reg_password and reg_key and reg_pin):
#                 st.sidebar.warning("Please fill in all fields.")
#                 error = True
#             if not error and (not reg_pin.isdigit() or len(reg_pin) != 4):
#                 st.sidebar.error("PIN must be exactly 4 digits.")
#                 error = True
#             if not error and not is_strong_password(reg_password):
#                 st.sidebar.error(
#                     "Password too weak! Needs 8+ chars, uppercase, lowercase, digit & symbol."
#                 )
#                 error = True
#             if not error:
#                 private_key, public_key = generate_keys()
#                 success = register_user(
#                     reg_username, reg_password, reg_key,
#                     role="admin", pin=str(reg_pin),
#                     public_key=public_key, private_key=private_key
#                 )
#                 if success:
#                     st.sidebar.success("✅ Admin account created! You can now log in.")
#                     log_action(reg_username, "Admin account created (first-time setup)", "INFO")
#                 else:
#                     st.sidebar.error("Username already exists.")

#     # ── Regular Client Registration (admin already exists) ─────────────────
#     else:
#         st.sidebar.subheader("Register New User")
#         reg_username = st.sidebar.text_input("Username", key="reg_user")
#         reg_password = st.sidebar.text_input("Password", type="password", key="reg_pass")
#         reg_key      = st.sidebar.text_input("Personal Encryption Key", type="password", key="reg_key")
#         reg_pin      = st.sidebar.text_input(
#             "4-digit PIN (decryption & duress detection)", type="password", key="reg_pin"
#         )
#         # Role is always "client" — admin role is locked after setup
#         reg_role = "client"

#         if st.sidebar.button("Register"):
#             error = False
#             if not (reg_username and reg_password and reg_key and reg_pin):
#                 st.sidebar.warning("Fill all fields.")
#                 error = True
#             if not error and (not reg_pin.isdigit() or len(reg_pin) != 4):
#                 st.sidebar.error("PIN must be exactly 4 digits.")
#                 error = True
#             if not error and not is_strong_password(reg_password):
#                 st.sidebar.error(
#                     "Password too weak! Must be 8+ chars, include uppercase, lowercase, number & symbol."
#                 )
#                 error = True
#             if not error:
#                 private_key, public_key = generate_keys()
#                 success = register_user(
#                     reg_username, reg_password, reg_key,
#                     role=reg_role, pin=str(reg_pin),
#                     public_key=public_key, private_key=private_key
#                 )
#                 if success:
#                     st.sidebar.success("User registered successfully as **Client**!")
#                     log_action(reg_username, "Registered account with role: client", "INFO")
#                 else:
#                     st.sidebar.error("Username already exists.")

if auth_mode == "Register":
    st.sidebar.subheader("Register New User")
    st.sidebar.caption("🔒 All new accounts are registered as **Client** only.")

    reg_username  = st.sidebar.text_input("Username", key="reg_user")
    reg_password  = st.sidebar.text_input("Password", type="password", key="reg_pass")
    reg_key       = st.sidebar.text_input("Personal Encryption Key", type="password", key="reg_key")
    reg_pin       = st.sidebar.text_input("Set 4-digit PIN", type="password", key="reg_pin")

    if st.sidebar.button("Register"):
        if reg_username and reg_password and reg_key and reg_pin:

            # ── Block any attempt to use the admin's username ──
            admin_uname = get_admin_username()
            if admin_uname and reg_username.lower() == admin_uname.lower():
                st.sidebar.error("❌ That username is reserved. Please choose a different username.")

            elif not reg_pin.isdigit() or len(reg_pin) != 4:
                st.sidebar.error("❌ PIN must be exactly 4 digits.")

            elif not is_strong_password(reg_password):
                st.sidebar.error("❌ Password too weak! Must be 8+ chars, include uppercase, lowercase, number & symbol.")

            else:
                private_key, public_key = generate_keys()
                success = register_user(
                    reg_username,
                    reg_password,
                    reg_key,
                    role="client",       # Always client — admin is set via create_admin.py
                    pin=str(reg_pin),
                    public_key=public_key,
                    private_key=private_key
                )
                if success:
                    st.sidebar.success("✅ Client account registered successfully!")
                    log_action(reg_username, "Registered new client account", "INFO")
                else:
                    st.sidebar.error("❌ Username already exists. Please choose another.")
        else:
            st.sidebar.warning("⚠️ Please fill in all fields.")

if auth_mode == "Login":
    st.sidebar.subheader("Login")
    username = st.sidebar.text_input("Username", key="login_user")
    password = st.sidebar.text_input("Password", type="password", key="login_pass")

    if st.sidebar.button("Login"):
        # Check lockout first
        is_locked, mins_remaining = check_lockout(username)
        if is_locked:
            st.sidebar.error(f"🔒 Account locked due to too many failed attempts. Try again in {mins_remaining} minute(s).")
            log_action(username, f"Login attempt while locked out", "WARNING")
        else:
            user = login_user(username, password)
            if user:
                st.session_state.user = user
                reset_failed_logins(username)
                # Log device/IP info
                try:
                    import socket
                    ip = socket.gethostbyname(socket.gethostname())
                except Exception:
                    ip = "unknown"
                ua = f"Python/Streamlit on {platform.system()} {platform.release()}"
                log_login_device(username, ip, ua)
                log_action(username, f"Logged in from {ip}", "INFO")
                st.sidebar.success(f"Welcome, {username}")
            else:
                locked_now = record_failed_login(username)
                if locked_now:
                    st.sidebar.error("🔒 Too many failed attempts. Account locked for 30 minutes.")
                    log_action(username, "Account locked after 5 failed login attempts", "ALERT")
                else:
                    log_action(username, "Failed login attempt", "WARNING")
                    st.sidebar.error("Invalid credentials")

if st.session_state.user:
    if st.sidebar.button("Logout"):
        st.session_state.user = None
        st.success("Logged out successfully!")
        st.experimental_rerun()



# -------------------------
# MAIN APP
# -------------------------
if st.session_state.user:
    current_user = st.session_state.user["username"]
    personal_key = st.session_state.user["personal_key"]
    current_role = st.session_state.user["role"]
    user_is_admin = is_admin(current_role)

    # ── Frozen account gate ──────────────────────────────────────────────────
    acct_status = get_user_status(current_user)
    if acct_status["status"] == "frozen" and not user_is_admin:
        st.error("🔒 Your account has been **frozen** by an administrator.")
        st.warning(f"**Reason:** {acct_status['freeze_reason'] or 'Security alert triggered.'}")

        if acct_status["unfreeze_requested"]:
            st.info("✅ Your unfreeze request has been sent. Please wait for admin approval.")
        else:
            st.markdown("---")
            st.markdown("### 📩 Request Account Unfreeze")
            st.write("If you believe this is a mistake, send an unfreeze request to the administrator.")
            if st.button("📤 Send Unfreeze Request to Admin"):
                request_unfreeze(current_user)
                log_action(current_user, "Requested account unfreeze", "INFO")
                st.success("✅ Unfreeze request sent! An admin will review your account.")
                st.rerun()
        st.stop()
    # ────────────────────────────────────────────────────────────────────────

    role_badge = "🛡️ Admin" if user_is_admin else "👤 Client"
    st.success(f"Logged in as: **{current_user}** ({role_badge})")

    # ── Dark mode CSS injection ──────────────────────────────────────────────
    dark_mode = get_user_pref(current_user, "dark_mode", "off") == "on"
    if dark_mode:
        st.markdown("""
        <style>
        .stApp { background-color: #1e1e2e; color: #cdd6f4; }
        .stSidebar { background-color: #181825; }
        .stTextInput>div>div>input { background-color: #313244; color: #cdd6f4; }
        .stTextArea textarea { background-color: #313244; color: #cdd6f4; }
        .stSelectbox>div>div { background-color: #313244; color: #cdd6f4; }
        .stDataFrame { background-color: #313244; }
        div[data-testid="metric-container"] { background-color: #313244; border-radius:8px; padding:8px; }
        .stAlert { background-color: #313244; }
        h1,h2,h3,h4,h5,h6,p,label { color: #cdd6f4 !important; }
        </style>""", unsafe_allow_html=True)

    # ── Broadcast alert banner ───────────────────────────────────────────────
    broadcasts = get_broadcasts()
    if broadcasts:
        latest = broadcasts[0]
        st.warning(f"📢 **Admin Broadcast** ({latest[2]}): {latest[1]}")
    # ────────────────────────────────────────────────────────────────────────

    # -------------------------
    # SIDEBAR NAVIGATION
    # -------------------------
    st.sidebar.markdown("---")
    st.sidebar.title("📂 Navigation")

    # Admin sees all pages; clients see everything except full Logs page
    if user_is_admin:
        nav_pages = ["Dashboard", "Send Message", "Inbox", "Search Messages", "File Integrity", "Logs", "Security Center", "Network Traffic Analysis", "Admin Panel", "Profile"]
    else:
        nav_pages = ["Dashboard", "Send Message", "Inbox", "Search Messages", "File Integrity", "Profile"]

    page = st.sidebar.radio("Go to", nav_pages)


            
    # -------------------------
    # DASHBOARD PAGE
    # -------------------------
    if page == "Dashboard":
        st.subheader("📊 System Dashboard")

        conn = get_connection()
        cursor = conn.cursor()

        # Messages sent by current user
        cursor.execute("SELECT COUNT(*) FROM messages WHERE sender = ?", (current_user,))
        sent_count = cursor.fetchone()[0]

        # Messages received by current user
        cursor.execute("SELECT COUNT(*) FROM messages WHERE receiver = ?", (current_user,))
        inbox_count = cursor.fetchone()[0]

        # Read messages
        cursor.execute("SELECT COUNT(*) FROM messages WHERE receiver = ? AND status='read'", (current_user,))
        read_count = cursor.fetchone()[0]

        # Tamper alerts related to current user
        cursor.execute("""
            SELECT COUNT(*) FROM logs 
            WHERE (username = ? OR action LIKE ?) AND action LIKE '%Tampering detected%'
        """, (current_user, f"%{current_user}%"))
        tamper_alerts = cursor.fetchone()[0]

        # Failed login attempts by current user
        cursor.execute("""
            SELECT COUNT(*) FROM logs 
            WHERE username = ? AND action LIKE '%Failed login attempt%'
        """, (current_user,))
        failed_logins = cursor.fetchone()[0]

        # Failed decryptions by current user
        cursor.execute("""
            SELECT COUNT(*) FROM logs 
            WHERE username = ? AND action LIKE '%Failed decryption%'
        """, (current_user,))
        failed_decryptions = cursor.fetchone()[0]

        conn.close()


        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📨 Your Sent Messages", sent_count)
        c2.metric("📥 Messages Received", inbox_count)
        c3.metric("🚨 Tamper Alerts", tamper_alerts)
        c4.metric("❌ Failed Decryptions", failed_decryptions)

        st.markdown("---")
        st.subheader("📌 Quick Overview")

        colA, colB = st.columns(2)

        with colA:
            st.info("Use **Send Message** to securely send doubly encrypted messages.")
            st.info("Use **Inbox** to verify integrity and decrypt incoming messages.")

        with colB:
            st.warning("Use **Security Center** to monitor suspicious activity and breach indicators.")
            st.success("Use **Logs** to review your system actions.")


            
    # -------------------------
    # SEND MESSAGE PAGE
    # -------------------------
    # elif page == "Send Message":
    #     st.subheader("📤 Send Encrypted Message")

    #     conn = get_connection()
    #     cursor = conn.cursor()
    #     cursor.execute("SELECT username FROM users WHERE username != ?", (current_user,))
    #     users = [row[0] for row in cursor.fetchall()]
    #     conn.close()

    #     if users:
    #         receiver = st.selectbox("Select Receiver", users)
    #         message = st.text_area("Enter Message")

    #         conn = get_connection()
    #         cursor = conn.cursor()
    #         cursor.execute("""
    #             SELECT sender, receiver, encrypted_for, encrypted_message, hash_value, plaintext_hash, timestamp, status
    #             FROM messages
    #             WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
    #             ORDER BY timestamp ASC
    #         """, (current_user, receiver, receiver, current_user))
    #         conversation = cursor.fetchall()
    #         conn.close()
            
    #         if st.button("🔒 Encrypt & Send"):
    #             if receiver and message:
    #                 conn = get_connection()
    #                 cursor = conn.cursor()

    #                 # Get receiver's personal key
    #                 cursor.execute("SELECT personal_key FROM users WHERE username = ?", (receiver,))
    #                 receiver_data = cursor.fetchone()

    #                 if receiver_data:
    #                     receiver_personal_key = receiver_data[0]

    #                     # 1️⃣ Create hash from original plaintext message
    #                     plaintext_hash = hash_message(message)

    #                     # 2️⃣ Encrypt using RECEIVER's personal key
    #                     first_layer, second_layer = double_encrypt(message, receiver_personal_key)

    #                     # 3️⃣ Create hash from final encrypted message
    #                     encrypted_hash = hash_message(second_layer)

    #                     # 4️⃣ Store both hashes
    #                     cursor.execute("""
    #                         INSERT INTO messages (
    #                             sender, receiver, encrypted_for, encrypted_message,
    #                             hash_value, plaintext_hash, timestamp, status,
    #                             delivered_at, read_at,
    #                             attachment_name, attachment_data, attachment_hash
    #                         )
    #                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    #                     """, (
    #                         current_user,
    #                         receiver,
    #                         receiver,
    #                         second_layer,
    #                         encrypted_hash,     # encrypted message hash
    #                         plaintext_hash,     # original plaintext hash
    #                         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    #                         "sent",
    #                         None,
    #                         None,
    #                         None,
    #                         None,
    #                         None
    #                     ))

    #                     conn.commit()
    #                     conn.close()

    #                     log_action(current_user, f"Sent encrypted message to {receiver}", "INFO")

    #                     st.success("Message encrypted twice and sent successfully!")

    #                     with st.expander("🔍 Encryption Details"):
    #                         st.write("**First Layer (Encrypted using Receiver's Personal Key):**")
    #                         st.code(first_layer)

    #                         st.write("**Second Layer (Server Protection Key):**")
    #                         st.code(second_layer)

    #                         st.write("**Encrypted Message Hash (Server Integrity):**")
    #                         st.code(encrypted_hash)

    #                         st.write("**Plaintext Message Hash (Sender Integrity):**")
    #                         st.code(plaintext_hash)

    #                 else:
    #                     conn.close()
    #                     st.error("Receiver not found.")
    #             else:
    #                 st.warning("Please enter a message.")
            
    #         st.markdown("### 🔐 Advanced Secure Message (Signature + RSA)")

    #         if st.button("Send HIGH-SECURITY Message"):

    #             conn = get_connection()
    #             cursor = conn.cursor()

    #             # Get sender private key
    #             cursor.execute("SELECT private_key FROM users WHERE username = ?", (current_user,))
    #             user_private_key = cursor.fetchone()[0]

    #             # Get receiver public key
    #             cursor.execute("SELECT public_key FROM users WHERE username = ?", (receiver,))
    #             receiver_public_key = cursor.fetchone()[0]

    #             conn.close()

    #             send_secure_message(
    #                 sender=current_user,
    #                 receiver=receiver,
    #                 message=message,
    #                 sender_private_key=load_private_key(user_private_key),
    #                 receiver_public_key=load_public_key(receiver_public_key)
    #             )

    #             st.success("🔐 High-security message sent (Signed + Encrypted)")
    #         st.subheader("📌 Conversation History ")
    #         for msg in conversation:
    #             sender, receiver, encrypted_for, encrypted_message, hash_value, plaintext_hash, timestamp, status = msg

    #             if sender == current_user:
    #                     st.markdown(
    #                         f"""
    #                         <div style='text-align: right; background-color: #DCF8C6; padding: 10px; border-radius: 10px; margin:5px'>
    #                             {encrypted_message}<br>
    #                             <small>{timestamp} | {status}</small>
    #                         </div>
    #                         """,
    #                         unsafe_allow_html=True
    #                     )
    #             else:
    #                     st.markdown(
    #                         f"""
    #                         <div style='text-align: left; background-color: #FFFFFF; padding: 10px; border-radius: 10px; margin:5px'>
    #                             {encrypted_message}<br>
    #                             <small>{timestamp} | {status}</small>
    #                         </div>
    #                         """,
    #                         unsafe_allow_html=True
    #                     )
    #     else:
    #         st.warning("No other users available. Please register another client first.")

    elif page == "Send Message":
        st.subheader("💬 Secure Chat")

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username != ?", (current_user,))
        users = [row[0] for row in cursor.fetchall()]
        conn.close()

        if users:
            receiver = st.selectbox("👤 Select Receiver", users)

            # -------------------------
            # CHAT HISTORY
            # -------------------------
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, sender, encrypted_message, decrypted_message, timestamp, status, read_at
                FROM messages
                WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
                ORDER BY timestamp ASC
            """, (current_user, receiver, receiver, current_user))
            conversation = cursor.fetchall()
            conn.close()

            st.markdown("### 💬 Conversation")

            chat_container = st.container()

            with chat_container:
                for msg in conversation:
                    msg_id, sender, encrypted_message, decrypted_message, timestamp, status, read_at = msg

                    display_message = decrypted_message if decrypted_message else encrypted_message

                    # Read receipt label
                    receipt = ""
                    if sender == current_user:
                        if read_at:
                            receipt = f" ✅✅ Read at {read_at}"
                        elif status == "delivered":
                            receipt = " ✅ Delivered"
                        else:
                            receipt = " 🕐 Sent"

                    # Reactions
                    rxns = get_reactions(msg_id)
                    rxn_str = " ".join([f"{r[0]}" for r in rxns]) if rxns else ""

                    if sender == current_user:
                        st.markdown(f"""
                            <div style='text-align:right; background:#DCF8C6; padding:10px; border-radius:10px; margin:5px'>
                                {display_message}<br>
                                <small>{timestamp}{receipt}</small>
                                {"<br><span style='font-size:18px'>" + rxn_str + "</span>" if rxn_str else ""}
                            </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                            <div style='text-align:left; background:#F1F0F0; padding:10px; border-radius:10px; margin:5px'>
                                {display_message}<br>
                                <small>{timestamp}</small>
                                {"<br><span style='font-size:18px'>" + rxn_str + "</span>" if rxn_str else ""}
                            </div>
                        """, unsafe_allow_html=True)
                        # Let receiver react
                        react_cols = st.columns(6)
                        for i, emoji in enumerate(["👍","❤️","😂","😮","😢","👎"]):
                            if react_cols[i].button(emoji, key=f"react_{msg_id}_{emoji}"):
                                add_reaction(msg_id, current_user, emoji)
                                log_action(current_user, f"Reacted {emoji} to message {msg_id}", "INFO")
                                st.rerun()

            st.markdown("---")

            # -------------------------
            # INPUT AREA (LIKE WHATSAPP)
            # -------------------------
            col1, col2 = st.columns([5,1])

            with col1:
                message = st.text_input("✍️ Type your message", key="chat_msg")

            # with col2:
            #     uploaded_file = st.file_uploader("📎", label_visibility="collapsed")

            if st.button("🚀 Send"):

                # if not message and uploaded_file is None:
                #     st.warning("Please enter a message or attach a file")
                # else:
                    conn = get_connection()
                    cursor = conn.cursor()

                    # Get receiver key
                    cursor.execute("SELECT personal_key FROM users WHERE username = ?", (receiver,))
                    receiver_key = cursor.fetchone()[0]

                    # -------------------------
                    # MESSAGE HANDLING
                    # -------------------------
                    if message:
                        plaintext_hash = hash_message(message)
                        first_layer, second_layer = double_encrypt(message, receiver_key)
                        encrypted_hash = hash_message(second_layer)
                    else:
                        second_layer = None
                        encrypted_hash = None
                        plaintext_hash = None

                    # -------------------------
                    # FILE HANDLING
                    # -------------------------
                    file_name = None
                    file_data = None
                    file_hash = None

                    # if uploaded_file is not None:
                    #     file_name = uploaded_file.name
                    #     file_data = uploaded_file.read()
                    #     file_hash = hash_message(file_data.hex())

                    # -------------------------
                    # SAVE TO DATABASE
                    # -------------------------
                    cursor.execute("""
                        INSERT INTO messages (
                            sender, receiver, encrypted_for, encrypted_message,
                            hash_value, plaintext_hash, timestamp, status,
                            attachment_name, attachment_data, attachment_hash
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        current_user,
                        receiver,
                        receiver,
                        second_layer,
                        encrypted_hash,
                        plaintext_hash,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "sent",
                        file_name,
                        file_data,
                        file_hash
                    ))

                    conn.commit()
                    conn.close()

                    log_action(current_user, f"Sent message/file to {receiver}", "INFO")

                    st.success("✅ Sent successfully!")
                    st.rerun()

        else:
            st.warning("No users available.")
        

    # -------------------------
    # INBOX PAGE
    # -------------------------
    elif page == "Inbox":
        st.subheader("📥 Inbox Messages")

        conn = get_connection()
        cursor = conn.cursor()

        # 1️⃣ Mark all unread messages as 'delivered'
        cursor.execute("""
            UPDATE messages 
            SET status='delivered', delivered_at=?
            WHERE receiver=? AND status='sent'
        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user))
        conn.commit()

        # 2️⃣ Fetch all messages after update
        cursor.execute("""
            SELECT id, sender, encrypted_for,  encrypted_message, hash_value, plaintext_hash, timestamp, status, delivered_at, read_at, decrypted_message
            FROM messages
            WHERE receiver = ?
            ORDER BY id DESC
        """, (current_user,))
        messages = cursor.fetchall()
        conn.close()

        if messages:
            for msg in messages:
                msg_id, sender, encrypted_for, encrypted_message,  stored_hash, stored_plaintext_hash, timestamp, status, delivered_at, read_at, decrypted_message   = msg 

                with st.container():
                    st.markdown(f"### ✉️ Message from **{sender}**")
                    st.write(f"**Encrypted For:** {encrypted_for}")
                    st.write(f"**Timestamp:** {timestamp}")
                    st.write(f"**Status:** `{status}`")
                    display_msg = decrypted_message if decrypted_message else encrypted_message
                    st.code(display_msg)

                    # Step 1: Show PIN input first
                    pin_input = st.text_input(
                        f"Enter your 4-digit PIN to decrypt Message {msg_id}",
                        type="password",
                        key=f"pin_{msg_id}"
                    )

                    # Step 2: Decrypt button
                    if st.button(f"🔓 Verify & Decrypt Message {msg_id}", key=f"decrypt_{msg_id}"):

                        pin_result = check_pin(pin_input, st.session_state.user,
                                               f"decrypt message {msg_id}", current_user)

                        if pin_result == "wrong":
                            st.error("❌ Incorrect PIN! Access denied.")
                            log_action(current_user, f"Incorrect PIN attempt for message {msg_id}", "WARNING")
                        else:
                            # Both 'ok' and 'duress' proceed normally (duress already silently logged)
                            if pin_result == "duress":
                                st.warning("⚠️ Proceeding under duress — alert has been raised silently.")

                            # 1️⃣ Verify encrypted message integrity
                            encrypted_integrity_ok = verify_integrity(encrypted_message, stored_hash)

                            if encrypted_integrity_ok:
                                try:
                                    # 2️⃣ Decrypt message
                                    first_decrypt, original_message = double_decrypt(encrypted_message, personal_key)

                                    # 3️⃣ Generate hash from recovered plaintext
                                    receiver_plaintext_hash = hash_message(original_message)

                                    # 4️⃣ Compare sender hash vs receiver hash
                                    if receiver_plaintext_hash == stored_plaintext_hash:
                                        st.success("✅ No threat detected. Sender and Receiver hash matched.")
                                        st.success("✅ Integrity verified. Message decrypted successfully!")

                                        st.write("**After Server Layer Decryption:**")
                                        st.code(first_decrypt)

                                        st.write("**Original Message:**")
                                        st.text_area(
                                            "Recovered Message",
                                            value=original_message,
                                            height=120,
                                            key=f"msg_{msg_id}"
                                        )

                                        conn = get_connection()
                                        cursor = conn.cursor()

                                        cursor.execute("""
                                            UPDATE messages
                                            SET decrypted_message = ?
                                            WHERE id = ?
                                        """, (original_message, msg_id))

                                        conn.commit()
                                        conn.close()

                                        st.rerun()

                                        st.write("**Sender Plaintext Hash:**")
                                        st.code(stored_plaintext_hash)

                                        st.write("**Receiver Plaintext Hash:**")
                                        st.code(receiver_plaintext_hash)

                                        log_action(current_user, f"Decrypted and verified message {msg_id} from {sender}", "INFO")

                                        # Update status to read
                                        conn = get_connection()
                                        cursor = conn.cursor()
                                        cursor.execute("""
                                            UPDATE messages 
                                            SET status='read', read_at=? 
                                            WHERE id=?
                                        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg_id))
                                        conn.commit()
                                        conn.close()

                                    else:
                                        st.error("🚨 THREAT DETECTED: Sender and Receiver plaintext hashes do not match!")
                                        st.write("**Sender Plaintext Hash:**")
                                        st.code(stored_plaintext_hash)

                                        st.write("**Receiver Plaintext Hash:**")
                                        st.code(receiver_plaintext_hash)

                                        log_action(current_user, f"Plaintext hash mismatch detected on message {msg_id}", "ALERT")

                                except Exception as e:
                                    st.error(f"❌ Decryption failed. Possible wrong key or corruption.\n\nError: {str(e)}")
                                    log_action(current_user, f"Failed decryption attempt on message {msg_id}", "WARNING")

                            else:
                                st.error("⚠️ BREACH DETECTED: Encrypted message integrity verification failed!")
                                log_action(current_user, f"Tampering detected on encrypted message {msg_id}", "ALERT")

                    st.markdown("---")
                
                st.markdown("## 🔐 High-Security Messages (Digital Signature)")

                conn = get_connection()
                cursor = conn.cursor()

                cursor.execute("SELECT private_key FROM users WHERE username = ?", (current_user,))
                user_private_key = cursor.fetchone()[0]
                conn.close()

                secure_msgs = receive_secure_messages(
                    current_user,
                    load_private_key(user_private_key),
                    get_public_key_func
                )

                if secure_msgs:
                    for msg in secure_msgs:
                        st.markdown(f"### 📩 From: {msg['sender']}")
                        st.write(f"Time: {msg['timestamp']}")
                        st.write(f"Message: {msg['message']}")

                        if msg["signature_valid"]:
                            st.success("✅ Signature Verified (Authentic Sender)")
                        else:
                            st.error("❌ Signature Invalid (Possible Attack)")

                        if msg["integrity_ok"]:
                            st.success("✅ Message Integrity OK")
                        else:
                            st.error("🚨 Message Tampered")

                        st.markdown("---")
                else:
                    st.info("No high-security messages.")
                    
        else:
            st.info("No messages yet.")
    # -------------------------
    # LOGS PAGE  (Admin: all logs | Client: own logs only)
    # -------------------------
    elif page == "Logs":
        if user_is_admin:
            st.subheader("📜 All System Logs (Admin View)")
            logs = get_logs()
            if logs:
                df_logs = pd.DataFrame(logs, columns=["User", "Action", "Severity", "Timestamp"])
                severity_filter = st.selectbox("Filter by Severity", ["All", "INFO", "WARNING", "ALERT", "CRITICAL"])
                if severity_filter != "All":
                    df_logs = df_logs[df_logs["Severity"] == severity_filter]
 
                def highlight_severity(row):
                    color_map = {
                        "INFO": "color: #2196F3",
                        "WARNING": "color: #FF9800",
                        "ALERT": "color: #f44336",
                        "CRITICAL": "color: #9C27B0; font-weight:bold"
                    }
                    sev = row.get("Severity", "")
                    style = color_map.get(sev, "")
                    return ["" if col != "Severity" else style for col in row.index]
 
                st.dataframe(
                    df_logs.style.apply(highlight_severity, axis=1),
                    use_container_width=True
                )
            else:
                st.info("No logs available.")
        else:
            # Clients only see their own non-duress logs
            st.subheader("📜 My Activity Logs")
            logs = get_user_logs(current_user)
            # Strip duress entries – those are admin-only
            logs = [l for l in logs if "[DURESS ALERT]" not in l[1]]
            if logs:
                for log in logs:
                    st.write(f"**Action:** {log[1]} | **Severity:** {log[2]} | **Time:** {log[3]}")
            else:
                st.info("No activity yet.")

    # -------------------------
    # SECURITY CENTER PAGE
    # -------------------------
    elif page == "Security Center":
        st.subheader("⚠️ Security Center")

        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT private_key FROM users WHERE username = ?", (current_user,))
        user_private_key = cursor.fetchone()[0]

        # Messages sent by current user
        cursor.execute("SELECT COUNT(*) FROM messages WHERE sender = ?", (current_user,))
        sent_count = cursor.fetchone()[0]

        # Delivered messages
        cursor.execute("SELECT COUNT(*) FROM messages WHERE receiver = ? AND status='delivered'", (current_user,))
        delivered_count = cursor.fetchone()[0]

        # Read messages
        cursor.execute("SELECT COUNT(*) FROM messages WHERE receiver = ? AND status='read'", (current_user,))
        read_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Tampering detected%'")
        tamper_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Failed login attempt%'")
        failed_logins = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Incorrect PIN%'")
        wrong_pin_attempts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Failed decryption%'")
        failed_decryptions = cursor.fetchone()[0]


        conn.close()

        # Load secure messages
        secure_msgs = receive_secure_messages(
            current_user,
            load_private_key(user_private_key),
            get_public_key_func
        )

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📨 Sent", sent_count)
        c2.metric("📥 Delivered", delivered_count)
        c3.metric("✅ Read", read_count)
        c4.metric("🚨 Tamper Alerts", tamper_alerts)

        st.markdown("---")
        
        secure_tampered = sum(1 for m in secure_msgs if not m["integrity_ok"])
        invalid_signatures = sum(1 for m in secure_msgs if not m["signature_valid"])

        st.metric("🔐 Signature Failures", invalid_signatures)
        st.metric("🚨 Secure Tampering", secure_tampered)

        st.info("This dashboard helps monitor suspicious activities and breach attempts.")

        st.markdown("## 📊 Message Status Overview")

        status_data = pd.DataFrame({
            "Status": ["Sent", "Delivered", "Read"],
            "Count": [sent_count, delivered_count, read_count]
        })

        fig_status = px.bar(
            status_data,
            x="Status",
            y="Count",
            title="Message Lifecycle Status"
        )

        st.plotly_chart(fig_status, use_container_width=True)

        st.markdown("## 🚨 Threat Detection Overview")

        threat_data = pd.DataFrame({
            "Threat Type": ["Failed Login", "Wrong PIN", "Failed Decryption", "Tamper Alert"],
            "Count": [failed_logins, wrong_pin_attempts, failed_decryptions, tamper_alerts]
        })

        fig_threat = px.bar(
            threat_data,
            x="Threat Type",
            y="Count",
            title="Threat Detection Events"
        )

        st.plotly_chart(fig_threat, use_container_width=True)

    elif page == "Profile":
        st.subheader(f"👤 {current_user} Profile")

        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs WHERE username=? AND action LIKE '%Failed login attempt%'", (current_user,))
        failed_logins = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM logs WHERE username=? AND action LIKE '%Failed decryption%'", (current_user,))
        failed_decryptions = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM logs WHERE (username=? OR action LIKE ?) AND action LIKE '%Tampering detected%'", (current_user, f"%{current_user}%"))
        tamper_events = cursor.fetchone()[0]
        conn.close()

        st.info(f"**Role:** {current_role}")
        st.write(f"**Personal Key:** {personal_key}")

        suspicious_score = failed_logins*2 + failed_decryptions*3 + tamper_events*5
        st.subheader("⚠️ Suspicious Activity Score")
        st.metric("Suspicious Activity Score", suspicious_score)

        st.markdown("---")

        # ── Settings ────────────────────────────────────────────────────────
        st.subheader("⚙️ Account Settings")

        col_dm, col_tm = st.columns(2)

        with col_dm:
            st.markdown("#### 🌙 Dark Mode")
            current_dark = get_user_pref(current_user, "dark_mode", "off")
            dark_toggle = st.toggle("Enable Dark Mode", value=(current_dark == "on"), key="dark_toggle")
            if st.button("Save Dark Mode", key="save_dark"):
                set_user_pref(current_user, "dark_mode", "on" if dark_toggle else "off")
                st.success("✅ Dark mode preference saved! Reload the page to see changes.")

        with col_tm:
            st.markdown("#### ⏱️ Session Timeout")
            current_timeout = int(get_user_pref(current_user, "session_timeout", "15"))
            timeout_val = st.selectbox(
                "Auto-logout after inactivity",
                [5, 10, 15, 30, 60],
                index=[5, 10, 15, 30, 60].index(current_timeout) if current_timeout in [5, 10, 15, 30, 60] else 2,
                format_func=lambda x: f"{x} minutes",
                key="timeout_select"
            )
            if st.button("Save Timeout", key="save_timeout"):
                set_user_pref(current_user, "session_timeout", str(timeout_val))
                st.success(f"✅ Session timeout set to {timeout_val} minutes.")

        st.markdown("---")

        # ── Activity heatmap ─────────────────────────────────────────────────
        st.subheader("📅 Activity Heatmap")
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp FROM logs WHERE username=? ORDER BY timestamp DESC LIMIT 500",
            (current_user,)
        )
        ts_rows = cursor.fetchall()
        conn.close()

        if ts_rows:
            import plotly.graph_objects as go
            ts_df = pd.DataFrame(ts_rows, columns=["timestamp"])
            ts_df["timestamp"] = pd.to_datetime(ts_df["timestamp"])
            ts_df["date"] = ts_df["timestamp"].dt.date
            ts_df["hour"] = ts_df["timestamp"].dt.hour
            heat = ts_df.groupby(["date", "hour"]).size().reset_index(name="count")
            heat_pivot = heat.pivot(index="hour", columns="date", values="count").fillna(0)
            fig_heat = px.imshow(
                heat_pivot,
                labels=dict(x="Date", y="Hour of Day", color="Actions"),
                title="Your Activity by Hour & Date",
                color_continuous_scale="Blues",
                aspect="auto"
            )
            st.plotly_chart(fig_heat, use_container_width=True)
        else:
            st.info("Not enough activity data for heatmap yet.")

        st.markdown("---")
        # ── Activity logs ────────────────────────────────────────────────────
        st.markdown("### 📜 Your Activity Logs")
        logs = get_user_logs(current_user)
        logs = [l for l in logs if "[DURESS ALERT]" not in l[1]]
        if logs:
            for log in logs:
                st.write(f"**Action:** {log[1]} | **Severity:** {log[2]} | **Time:** {log[3]}")
        else:
            st.info("No activity yet.")

        st.markdown("---")

        # ── 11. Activity Timeline ─────────────────────────────────────────────
        st.subheader("📋 Activity Timeline")
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT action, severity, timestamp FROM logs WHERE username=? AND action NOT LIKE '%DURESS%' ORDER BY timestamp DESC LIMIT 100",
            (current_user,)
        )
        timeline_rows = cursor.fetchall()
        conn.close()

        if timeline_rows:
            severity_icons = {"INFO": "🔵", "WARNING": "🟡", "ALERT": "🔴", "CRITICAL": "🟣"}
            for action, sev, ts in timeline_rows:
                icon = severity_icons.get(sev, "⚪")
                st.markdown(f"{icon} **{ts}** — {action}")
        else:
            st.info("No timeline data yet.")

        st.markdown("---")

        # ── 3. Password Change ────────────────────────────────────────────────
        st.subheader("🔑 Change Password")
        with st.expander("Change my password"):
            old_pw = st.text_input("Current Password", type="password", key="old_pw")
            new_pw = st.text_input("New Password", type="password", key="new_pw")
            new_pw2 = st.text_input("Confirm New Password", type="password", key="new_pw2")
            if st.button("Update Password", key="update_pw"):
                if new_pw != new_pw2:
                    st.error("New passwords do not match.")
                else:
                    ok, msg = change_password(current_user, old_pw, new_pw)
                    if ok:
                        st.success(f"✅ {msg}")
                        log_action(current_user, "Changed account password", "INFO")
                    else:
                        st.error(f"❌ {msg}")

        st.markdown("---")

        # ── 4. Device / IP Login History ─────────────────────────────────────
        st.subheader("🖥️ Login Device History")
        devices = get_login_devices(current_user)
        if devices:
            df_dev = pd.DataFrame(devices, columns=["IP Address", "Device/Platform", "Login Time"])
            st.dataframe(df_dev, use_container_width=True)
        else:
            st.info("No device login history yet.")

    elif page == "File Integrity":
        st.subheader("🛡️ File Integrity Monitoring")

        import os
        from file_integrity import (
            calculate_file_hash,
            verify_file_integrity,
            save_file_record,
            update_file_status,
            get_sent_files,
            get_received_files
        )
        from crypto_utils import encrypt_file_bytes, decrypt_file_bytes
        from database import get_all_other_users
        from datetime import datetime

        upload_dir = "uploaded_files"
        os.makedirs(upload_dir, exist_ok=True)

        receiver = st.selectbox("Select Receiver", get_all_other_users(current_user))
        uploaded_file = st.file_uploader("Upload a file to send")

        if uploaded_file is not None:
            send_pin_input = st.text_input(
                "Enter your PIN to confirm file send",
                type="password",
                key="send_file_pin"
            )

            if st.button("Send File"):
                # Verify sender identity with their own PIN first
                pin_result = check_pin(send_pin_input, st.session_state.user,
                                       f"send file {uploaded_file.name}", current_user)
                if pin_result == "wrong":
                    st.error("❌ Incorrect PIN! File not sent.")
                    log_action(current_user, f"Wrong PIN on file send: {uploaded_file.name}", "WARNING")
                else:
                    if pin_result == "duress":
                        st.warning("Proceeding under duress — silent alert raised.")

                    # Fetch the RECEIVER's PIN from the database
                    conn = get_connection()
                    cursor = conn.cursor()
                    cursor.execute("SELECT pin FROM users WHERE username = ?", (receiver,))
                    receiver_row = cursor.fetchone()
                    conn.close()

                    if not receiver_row:
                        st.error("❌ Receiver not found.")
                    else:
                        receiver_pin = str(receiver_row[0])

                        unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{uploaded_file.name}"
                        file_path = os.path.join(upload_dir, unique_filename)

                        raw_bytes = uploaded_file.getbuffer().tobytes()

                        # Encrypt with RECEIVER's PIN so only they can decrypt
                        encrypted_bytes = encrypt_file_bytes(raw_bytes, receiver_pin)

                        with open(file_path, "wb") as f:
                            f.write(encrypted_bytes)

                        # Store hash of original bytes as integrity baseline
                        import hashlib
                        original_hash = hashlib.sha256(raw_bytes).hexdigest()
                        save_file_record(current_user, receiver, uploaded_file.name, file_path, original_hash)

                        log_action(current_user, f"Sent encrypted file to {receiver}: {uploaded_file.name}", "INFO")
                        st.success(f"✅ File '{uploaded_file.name}' encrypted with **{receiver}'s PIN** and sent!")

                        with st.expander("🔍 Original File Hash (pre-encryption)"):
                            st.code(original_hash)

        st.subheader("📤 Sent Files")
        sent_files = get_sent_files(current_user)

        if sent_files:
                for file in sent_files:
                    file_id, receiver, file_name, file_path, original_hash, last_checked_hash, status, upload_time, last_checked_time = file

                    with st.container():
                        st.write(f"### 📄 {file_name}")
                        st.write(f"**To:** {receiver}")
                        st.write(f"**Sent Time:** {upload_time}")
                        st.write(f"**Status:** {'✅ Safe' if status == 'safe' else '⚠️ Tampered'}")
                        st.markdown("---")
        else:
                st.info("No sent files yet.")
                
        st.subheader("📥 Inbox - Received Files")
        received_files = get_received_files(current_user)

        if received_files:
            for file in received_files:
                file_id, sender, file_name, file_path, original_hash, last_checked_hash, status, upload_time, last_checked_time = file

                with st.container():
                    st.write(f"### 📄 {file_name}")
                    st.write(f"**From:** {sender}")
                    st.write(f"**Received Time:** {upload_time}")
                    st.write(f"**Status:** {'✅ Safe' if status == 'safe' else '⚠️ Tampered'}")

                    # ── PIN gate: receiver enters their OWN PIN to decrypt ──
                    st.info("ℹ️ This file was encrypted with **your PIN**. Enter your PIN to decrypt and download it.")
                    file_pin_input = st.text_input(
                        "🔐 Enter your PIN to decrypt & download",
                        type="password",
                        key=f"fpin_{file_id}"
                    )

                    if st.button(f"🔓 Verify, Decrypt & Download — {file_name}", key=f"fverify_{file_id}"):
                        # Validate receiver's own PIN (also catches duress)
                        pin_result = check_pin(file_pin_input, st.session_state.user,
                                               f"decrypt file {file_name}", current_user)

                        if pin_result == "wrong":
                            st.error("❌ Incorrect PIN! File access denied.")
                            log_action(current_user, f"Wrong PIN attempt for file: {file_name}", "WARNING")
                        else:
                            if pin_result == "duress":
                                st.warning("⚠️ Proceeding under duress — silent alert raised.")

                            # Attempt to read and decrypt the file
                            if not os.path.exists(file_path):
                                st.error("❌ File not found on server. It may have been moved or deleted.")
                                log_action(current_user, f"File missing on server: {file_name}", "ALERT")
                            else:
                                try:
                                    with open(file_path, "rb") as enc_f:
                                        encrypted_bytes = enc_f.read()

                                    # Decrypt using receiver's own PIN
                                    decrypted_bytes = decrypt_file_bytes(encrypted_bytes, file_pin_input)

                                    # Verify integrity against original hash
                                    import hashlib
                                    decrypted_hash = hashlib.sha256(decrypted_bytes).hexdigest()

                                    if decrypted_hash == original_hash:
                                        update_file_status(file_id, decrypted_hash, "safe")
                                        st.success("✅ PIN correct! File decrypted and integrity verified.")
                                        log_action(current_user, f"Successfully decrypted & downloaded: {file_name}", "INFO")

                                        with st.expander("🔍 Hash Verification"):
                                            st.write("**Original Hash (pre-encryption):**")
                                            st.code(original_hash)
                                            st.write("**Decrypted File Hash:**")
                                            st.code(decrypted_hash)
                                            st.success("✅ Hashes match — file is untampered.")

                                        # Download button with clean decrypted bytes
                                        st.download_button(
                                            label=f"⬇️ Download {file_name}",
                                            data=decrypted_bytes,
                                            file_name=file_name,
                                            mime="application/octet-stream",
                                            key=f"dl_{file_id}"
                                        )

                                    else:
                                        update_file_status(file_id, decrypted_hash, "tampered")
                                        st.error("🚨 TAMPER DETECTED! File hash does not match original.")
                                        log_action(current_user, f"Tampering detected in file: {file_name}", "ALERT")

                                        with st.expander("🔍 Hash Mismatch Details"):
                                            st.write("**Expected Hash:**")
                                            st.code(original_hash)
                                            st.write("**Actual Decrypted Hash:**")
                                            st.code(decrypted_hash)

                                except Exception:
                                    st.error("❌ Decryption failed — incorrect PIN or corrupted file.")
                                    log_action(current_user, f"Failed decryption attempt for file: {file_name}", "WARNING")

                    st.markdown("---")
        else:
            st.info("No received files yet.")

        # st.markdown("---")
        # st.subheader("📂 Monitored Files")

        # files = get_user_files(current_user)

        # if files:
        #     for file in files:
        #         file_id, file_name, file_path, original_hash, last_checked_hash, status, upload_time, last_checked_time = file

        #         with st.container():
        #             st.write(f"### 📄 {file_name}")
        #             st.write(f"**Upload Time:** {upload_time}")
        #             st.write(f"**Status:** {'✅ Safe' if status == 'safe' else '⚠️ Tampered'}")

        #             if st.button(f"Check Integrity - {file_id}"):
        #                 is_safe, current_hash = verify_file_integrity(file_path, original_hash)

        #                 new_status = "safe" if is_safe else "tampered"
        #                 update_file_status(file_id, current_hash, new_status)

        #                 if is_safe:
        #                     st.success("✅ File integrity verified. No changes detected.")
        #                     log_action(current_user, f"Verified integrity of file: {file_name}", "INFO")
        #                 else:
        #                     st.error("⚠️ BREACH DETECTED: File has been modified!")
        #                     log_action(current_user, f"Tampering detected in file: {file_name}", "ALERT")

        #                 with st.expander("Hash Comparison"):
        #                     st.write("**Original Hash:**")
        #                     st.code(original_hash)

        #                     st.write("**Current Hash:**")
        #                     st.code(current_hash)

        #             st.markdown("---")
        # else:
        #     st.info("No monitored files yet.")     


    elif page == "Network Traffic Analysis":
        st.subheader("🌐 Network Traffic Breach Analysis")
        st.caption("Upload CIC IDS2017 traffic CSV and detect suspicious network flows")

        from network_analysis import (
            load_network_data,
            clean_network_data,
            select_features,
            run_anomaly_detection,
            add_anomaly_labels,
            get_summary_stats
        )

        uploaded_csv = st.file_uploader("📂 Upload CIC IDS2017 CSV file", type=["csv"])

        if uploaded_csv is not None:
            try:
                with st.spinner("Loading and analyzing dataset..."):
                    df = load_network_data(uploaded_csv)

                    # Limit rows for performance
                    df = df.head(5000)

                    st.success("Dataset loaded successfully!")
                    st.write("### Raw Dataset Preview")
                    st.dataframe(df.head())

                    # Clean dataset
                    df = clean_network_data(df)

                    # Select important features
                    df_features, feature_names = select_features(df)

                    if len(feature_names) == 0:
                        st.error("No required traffic analysis columns were found in this dataset.")
                    else:
                        st.write("### Selected Features for Analysis")
                        st.write(feature_names)

                        # Run anomaly detection
                        preds = run_anomaly_detection(df_features)
                        df = add_anomaly_labels(df, preds)

                        # Summary stats
                        summary = get_summary_stats(df)

                        c1, c2, c3 = st.columns(3)
                        c1.metric("Total Flows", summary["Total Flows"])
                        c2.metric("Suspicious Flows", summary["Suspicious Flows"])
                        c3.metric("Normal Flows", summary["Normal Flows"])

                        st.markdown("---")
                        st.write("### 🚨 Detection Results")

                        show_cols = ["Anomaly_Label"] + feature_names
                        if "Label" in df.columns:
                            show_cols = ["Label"] + show_cols

                        st.dataframe(df[show_cols].head(100))

                        # Suspicious only
                        st.markdown("---")
                        st.write("### 🔍 Suspicious Traffic Only")
                        suspicious_df = df[df["Anomaly_Label"] == "Suspicious"]
                        st.dataframe(suspicious_df[show_cols].head(100))

                        # Charts
                        st.markdown("---")
                        st.write("### 📊 Traffic Visualizations")

                        if "Flow Duration" in df.columns:
                            st.write("#### Flow Duration")
                            st.line_chart(df["Flow Duration"].head(100))

                        if "Flow Bytes/s" in df.columns:
                            st.write("#### Flow Bytes/s")
                            st.line_chart(df["Flow Bytes/s"].head(100))

                        if "Flow Packets/s" in df.columns:
                            st.write("#### Flow Packets/s")
                            st.line_chart(df["Flow Packets/s"].head(100))

                        if "Label" in df.columns:
                            st.write("#### Traffic Label Distribution")
                            st.bar_chart(df["Label"].value_counts().head(10))

                        log_action(current_user, "Performed network traffic anomaly analysis", "INFO")
                        st.markdown("---")
                        st.write("### 📊 Traffic Visualizations")

                        if "Flow Duration" in df.columns:
                            st.write("#### Flow Duration Distribution")
                            st.bar_chart(df["Flow Duration"].head(100))

                        if "Flow Bytes/s" in df.columns:
                            st.write("#### Flow Bytes/s Distribution")
                            st.line_chart(df["Flow Bytes/s"].head(100))

                        if "Flow Packets/s" in df.columns:
                            st.write("#### Flow Packets/s Distribution")
                            st.line_chart(df["Flow Packets/s"].head(100))
                            
            except Exception as e:
                st.error(f"Error during analysis: {str(e)}")

    # -------------------------
    # ADMIN PANEL (Admin only)
    # -------------------------
    # ─────────────────────────────────────────────
    # SEARCH MESSAGES PAGE
    # ─────────────────────────────────────────────
    elif page == "Search Messages":
        st.subheader("🔍 Search Messages")
        st.caption("Search through your decrypted message history.")

        search_query = st.text_input("🔎 Enter keyword to search", placeholder="e.g. hello, meeting, report...")
        search_col, filter_col = st.columns([3,1])
        with filter_col:
            search_scope = st.selectbox("Search in", ["All", "Sent", "Received"], key="search_scope")

        if search_query:
            conn = get_connection()
            cursor = conn.cursor()

            if search_scope == "Sent":
                cursor.execute("""
                    SELECT id, sender, receiver, decrypted_message, timestamp, status
                    FROM messages
                    WHERE sender=? AND (
                        decrypted_message LIKE ? OR encrypted_message LIKE ?
                    )
                    ORDER BY timestamp DESC
                """, (current_user, f"%{search_query}%", f"%{search_query}%"))
            elif search_scope == "Received":
                cursor.execute("""
                    SELECT id, sender, receiver, decrypted_message, timestamp, status
                    FROM messages
                    WHERE receiver=? AND (
                        decrypted_message LIKE ? OR encrypted_message LIKE ?
                    )
                    ORDER BY timestamp DESC
                """, (current_user, f"%{search_query}%", f"%{search_query}%"))
            else:
                cursor.execute("""
                    SELECT id, sender, receiver, decrypted_message, timestamp, status
                    FROM messages
                    WHERE (sender=? OR receiver=?) AND (
                        decrypted_message LIKE ? OR encrypted_message LIKE ?
                    )
                    ORDER BY timestamp DESC
                """, (current_user, current_user, f"%{search_query}%", f"%{search_query}%"))

            results = cursor.fetchall()
            conn.close()

            if results:
                st.success(f"Found **{len(results)}** result(s) for `{search_query}`")
                for r in results:
                    msg_id, sender, receiver, decrypted_msg, timestamp, status = r
                    direction = "📤 Sent" if sender == current_user else "📥 Received"
                    other = receiver if sender == current_user else sender
                    display = decrypted_msg if decrypted_msg else "*(encrypted — not yet decrypted)*"

                    # Highlight the search term in the display text
                    if decrypted_msg and search_query.lower() in decrypted_msg.lower():
                        highlighted = decrypted_msg.replace(
                            search_query,
                            f"**:orange[{search_query}]**"
                        )
                    else:
                        highlighted = display

                    with st.container():
                        st.markdown(f"**{direction}** with **{other}** — {timestamp} | Status: `{status}`")
                        st.markdown(highlighted)
                        st.markdown("---")
            else:
                st.info(f"No messages found matching `{search_query}`.")
        else:
            st.info("Type a keyword above to search your messages.")

        log_action(current_user, f"Used message search: '{search_query}'", "INFO") if search_query else None

    # ─────────────────────────────────────────────
    # ADMIN PANEL
    # ─────────────────────────────────────────────
    elif page == "Admin Panel":
        if not user_is_admin:
            st.error("Access Denied. This page is for administrators only.")
        else:
            st.subheader("Admin Control Panel")

            st.markdown("### 👥 Registered Users")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, role FROM users ORDER BY role, username")
            all_users = cursor.fetchall()
            conn.close()
            if all_users:
                df_users = pd.DataFrame(all_users, columns=["Username", "Role"])
                st.dataframe(df_users, use_container_width=True)
            else:
                st.info("No users registered.")

            st.markdown("---")

            # ── 7. Broadcast Alert ───────────────────────────────────────────
            st.markdown("### 📢 Broadcast Alert to All Users")
            broadcast_msg = st.text_area(
                "Write a message to broadcast to all users",
                placeholder="e.g. System maintenance at 10pm. Please save your work.",
                key="broadcast_input"
            )
            if st.button("📤 Send Broadcast", key="send_broadcast"):
                if broadcast_msg.strip():
                    create_broadcast(current_user, broadcast_msg.strip())
                    log_action(current_user, f"Sent broadcast: {broadcast_msg[:60]}", "INFO")
                    st.success("✅ Broadcast sent! All users will see it on their next page load.")
                else:
                    st.warning("Please write a message first.")

            st.markdown("#### 📋 Recent Broadcasts")
            for b in get_broadcasts():
                st.info(f"**{b[0]}** ({b[2]}): {b[1]}")

            st.markdown("---")

            # ── 5. Audit Trail Export ────────────────────────────────────────
            st.markdown("### 📥 Audit Trail Export")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, action, severity, timestamp FROM logs ORDER BY id DESC")
            all_logs_export = cursor.fetchall()
            conn.close()

            if all_logs_export:
                df_export = pd.DataFrame(all_logs_export, columns=["User", "Action", "Severity", "Timestamp"])

                col_csv, col_pdf_note = st.columns(2)
                with col_csv:
                    csv_data = df_export.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        label="⬇️ Download Logs as CSV",
                        data=csv_data,
                        file_name=f"audit_trail_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        key="dl_audit_csv"
                    )
                with col_pdf_note:
                    # Build a simple HTML report for PDF-style printing
                    html_rows = "".join(
                        f"<tr><td>{r['User']}</td><td>{r['Action']}</td>"
                        f"<td style='color:{'red' if r['Severity'] in ['ALERT','CRITICAL'] else 'orange' if r['Severity']=='WARNING' else 'blue'}'>"
                        f"{r['Severity']}</td><td>{r['Timestamp']}</td></tr>"
                        for _, r in df_export.iterrows()
                    )
                    html_report = f"""<html><head><style>
                    body{{font-family:Arial;font-size:12px;}}
                    table{{width:100%;border-collapse:collapse;}}
                    th{{background:#333;color:white;padding:6px;}}
                    td{{border:1px solid #ccc;padding:5px;}}
                    tr:nth-child(even){{background:#f9f9f9;}}
                    </style></head><body>
                    <h2>Secure Chat System — Audit Trail</h2>
                    <p>Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Total entries: {len(df_export)}</p>
                    <table><tr><th>User</th><th>Action</th><th>Severity</th><th>Timestamp</th></tr>
                    {html_rows}</table></body></html>"""
                    st.download_button(
                        label="⬇️ Download Logs as HTML Report",
                        data=html_report.encode("utf-8"),
                        file_name=f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                        mime="text/html",
                        key="dl_audit_html"
                    )
            else:
                st.info("No logs to export yet.")

            st.markdown("---")

            # ── 6. System-wide Activity Heatmap ─────────────────────────────
            st.markdown("### 📅 System-Wide Activity Heatmap")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, timestamp FROM logs ORDER BY timestamp DESC LIMIT 2000")
            heat_rows = cursor.fetchall()
            conn.close()

            if heat_rows:
                heat_df = pd.DataFrame(heat_rows, columns=["username", "timestamp"])
                heat_df["timestamp"] = pd.to_datetime(heat_df["timestamp"])
                heat_df["date"] = heat_df["timestamp"].dt.date
                heat_df["hour"] = heat_df["timestamp"].dt.hour
                heat_agg = heat_df.groupby(["hour", "date"]).size().reset_index(name="count")
                heat_pivot = heat_agg.pivot(index="hour", columns="date", values="count").fillna(0)
                fig_sys_heat = px.imshow(
                    heat_pivot,
                    labels=dict(x="Date", y="Hour of Day", color="Actions"),
                    title="All Users — Activity by Hour & Date",
                    color_continuous_scale="Reds",
                    aspect="auto"
                )
                st.plotly_chart(fig_sys_heat, use_container_width=True)

                st.markdown("#### Activity by User")
                user_counts = heat_df["username"].value_counts().reset_index()
                user_counts.columns = ["User", "Actions"]
                fig_users = px.bar(user_counts, x="User", y="Actions",
                                   title="Total Actions per User", color="Actions",
                                   color_continuous_scale="Blues")
                st.plotly_chart(fig_users, use_container_width=True)
            else:
                st.info("Not enough data for heatmap yet.")

            st.markdown("---")

            # ── Frozen Accounts & Unfreeze Requests ──────────────────────────
            st.markdown("### 🔒 Frozen Accounts & Unfreeze Requests")
            frozen_users = get_frozen_users()

            if frozen_users:
                for fu_username, fu_reason, fu_requested in frozen_users:
                    with st.container():
                        col_info, col_btn = st.columns([4, 1])
                        with col_info:
                            st.error(f"🔒 **{fu_username}** — {fu_reason or 'No reason given'}")
                            if fu_requested:
                                st.warning("📩 This user has sent an **unfreeze request**.")
                            else:
                                st.caption("No unfreeze request yet.")
                        with col_btn:
                            if st.button(f"✅ Unfreeze {fu_username}", key=f"unfreeze_{fu_username}"):
                                unfreeze_user(fu_username)
                                log_action(current_user, f"Admin unfroze account: {fu_username}", "INFO")
                                st.success(f"✅ {fu_username}'s account has been unfrozen.")
                                st.rerun()
                        st.markdown("---")
            else:
                st.success("✅ No accounts are currently frozen.")

            st.markdown("---")

            # ── Duress Alerts log ────────────────────────────────────────────
            st.markdown("### 🆘 Duress Alerts (Coercion Signals)")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, action, severity, timestamp FROM logs"
                " WHERE action LIKE '%DURESS ALERT%' ORDER BY id DESC"
            )
            duress_logs = cursor.fetchall()
            conn.close()
            if duress_logs:
                for d in duress_logs:
                    st.error(f"🚨 **{d[0]}** | {d[3]} | {d[1]}")

                # Manual freeze any active user from here too
                st.markdown("#### Manually Freeze a User")
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM users WHERE status='active' AND role != 'admin'")
                active_users = [r[0] for r in cursor.fetchall()]
                conn.close()
                if active_users:
                    freeze_target = st.selectbox("Select user to freeze", active_users, key="manual_freeze_select")
                    freeze_reason_input = st.text_input("Reason", value="Manual freeze by admin", key="manual_freeze_reason")
                    if st.button("🔒 Freeze Account", key="manual_freeze_btn"):
                        freeze_user(freeze_target, reason=freeze_reason_input)
                        log_action(current_user, f"Admin manually froze account: {freeze_target}", "WARNING")
                        st.warning(f"🔒 {freeze_target}'s account has been frozen.")
                        st.rerun()
            else:
                st.success("No duress alerts on record.")

            st.markdown("---")

            st.markdown("### Full System Logs")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username, action, severity, timestamp FROM logs ORDER BY id DESC LIMIT 500"
            )
            all_logs = cursor.fetchall()
            conn.close()
            if all_logs:
                df_all_logs = pd.DataFrame(all_logs, columns=["User", "Action", "Severity", "Timestamp"])
                sev_options = ["All"] + sorted(df_all_logs["Severity"].unique().tolist())
                sev_filter = st.selectbox("Filter by Severity", sev_options, key="admin_sev_filter")
                if sev_filter != "All":
                    df_all_logs = df_all_logs[df_all_logs["Severity"] == sev_filter]
                def highlight_sev(row):
                    color_map = {
                        "INFO": "color: #2196F3",
                        "WARNING": "color: #FF9800",
                        "ALERT": "color: #f44336",
                        "CRITICAL": "color: #9C27B0; font-weight:bold"
                    }
                    sev = row.get("Severity", "")
                    style = color_map.get(sev, "")
                    return ["" if col != "Severity" else style for col in row.index]
 
                st.dataframe(
                    df_all_logs.style.apply(highlight_sev, axis=1),
                    use_container_width=True
                )
                st.markdown("#### Severity Distribution")
                sev_counts = df_all_logs["Severity"].value_counts().reset_index()
                sev_counts.columns = ["Severity", "Count"]
                fig_sev = px.bar(
                    sev_counts, x="Severity", y="Count", color="Severity",
                    color_discrete_map={
                        "INFO": "#2196F3", "WARNING": "#FF9800",
                        "ALERT": "#f44336", "CRITICAL": "#9C27B0"
                    },
                    title="Log Events by Severity"
                )
                st.plotly_chart(fig_sev, use_container_width=True)
            else:
                st.info("No logs yet.")

            st.markdown("---")

            st.markdown("### System-Wide Threat Summary")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Failed login%'")
            total_failed_logins = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Incorrect PIN%'")
            total_wrong_pins = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%Tampering detected%'")
            total_tamper = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE '%DURESS ALERT%'")
            total_duress = cursor.fetchone()[0]
            conn.close()
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Failed Logins", total_failed_logins)
            c2.metric("Wrong PINs", total_wrong_pins)
            c3.metric("Tamper Events", total_tamper)
            c4.metric("Duress Signals", total_duress)

            st.markdown("---")

            # ── 11. User Activity Timeline (admin view) ───────────────────────
            st.markdown("### 📋 User Activity Timeline")
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users ORDER BY username")
            all_unames = [r[0] for r in cursor.fetchall()]
            conn.close()

            if all_unames:
                selected_user_tl = st.selectbox("Select user to view timeline", all_unames, key="admin_tl_user")
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT action, severity, timestamp FROM logs WHERE username=? ORDER BY timestamp DESC LIMIT 100",
                    (selected_user_tl,)
                )
                tl_rows = cursor.fetchall()
                conn.close()

                severity_icons = {"INFO": "🔵", "WARNING": "🟡", "ALERT": "🔴", "CRITICAL": "🟣"}
                if tl_rows:
                    for action, sev, ts in tl_rows:
                        icon = severity_icons.get(sev, "⚪")
                        st.markdown(f"{icon} **{ts}** — {action}")
                else:
                    st.info("No activity for this user yet.")

            st.markdown("---")

            # ── 12. Admin Notes on Users ──────────────────────────────────────
            st.markdown("### 📝 Admin Notes on Users")
            note_target = st.selectbox("Select user to add a note about", all_unames, key="note_target")
            note_text = st.text_area("Write a private note about this user", key="note_text_input")
            if st.button("💾 Save Note", key="save_note_btn"):
                if note_text.strip():
                    save_admin_note(current_user, note_target, note_text.strip())
                    log_action(current_user, f"Added admin note about {note_target}", "INFO")
                    st.success(f"✅ Note saved for {note_target}.")
                else:
                    st.warning("Please write a note first.")

            st.markdown("#### 📋 Existing Notes")
            view_notes_user = st.selectbox("View notes for user", all_unames, key="view_notes_user")
            notes = get_admin_notes(view_notes_user)
            if notes:
                for n_admin, n_text, n_ts in notes:
                    st.info(f"**{n_ts}** (by {n_admin}): {n_text}")
            else:
                st.caption(f"No notes for {view_notes_user} yet.")

            st.markdown("---")

            # ── 4. IP / Device Login History (admin view) ─────────────────────
            st.markdown("### 🖥️ User Login Device History")
            device_user = st.selectbox("Select user", all_unames, key="device_user_select")
            devices = get_login_devices(device_user)
            if devices:
                df_dev = pd.DataFrame(devices, columns=["IP Address", "Device/Platform", "Login Time"])
                st.dataframe(df_dev, use_container_width=True)
            else:
                st.info(f"No login device history for {device_user}.")

            st.markdown("---")

            # ── 14. Backup & Restore ──────────────────────────────────────────
            st.markdown("### 💾 Database Backup & Restore")

            col_bk, col_rs = st.columns(2)

            with col_bk:
                st.markdown("#### ⬇️ Download Backup")
                db_path = "secure_chat.db"
                if os.path.exists(db_path):
                    with open(db_path, "rb") as f:
                        db_bytes = f.read()
                    st.download_button(
                        label="⬇️ Download Database Backup (.db)",
                        data=db_bytes,
                        file_name=f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
                        mime="application/octet-stream",
                        key="dl_backup"
                    )
                    st.caption(f"Current DB size: {len(db_bytes)/1024:.1f} KB")
                else:
                    st.warning("Database file not found.")

            with col_rs:
                st.markdown("#### ⬆️ Restore from Backup")
                restore_file = st.file_uploader("Upload .db backup file", type=["db"], key="restore_upload")
                if restore_file is not None:
                    if st.button("⚠️ Restore Database (overwrites current!)", key="restore_btn"):
                        backup_bytes = restore_file.read()
                        with open(db_path, "wb") as f:
                            f.write(backup_bytes)
                        log_action(current_user, "Restored database from backup", "ALERT")
                        st.success("✅ Database restored! Please restart the app.")
                        st.warning("⚠️ App restart required for changes to take effect.")

            st.markdown("---")

            # ── 15. System Health Monitor ──────────────────────────────────────
            st.markdown("### 🖥️ System Health Monitor")

            h1, h2, h3, h4 = st.columns(4)

            # Disk usage
            try:
                disk = shutil.disk_usage(".")
                disk_used_pct = (disk.used / disk.total) * 100
                h1.metric("💽 Disk Used", f"{disk.used//(1024**3)} GB", f"{disk_used_pct:.1f}%")
                h2.metric("💽 Disk Free", f"{disk.free//(1024**3)} GB")
            except Exception:
                h1.metric("💽 Disk", "N/A")

            # DB size
            try:
                db_size_kb = os.path.getsize("secure_chat.db") / 1024
                h3.metric("🗄️ DB Size", f"{db_size_kb:.1f} KB")
            except Exception:
                h3.metric("🗄️ DB Size", "N/A")

            # Total log entries
            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM logs")
            total_log_entries = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users_count = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM messages")
            total_msgs = cursor.fetchone()[0]
            conn.close()
            h4.metric("📋 Total Log Entries", total_log_entries)

            sys_c1, sys_c2, sys_c3 = st.columns(3)
            sys_c1.metric("👥 Total Users", total_users_count)
            sys_c2.metric("💬 Total Messages", total_msgs)
            sys_c3.metric("🐍 Python", platform.python_version())

            # Uploaded files size
            try:
                uf_size = sum(
                    os.path.getsize(os.path.join("uploaded_files", f))
                    for f in os.listdir("uploaded_files")
                    if os.path.isfile(os.path.join("uploaded_files", f))
                )
                st.metric("📁 Uploaded Files Storage", f"{uf_size/1024:.1f} KB")
            except Exception:
                pass

            st.markdown(f"**OS:** {platform.system()} {platform.release()} | "
                        f"**Machine:** {platform.machine()} | "
                        f"**Hostname:** {platform.node()}")


else:
    st.info("Please login or register to use the secure chat system.")
