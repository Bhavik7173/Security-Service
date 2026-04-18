import hashlib
import os

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)

    return sha256.hexdigest()


def verify_file_integrity(file_path, original_hash):
    current_hash = calculate_file_hash(file_path)
    return current_hash == original_hash, current_hash

from database import get_connection
from datetime import datetime

def save_file_record(sender, receiver, file_name, file_path, original_hash):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO file_integrity (
            sender, receiver, file_name, file_path, original_hash,
            last_checked_hash, status, upload_time, last_checked_time
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sender,
        receiver,
        file_name,
        file_path,
        original_hash,
        original_hash,
        "safe",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


def update_file_status(file_id, new_hash, status):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE file_integrity
        SET last_checked_hash=?, status=?, last_checked_time=?
        WHERE id=?
    """, (
        new_hash,
        status,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        file_id
    ))

    conn.commit()
    conn.close()


def get_user_files(username):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, file_name, file_path, original_hash, last_checked_hash, status, upload_time, last_checked_time
        FROM file_integrity
        WHERE username=?
        ORDER BY id DESC
    """, (username,))

    files = cursor.fetchall()
    conn.close()
    return files

def get_received_files(receiver):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, sender, file_name, file_path, original_hash, last_checked_hash, status, upload_time, last_checked_time
        FROM file_integrity
        WHERE receiver=?
        ORDER BY id DESC
    """, (receiver,))

    files = cursor.fetchall()
    conn.close()
    return files

def get_sent_files(sender):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, receiver, file_name, file_path, original_hash, last_checked_hash, status, upload_time, last_checked_time
        FROM file_integrity
        WHERE sender=?
        ORDER BY id DESC
    """, (sender,))

    files = cursor.fetchall()
    conn.close()
    return files