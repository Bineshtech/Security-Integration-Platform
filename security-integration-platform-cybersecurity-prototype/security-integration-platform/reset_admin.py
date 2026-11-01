import getpass
import app

username = "admin"

password = getpass.getpass("Enter your NEW password: ")
confirm = getpass.getpass("Confirm your NEW password: ")

if password != confirm:
    print("Passwords do not match.")
    raise SystemExit(1)

if len(password) < 12:
    print("Password must be at least 12 characters.")
    raise SystemExit(1)

password_hash = app.auth_manager.hash_password(password)

with app.db_connection() as conn:
    result = conn.execute(
        "UPDATE platform_accounts SET password_hash=? WHERE username=?",
        (password_hash, username)
    )

    if result.rowcount != 1:
        print("Admin account not updated.")
        raise SystemExit(1)

print("SUCCESS: Admin password reset.")
