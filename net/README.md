# Simple Login System (Flask)

Features: unique user identification, password + TOTP 2FA, role-based access (user/admin),
salted + peppered scrypt hashing, lockout after 5 failures, CSRF protection.

## Run
    pip install -r requirements.txt
    export PEPPER="$(python -c 'import secrets;print(secrets.token_hex(32))')"   # keep this secret & stable!
    export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
    python app.py                       # http://127.0.0.1:5000/register
    python app.py make-admin <username> # promote a user to admin

Losing/changing PEPPER invalidates all stored passwords.
