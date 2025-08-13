# totty

A minimal, self-contained command-line tool for importing _otpauth://_ URIs and displaying Time-based One-Time Passwords (TOTP) on demand.

- **Import** authenticator URIs from a file or **stdin** and store them in an encrypted SQLite database.
- **Display** the current codes with colour-coded expiry status.
- Works anywhere Python ≥ 3.10 runs and follows the XDG Base-Directory spec for config storage.

---

## Installation

```bash
# editable install while hacking on sources
pip install -e .

# or install via uv once released
uv sync
```

This exposes the executable `totty`.

## Quick start

```bash
# import URIs listed in accounts.txt
$ totty add accounts.txt
Inserted 3 records into /home/$USER/.config/totty/totp.db.

# list all stored entries (names only)
$ totty get
ACME alice@example.com
GitHub bob
AWS root

# display codes for a matching issuer/account
$ totty get github
GitHub bob: [yellow]143925[/yellow] (expires in [yellow]12s[/yellow])
```

### Sub-commands

| Command          | Purpose                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| `add <file\|- >` | Import each line containing an `otpauth://` URI; `-` reads from _stdin_.                            |
| `get [search]`   | Show codes whose _issuer_ or _account_ contains `search` (case-insensitive). No argument lists all. |

## Database & encryption

- Database file: `$XDG_CONFIG_HOME/totty/totp.db` (defaults to `~/.config/totty/totp.db`).
- Secrets are encrypted at rest with AES-CFB using a master password prompted on first use.

Schema:

```sql
CREATE TABLE IF NOT EXISTS totp_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    account_name TEXT,
    issuer TEXT,
    secret TEXT,      -- ENC::<salt>::<cipher>
    algorithm TEXT,   -- SHA1, SHA256, SHA512
    digits INTEGER,   -- OTP length
    period INTEGER,   -- interval seconds
    counter INTEGER   -- for HOTP (optional)
);
```

## Development

```bash
# run Ruff & type-checker
uvx ruff check src/totty && uvx ty check src/totty

# run unit tests (coming soon)
pytest
```

## License

This project is licensed under the MIT License – see `LICENSE.txt` for details.
