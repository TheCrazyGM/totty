# TOTP-CLI

A minimal, self-contained command-line tool for importing _otpauth://_ URIs and displaying Time-based One-Time Passwords (TOTP) on demand.

- **Import** authenticator URIs from a file or **stdin** and store them in an encrypted SQLite database.
- **Display** the current codes with colour-coded expiry status.
- Works anywhere Python ≥ 3.10 runs and follows the XDG Base-Directory spec for config storage.

---

## Installation

```bash
# editable install while hacking on sources
pip install -e .

# or install from PyPI once released
pip install totp-cli
```

This exposes the executable `totp-cli`.

## Quick start

```bash
# import URIs listed in accounts.txt
$ totp-cli add accounts.txt
Inserted 3 records into /home/$USER/.config/totp-cli/totp.db.

# list all stored entries (names only)
$ totp-cli get
ACME alice@example.com
GitHub bob
AWS root

# display codes for a matching issuer/account
$ totp-cli get github
GitHub bob: [yellow]143925[/yellow] (expires in [yellow]12s[/yellow])
```

### Sub-commands

| Command          | Purpose                                                                                             |
| ---------------- | --------------------------------------------------------------------------------------------------- |
| `add <file\|- >` | Import each line containing an `otpauth://` URI; `-` reads from _stdin_.                            |
| `get [search]`   | Show codes whose _issuer_ or _account_ contains `search` (case-insensitive). No argument lists all. |

## Database & encryption

- Database file: `$XDG_CONFIG_HOME/totp-cli/totp.db` (defaults to `~/.config/totp-cli/totp.db`).
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
uvx ruff src/totp_cli && uvx ty src/totp_cli

# run unit tests (coming soon)
pytest
```

## License

This project is licensed under the MIT License – see `LICENSE.txt` for details.
