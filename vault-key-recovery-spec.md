# Vault Key & Recovery Specification — v2

**Status:** design, not yet implemented. Upgrade of the v1 scheme in which the vault key was derived directly from master password + USB secret.


## 1. Goals

- The vault is encrypted with a key that **never changes** after setup.
- Access requires **any 2 of 3 factors**, enforced cryptographically rather than by a Python flag.
- No factor (password, USB secret, PIN, recovery key) is ever written to disk in a recoverable form.
- Recovery replaces credentials, never re-encrypts the vault.

## 2. Non-goals

- Hardware binding of the USB. The "something you have" factor is a *file*, which can be copied. Defeating a cloned USB is out of scope for v2.
- Multi-user / shared vaults. 
- Protection against a compromised host (keylogger, memory scraping). Python strings are immutable; secrets cannot be reliably scrubbed from memory.

## 3. Threat model

| **Attacker holds**                |    ---     |         **Outcome**       |

| `master.json` + `vault.bin` only  |    ---     | Must brute-force a full 2-factor pair. Infeasible for pairs containing the recovery key. 
| Above + USB drive (no PIN)        |    ---     | USB secret is wrapped by the PIN; must brute-force the PIN, then still needs password or recovery key. 
| Above + PIN                       |    ---     | Reduced to brute-forcing the master password. **This is the weak link** — password strength and scrypt cost are the only mitigations. 
| Recovery key alone                |    ---     | Unlocks nothing. 


## 4. Key hierarchy

**Vault Key (VK)** — 32 random bytes, generated once at setup
  
    +-- VK is used to encrypt vault.bin with Fernet
  
    +-- wrapped three times, once per factor pair, and stored in master.json

**USB Secret (US)** — 32 random bytes, generated once at setup
  
    +-- wrapped by scrypt(PIN) and stored on the USB drive


## Authentication Factors

 **Factor**                   ---              **Representation**                 ---                 **Where it is Stored** 

 Master password (MP)         ---          UTF-8 bytes of user input              ---                      User's head 
 USB secret (US)              ---                32 raw bytes                     ---                  Wrapped on USB drive 
 PIN                          ---             UTF-8 bytes of digits               ---                      User's head
 Recovery key (RK)            ---      32-char hex string, 128 bits entropy       ---                  Printed once at setup


## 5. The three slots

Each slot stores an independently wrapped copy of the same VK. Unwrapping any one yields the vault key.

  **Slot**          ---          **KEK derived from**       ---         **Unlocks when** 

 `normal`           ---                MP + US              ---          Everyday login 
 `lost_password`    ---                RK + US              ---      Master password forgotten 
 `lost_usb`         ---                RK + MP              ---   USB lost, destroyed, or PIN forgotten 

**Consequence of wrapping PIN:** a forgotten PIN destroys the USB secret even though the drive is physically present. "Forgot PIN" and "lost USB" therefore have the same recovery path with the same solution: create a new USB secret. There are two recovery flows, not three.

## 6. Cryptographic parameters/variables

- **KDF:** scrypt, `r=8`, `p=1`.
  - Slots: `n = 2**17` (128 MiB, ≈0.5–1 s)
  - PIN wrap: `n = 2**17` minimum. **Minimum 6 digits**, 8 recommended.
- **Wrapping cipher:** AES-256-GCM. Stored blob is base64-encoded.
- **Vault cipher:** Fernet, unchanged from v1, keyed by `urlsafe_b64encode(VK)`. This keeps `vault.py` untouched.


### KEK derivation — canonical encoding

The factors used to derive a key-encryption key (KEK) are given their lengths before being combined. This avoids ambiguity when combining multiple factors.


```
material = len(f1).to_bytes(4,'big') || f1 || len(f2).to_bytes(4,'big') || f2
KEK      = scrypt(material, salt=slot_salt, length=32, n, r, p)
```

Each factor is stored together with its length, so the boundaries between factors are always unambiguous.

The V1 implementation combined the factors using a ':' delimiter; f"{password}:{usb_secret}"
This could be ambiguous if a factor itself contained ':'. This new method removes this ambiguity and provides a consistent encoding for all factor combinations.


### Additional authenticated Data (AAD) - Binding Wrapped Keys to its Purpose

Each wrapped key is cryptographically bound to the slot it belongs to using AES-GCM's Additional Authenticated Data (AAD).

The AAD identifies the purpose of the wrapped key:
    slot:<name>:v2
    The USB secret wrap uses: usb-secret:v2

This prevents an encrypted key from being moved to a different slot and reused for another purpose. For example, an attacker cannot take the lost_usb slot's wrapped key and place it in the normal slot. Because the slot identity is authenticated using AAD, the unwrap operation will fail.

### No verifier hashes

AES-GCM authenticates the wrapped key when decrypted. A failed unwrap is the "wrong credentials" signal. All `verifier` and `hash` fields from v1 are deleted, and `install_usb.hash` file will not be created in this version.

Login failure must not distinguish *which* factor was wrong. A single "Authentication failed." response for any unwrap failure.


## 7. File formats

### `master.json` (v2)

```json
{
  "version": 2,
  "kdf": { "name": "scrypt", "n": 131072, "r": 8, "p": 1 },
  "slots": {
    "normal": {
      "salt": "<b64, 16 bytes>",
      "wrapped_key": "<b64 nonce||ct||tag>",
      "aad": "slot:normal:v2"
    },
    "lost_password": { "salt": "...", "wrapped_key": "...", "aad": "slot:lost_password:v2" },
    "lost_usb":      { "salt": "...", "wrapped_key": "...", "aad": "slot:lost_usb:v2" }
  },
  "recovery_key_created": "<ISO-8601 UTC>"
}
```

### `pm_install.key` (on the USB drive)

```json
{
  "version": 2,
  "kdf": { "name": "scrypt", "n": 131072, "r": 8, "p": 1 },
  "salt": "<b64, 16 bytes>",
  "wrapped_secret": "<b64 nonce||ct||tag>",
  "aad": "usb-secret:v2"
}
```

### `vault.bin`

Unchanged: Fernet ciphertext of the vault JSON.


## 8. Operations

`VK` = Vault Key, `RK` = Recovery Key, `US` = USB Secret, `MP` = Master Password, `KEK` = Key Encyrption Key 


### Setup

1. Generate `VK = os.urandom(32)` and `US = os.urandom(32)`.
2. Prompt master password and PIN.
3. Generate `RK = secrets.token_hex(16)`; display once, require typed confirmation before continuing.
4. Wrap `US` under `scrypt(PIN)`; write `pm_install.key` to the USB.
5. Write all three slots (see *Rewrite all slots*).
6. Encrypt an empty vault with `Fernet(b64url(VK))` → `vault.bin`.

### Login

1. Locate USB → read `pm_install.key` → prompt PIN → unwrap → `US`.
2. Prompt master password.
3. `KEK = KDF(MP, US, slots.normal.salt)` → unwrap `slots.normal` → `VK`.
4. Open vault with `Fernet(b64url(VK))`.

### Rewrite all slots — the single key update operation

When all required authentication factors `VK`, `MP`, `US` and `RK` are available, generate a new salt for each of the three slots and create new wrapped copies of VK. Write all three updated slots to master.json together as one atomic operation. 

Every credential change and every recovery is a call to this function. It is the only code that ever writes `master.json`.

### Recovery A — forgot master password

Factors: USB + PIN + recovery key.
Unwrap `lost_password` → `VK` → prompt new password → rotate `RK` → rewrite all slots.

### Recovery B — lost USB, or forgot PIN

Factors: master password + recovery key.
Unwrap `lost_usb` → `VK` → generate new `US` and PIN → write new `pm_install.key` → rotate `RK` → rewrite all slots.

### Change master password / change PIN (from inside the vault)

Both collapse to: unwrap via `normal`, replace the one factor, rewrite all slots. Neither touches `vault.bin`.


## 9. Invariants

1. **VK is generated once and never changes.** The only exception is the one-time v1→v2 migration.
2. **The vault is never re-encrypted during recovery.** Recovery rewrites a few hundred bytes of key material.
3. **The recovery key is rotated after every successful recovery.** Must be recorded upon creation
4. **`master.json` is written atomically:** serialize in full → write to temp file → `fsync` → `os.replace`. `master.json` is always written as one complete update: the new file is prepared in a temporary file, saved to disk, and then replaces the old file. This prevents a failed or interrupted write from leaving `master.json` only partially updated.
5. **Fresh salts on every rewrite.** A new salt is generated whenever the slots are rewritten.
6. **No factor is stored.** Only wrapped material and KDF parameters.


## 10. Open questions

- **Preserving the USB secret through a forgotten PIN.** 
A second copy of `US` could be protected with the recovery key and stored on the USB drive. This would allow the user to keep the same USB secret after forgetting the PIN instead of registering the USB again. However, it adds extra complexity, currently unecessary for app completion. *Deferred*

- **Persistent attempt limits.** 
The current 3-attempt limit resets when the program restarts, so it does not provide much protection against someone attacking the files directly. Storing an attempt counter and timestamp in `master.json` could slow down online guessing, but the KDF's cost is the main protection against offline attacks. *Low priority.*


- **Cross-platform USB detection.** 
`find_file_usb()` scans drive letters from `A:`–`Z:`, so USB detection only works on Windows. Support for Linux and macOS could be added later.
