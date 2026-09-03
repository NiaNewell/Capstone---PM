# PASSWORD MANAGER 

A self-hosted, security-focused password manager. Credentials are encrypted and stored locally, and access is gated by multi-factor authentication combining a master password, a USB key file and a PIN, with the inclusion of a recovery key for account recovery.

The project is being developed in three stages: a working CLI (done), a rewritten cryptographic core (in progress), and a local REST API with an optional container deployment (planned).

Status: v1 CLI functional. Cryptographic core being restructured. Currently only stores test credentials.


## ABOUT V1:  
Self-auditing found that storing the derived vault key in the master.json verifier field was too insecure— anyone holding that single file can decrypt the vault without supplying any authentication factor. This invalidated the key-derivation design, so the core is being rebuilt around a wrapped-key architecture before the API work begins.
The full v2 design and threat model:
[`docs/vault-key-recovery-spec.md`](docs/vault-key-recovery-spec.md)


## Why Self-Hosted:
Commercial password managers require trusting a third party with an encrypted vault and the infrastructure that serves it. This project keeps the vault, the key material, and the authentication data entirely on the user's own machine. The API binds to localhost by default and has no outbound network dependency.

**Risks:** The user takes on backup and availability. If the vault file is lost or damaged without a backup, the data is gone — there is no provider to restore it.


## Authentication Model
Three factors, any two of which grant access:

FACTOR               ---	           TYPE             ---	          STORAGE
Master password	     ---     Something you know	        ---        Never stored
USB key file + PIN	 ---     Something you have	        ---        Secret wrapped by the PIN, on the drive
Recovery key         ---	Pre-generated secret        --- 	   Never stored

The vault key is a random 32-byte value generated once at setup. It is wrapped three times — once per pair of factors — and any one of those wrapped copies unwraps to the same key:

SLOT               ---	           FACTORS REQUIRED             ---	          SCENARIO
normal	           ---       master password + USB secret       ---     	Everyday login
lost_password	   ---         recovery key + USB secret	    ---     Master password forgotten
lost_usb	       ---      recovery key + master password	    ---     USB lost, destroyed, or PIN forgotten


**NOTE:**
1. Recovery never re-encrypts the vault. Because the vault key never changes, recovering from a lost factor rewrites a few hundred bytes of wrapped key material. The vault file is untouched, so there is no window in which a crash mid-rewrite destroys the data.
2. 2/3 authentication is enforced by cryptography, not application logic. An attacker who
copies the vault files does not run this program's checks — they attack the
ciphertext directly. Because each slot's key-encryption key is derived from a
pair of factors, a single factor unwraps nothing.


## Cryptography:
- Key derivation: scrypt (n=2^17, r=8, p=1) over length-prefixed factor material
- Key wrapping: AES-256-GCM, with the slot identity bound as additional authenticated data
- Vault encryption: Fernet (AES-128-CBC + HMAC-SHA256), keyed by the random vault key

**Objectives:** No verifier hashes. AEAD authenticates on decrypt, so a failed unwrap is the wrong-credentials signal. Nothing is stored that can be attacked offline independently of the vault itself.


## PROJECT 

**Stage 1 — CLI (complete)**
 Encrypted local vault with group and credential CRUD
 USB key file detection and PIN registration
 Master password setup, verification, and rotation
 Recovery key generation

**Stage 2 — Cryptographic core (in progress)**
 Threat model and v2 specification
 wrap / unwrap / derive_kek primitives, with unit tests
 PIN-wrapped USB secret, replacing the PIN verifier hash
 Slot-based setup and login
 Recovery and credential-change flows
 Atomic writes for all key material

**Stage 3 — REST API (planned)**
 Flask application exposing authentication, vault, group, and credential endpoints
 Token-based session handling with idle and absolute timeouts
 Request validation and consistent, non-leaking error responses
 Rate limiting on authentication endpoints
 Container deployment with the vault on a mounted volume

## Planned API surface
Draft — modifications may be made as stage 2 progresses.

Method  	        Endpoint	                 Purpose
POST    	       /auth/login	        Submit factors, receive a session token
POST    	       /auth/logout	        Invalidate the session and drop the key from memory
POST    	       /auth/recover	    Recovery flow entry point
GET 	           /groups	            List credential groups
POST    	       /groups	            Create a group
GET 	    /groups/{group}/entries	    List entries, secrets omitted
POST	    /groups/{group}/entries	    Create an entry
GET	        /entries/{id}/secret	    Retrieve one password, explicitly requested
PUT	                /entries/{id}	    Update an entry
DELETE	            /entries/{id}	    Delete an entry


**API Rules:**
- The vault key exists only in server memory, only for the life of a session. It is never written to disk, never logged, and never returned to a client.

- Secrets are never included in list responses; Passwords are only returned when a specific entry is requested, so a list of credentials can never expose all of the passwords at once.


## SECURITY CONCERNS/CONSIDERATIONS
- The USB is a file, not hardware-bound. Its secret can be copied. The PIN wrap raises the cost of a stolen drive but does not make the factor unclonable. True hardware binding would require a security key with an onboard secret.

- A compromised host defeats everything. A keylogger would capture the master password and PIN. Python strings are immutable, so secrets cannot be reliably scrubbed from process memory.

- The API is localhost-only by design. Exposing it to a network would require TLS and a much larger threat model than the one documented.

- Attempt limits are useless against an offline attacker. They deter online guessing; the real defence against a copied vault file is the cost of the KDF.

**V1 IS NOT SAFE FOR REAL-WORLD USE!!!  See the status note above.**


