# Administration and automatic account keys

The user requests a backend to manage all users/activity and explicitly clarified that a public/private key pair must be assigned automatically when an account is created. They rejected further key-custody questions and asked to proceed with automatic assignment. Implementation continues inline in the existing local project.

## Intended behavior

- New accounts created through registration (when enabled), the operator CLI, or the admin UI receive a unique RSA-3072 key pair before creation commits. Account creation fails safely if the isolated key worker is unavailable. Existing accounts without an assigned pair receive one after their next successful authentication, including MFA when enrolled.
- Assignment is automatic and idempotent: signing in again never changes a key. No separate key-generation wizard is required. Old manually downloaded keys and previously protected PNGs remain usable through the existing upload-based recovery path.
- A local key-vault row stores the public PEM, its SHA-256 fingerprint, a passphrase-encrypted PKCS8 private PEM, creation time and vault version. A domain-separated HKDF secret derived from the persistent application secret and account ID unlocks that private PEM. The passphrase is never stored in the database or logs. Unencrypted private keys remain in the bounded local worker's memory.
- This is server-managed key custody. The trusted Windows operator controls the application secret and can ultimately access the vault. Ordinary application administrators receive no private-key viewing/export capability for other accounts. Database backups now contain encrypted private keys and require the original application secret for recovery; changing that secret does not regenerate existing keys.
- The owner can download their public key. Private-key export requires fresh password verification (and TOTP if enabled), trusted-server acknowledgment, and a separate 12–256-character export passphrase. Export re-encrypts the same assigned key in the isolated document worker. A normal login password change does not rotate or lose document keys.
- Protect document defaults to the signed-in user's assigned public key, with an explicit uploaded recipient-key option. Recover document supports the assigned private key after fresh verification, and retains uploaded private-key recovery for old/external packages.

## Administration

Use one MFA-protected admin blueprint for every administrative route. Provide a dashboard, paginated/searchable accounts, a per-user account/activity view, account creation, enable/disable, session revocation, and issuance of a short-lived one-time password setup/recovery code. New accounts created by an administrator use a random unknown login password until the owner redeems their setup code. Codes are displayed only in the action response, never logged, emailed automatically or placed in a URL.

The dashboard/activity pages show account status, role, key-assignment status, scan/external-check counts, provider processing-state counts, and a paginated filterable audit trail. Audit entries distinguish the acting user from the affected account. Add activity events for meaningful account and key operations. Private scan findings, submitted URLs/files, document bytes, passwords, keys and provider credentials do not appear in administrative activity views. Existing owner-only content authorization remains in force.

Account management through this UI applies to ordinary users. Administrator creation/recovery remains an operator-console function; the UI cannot disable an administrator, change roles or delete audit history and has no direct impersonation control. Recovery administrators are trusted identity verifiers: a recovery code can let them reset and access a non-MFA account. Existing owner MFA is preserved. These are implementation boundaries chosen to preserve administrator access and make the recovery trust boundary explicit.

## Approaches and implementation choices

Download-only private keys would preserve the former transient-key model but cannot provide an automatically assigned pair to an operator-created account before its owner signs in. A user-passphrase vault would require a setup choice the user explicitly does not want before assignment. The implementer therefore selects an encrypted, server-managed local vault and communicates that custody change. This is a technical choice to satisfy automatic assignment, not a claim that the user selected a specific cryptographic format.

Reuse Flask, SQLAlchemy/SQLite, existing authentication/TOTP/CSRF/rate controls and the isolated Docker document worker. Add no cloud service or dependency. Keep registration closed by default and keep the loopback-only deployment. Do not create a real administrator, choose their credentials or enroll their authenticator through automation.

## Migration, failures and acceptance

Schema version 4 adds the account-key table and an optional audit target ID. Preserve all existing users, scans, checks and events, and create the existing pre-upgrade backup. Restore accepts valid schema 2/3/4 snapshots, adds new structures only to the staged copy and keeps its current atomic replacement protections. Legacy restored accounts are assigned keys on authenticated use; current vault rows survive backups/restores unchanged.

Prove assignment uniqueness, repeated-login stability, concurrent first assignment, account-creation rollback, encrypted persistence, owner-only export, password/MFA checks, recovery with the assigned key, compatibility with uploaded old keys, admin authorization on every route, target-specific auditing, filtering/pagination and migration/restore preservation. Run the full suite, rebuild the document worker, verify real worker export/recovery and inspect the admin/key screens on desktop/mobile. Use disposable browser fixtures for administrator MFA; do not promote the publicly documented preview account.
