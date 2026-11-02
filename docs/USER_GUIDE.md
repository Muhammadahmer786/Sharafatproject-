# Sentinel Lab user guide

Your local administrator completes [server setup](LOCAL_DEPLOYMENT.md) and creates your account. Open http://127.0.0.1:5050/ on the same machine and sign in. No default passwords are shipped. Check Workspace settings for processing availability; missing isolated workers produce a setup error.

## Check a hash, URL, IP or any file type

Open **Threat intelligence** and select a tab:

- **File hash:** paste an MD5, SHA-1 or SHA-256 fingerprint to retrieve an existing report. No file bytes are sent.
- **URL:** submit a public HTTP(S) link for provider analysis. The entire URL and query are disclosed. Private/local addresses and embedded credentials are rejected. This server does not visit the target.
- **IP address:** enter a public IPv4/IPv6 address to retrieve reputation. This is not a port or vulnerability scan.
- **File upload:** select a non-empty file of any extension up to 20 MiB. The entire file is sent to VirusTotal; individual engines may not support its format. The local server does not execute it.

Read and check the disclosure confirmation before submitting. VirusTotal may retain/share submitted data; use only authorized, non-confidential inputs. The API key stays on the server. The external workspace needs internet and a configured key, but not Docker.

Checks share a quota, so results may wait. Open **Updates** (the bell in the top bar) from any signed-in page to see checks in progress and recent results. A clickable alert appears when an observed check completes or needs attention. Select **View result**, or click its entry in Updates, to open that check. **Mark all read** clears the unread indicators. On a waiting result page, the message also changes to a clickable result link when an update arrives.

Updates check the local server about every ten seconds while the page is visible; this does not spend VirusTotal quota. They pause in hidden tabs and stop when the session expires. Jobs continue in the server independently. The panel shows up to 20 active and 20 recent finished checks, plus the currently viewed check if needed; **View all checks** opens complete history. Old results populate the panel without a burst of alerts on first use. Read flags are remembered in this browser for this account; only bounded record IDs/revision/read flags are stored there, not indicators or provider results. No desktop or email notification is sent when the site is closed.

Check history is searchable/filterable and private to your account. Open a record for engine findings, provider analysis time, refresh, JSON export or local deletion. **Analysis complete** means a report is available. **No report available**, **Analysis unfinished** and **Analysis needs attention** explain different outcomes; unknown, pending and failed results never mean safe. Refresh retrieves the existing URL/file analysis; it does not upload again. An uncertain submission requires a new check with consent. Deletion does not erase provider copies or older local backups.

## Inspect a Windows file locally

1. Open Local file analysis and select an authorized native x86/x64 EXE or DLL, up to 10 MiB. Use examples/synthetic-demo.exe for demonstrations; never launch it.
2. Leave external consent unchecked for local-only inspection. Optional VirusTotal consent permits sending the SHA-256 hash. Cloud-code disclosure consent is separate.
3. Review structure, sections, entropy and preliminary indicators. Samples are never executed. Managed .NET files are outside scope.
4. Download the PDF or find the record through Scan history. Records remain owner-only; administrators cannot open another user's results.
5. Open Local OpenBin to decompile the same file, review its code and import the [findings contract](OPENBIN_IMPORT.md). Do not describe manual evidence as AI-generated.

An unknown hash, no detections or empty findings does not prove safety. Local/cloud provenance is the reviewer's declaration, shown in reports.

## Decompile with local OpenBin

1. Open **Local OpenBin** in the sidebar and choose an authorized Windows EXE or DLL, up to 10 MiB.
2. Select **Decompile & download**. Allow up to six minutes, including a cold WSL startup. One decompilation can run at a time.
3. Save the JSON download locally. It includes available functions, pseudocode, metadata and a SHA-256 link to the input file. The source program is never executed, and the worker has no network access.
4. Review the code manually. This raw decompilation page does not run a model; its output records that no AI model ran. For automatic local model review, open **Local AI** and follow [the local AI guide](LOCAL_AI.md). Raw decompilation JSON is different from an AI report or reviewed findings JSON.
5. To attach supported findings to a saved assessment, use the matching scan and the reviewed findings format linked above.

Input files and decompiled code are not kept in the application's history. The downloaded JSON remains wherever you save it; protect that local copy. A setup error requires the operator to check the local worker. A busy response means another decompilation is running.

## Protect and recover

1. Your public/private pair is assigned automatically when the account is created. Existing accounts receive a pair at their next successful sign-in. Open **Encryption keys** to see, copy or download your public PEM. To see your private PEM, enter your current account password, a fresh authenticator code if enrolled, and a separate backup passphrase (12–256 characters), acknowledge local processing and select **Show private key**. The displayed private PEM is encrypted with that backup passphrase. **Hide private key** removes the view; with JavaScript enabled it also clears after five minutes or when you leave. **Download key backup** downloads a ZIP containing the same public and encrypted private pair. Each account can access only its own keys. Share only the public PEM.
2. In Protect document, select your document and a sufficiently large lossless PNG. Keep My account selected to use your assigned public key, or choose Another recipient / uploaded public key and upload their PEM. Demonstration inputs are examples/sample-document.txt and examples/cover.png.
3. Check capacity, acknowledge processing and click **Protect & download**. An animated bar appears while the upload and protection are running. Keep the page open. When the server prepares **sentinel-protected.png**, the bar fills and says **Download started**; check the browser's Downloads panel or save dialog. Validation errors appear on the page instead. Transfer the protected PNG as an original file without resizing or recompressing.
4. In Recover document, provide the original protected PNG. Use My assigned private key with your account password and fresh authenticator code if enrolled, or choose an uploaded private PEM and its file passphrase. The same progress bar appears during recovery. A download is released only after authenticated decryption succeeds.
5. Compare original/recovered hashes with PowerShell Get-FileHash -Algorithm SHA256.

Documents are limited to 5 MiB and available image capacity; PNGs to 22 MiB and 12 million pixels; PEM key files to 16 KiB. With JavaScript enabled, selecting an oversized file shows a message before submission; replace it with a smaller file. The complete request, including form fields, must remain below 28 MiB. Application-generated upload errors return to the document form and require reselecting files; requests rejected earlier by the HTTP server display its 413 response. A file within the size limit still needs sufficient PNG capacity. RSA PEM keys support 2048–4096 bits; generated keys use 3072 bits. Encryption is AES-256-GCM with RSA-OAEP SHA-256 wrapping.

The progress bar shows activity, not a measured encryption percentage. **Download started** confirms the server has sent the attachment response; it cannot confirm that the browser saved the file to disk. The submit button is disabled while awaiting the response. If confirmation does not arrive within five minutes, the page stops the animation and asks you to check Downloads before refreshing and trying again. No automatic retry occurs. Reduced-motion preferences are respected; native downloads also work without JavaScript.

The trusted local server temporarily handles plaintext and private keys in memory. Hiding data does not make it undetectable. Assigned keys remain encrypted in the account vault and survive password changes/recovery. The original server secret is needed to unlock that copy. Keep an independent exported backup. A lost external private key or forgotten export passphrase cannot be reconstructed. The trusted machine operator controls the server secret; this is not end-to-end encryption. Wrong keys and changed image pixels can prevent recovery.

## Account security

Workspace settings → Account security provides password changes, TOTP enrollment and session revocation. Password changes sign out all old sessions. Administrator actions require an authenticator. A used six-digit code cannot be reused; wait for the next code.

For forgotten passwords, the operator verifies identity and issues a one-time recovery code. Use Recover your account on the sign-in page. No recovery email is sent. Lost authenticators require separate operator recovery.

Sessions expire after 30 idle minutes or eight hours from sign-in. Reload expired forms for a fresh CSRF token. Repeated sign-in attempts or heavy processing may require waiting for limits to reset.

## Administrator workspace

After creating the real administrator through the operator console and enrolling an authenticator, open Admin workspace. Overview shows account/key counts and recent activity. Accounts supports search, status filtering, account creation, individual activity, enable/disable, session revocation and recovery-code issuance. Activity searches actions by date and account, with pagination. Local server shows deployment checks and provider queue counts.

New account creation assigns keys before saving the account and displays a one-time setup code. Give the code directly to the intended owner; they open Recover your account, enter it and choose a password. Codes expire in 30 minutes and are shown once. The app sends no email. Existing MFA remains required after password recovery. Administrator accounts themselves are managed through the operator console.

Admin pages show account metadata and action history. They do not expose other users’ scan contents, submitted indicators or private keys.

## Retained information

Accounts, scan metadata/results, submitted indicators/URLs/filenames, consent, findings, jobs and activity persist. Assigned public keys and encrypted private keys persist in the local vault. Upload bytes and uploaded private-key files do not persist locally; VirusTotal may retain its copy. The operator decompiler deliberately saves its local output. Deleting a record does not remove older backups; retention is managed by the operator.

Read [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md) for API-key setup, backup/restore and recovery commands. Academic measurements require the separate [evaluation protocol](EVALUATION.md).


Administrator trust boundary: administrators who issue password recovery codes must verify the owner and handle codes securely. A trusted administrator could redeem a code themselves and access an account without MFA. Existing owner MFA is preserved and required at sign-in and private-key export. These controls restrict direct admin access; they do not make accounts cryptographically inaccessible to a malicious recovery administrator or machine operator.
