# Demonstration inputs

Run python tools/make_demo_files.py after installing dependencies.

- synthetic-demo.exe is a hand-assembled 1 KiB PE data fixture. Upload it to Analyze a file; never execute it. It contains no actual malware and cannot validate malware-detection accuracy.
- sample-document.txt is explicitly synthetic text for encryption/recovery.
- cover.png is an 800 x 600 synthetic RGB gradient, with approximately 179 KB available after package overhead.
- reviewed-findings.template.json is a placeholder contract, not model output. Replace every placeholder with actual reviewed evidence before importing. It intentionally fails hash validation unchanged.

No default accounts, real malware, real findings, private keys, or credentials ship in the source archive.
