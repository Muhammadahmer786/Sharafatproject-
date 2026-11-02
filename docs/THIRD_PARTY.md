# Third-party components and downloads

## Local AI runtime added 2 November 2026

The [official Ollama Windows archive](https://github.com/ollama/ollama/releases/tag/v0.40.13) is pinned to 0.40.13 and SHA-256 `7afa38624fa62ee5d8293422d0ab084c1bb4603134c7f4dafce11a033b57cc19`. The portable runtime and models are excluded from the source ZIP. [Qwen3:4b](https://ollama.com/library/qwen3:4b) is the installed local model; each report records its actual manifest digest. Preserve upstream runtime/model notices when redistributing their assets. Setup follows the [Ollama Windows documentation](https://docs.ollama.com/windows); API integration follows [Chat](https://docs.ollama.com/api/chat), with cloud features disabled as described in the [FAQ](https://docs.ollama.com/faq). See LOCAL_AI.md for the actual pipeline and evaluation limits.

Recorded 30 October 2026. Python versions are pinned in requirements.lock.txt; their upstream licenses apply. Pillow was upgraded from 12.3.0 to 13.0.0 following the dependency audit. See [release notes](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html) and [upstream advisory](https://github.com/python-pillow/Pillow/security/advisories/GHSA-78g4-xqwv-q3g8).

## OpenBin tooling

Official sources: [OpenBin platform](https://github.com/openbin-ai/platform), [BINNY source](https://github.com/openbin-ai/binny), [BINNY releases](https://github.com/openbin-ai/binny-releases). Downloaded source trees retain LICENSE files. The reviewed source includes AGPL terms; inspect exact upstream distribution terms and satisfy applicable redistribution/source obligations before packaging for a customer. This inventory is not a legal certification.

The source ZIP excludes vendor binaries/source; reproduce downloads with tools/install-openbin.ps1 and preserve notices. No upstream installer was piped into a shell; no upstream executable was run as administrator; no cloud login/upload was made.

| Reviewed download | Observed SHA-256 |
| --- | --- |
| OpenBin Windows amd64 v0.10.0 ZIP | B08B0A73372D4F83E337D88BA33E57FDCFAC57A7490F72CE7E5BC5897D6976E7 |
| BINNY Windows amd64 v0.1.0-beta.3 ZIP | D8BFFFB1E97311C87723E03259BA07E3AF0E2DA5366D2133903FF6525107E70E |
| BINNY main source ZIP | 2C3EAA6347E6E463FBC7ABB2C6B04009F5DB04A4643DFEEDB8FC0BEB229F4A07 |
| OpenBin platform master source ZIP | 8F1FB318FE573BF0A5136F9492872745B346DDA025F5E546CE57E637A3E46927 |

Checksums identify artifacts downloaded over official HTTPS; they are not publisher signatures. Main/master references move; the hashes identify the reviewed snapshots.

setup-workers.ps1 targets the [official OpenBin release openbin-v0.10.0](https://github.com/openbin-ai/platform/releases/tag/openbin-v0.10.0) and expects openbin/ghidra-worker:7. The Ghidra archive's publisher-reported size is 663,034,322 bytes and SHA-256 is `5db065717451ae758bbd9f3302b6f4ac9c471acab23cb177780e4eb17a4dee1f`. Both are checked before Docker loads it. The old unprefixed release URL returned 404 and was corrected. See VERIFICATION.md for actual runtime evidence.

The dedicated WSL runtime uses Ubuntu 24.04 from [Microsoft's distribution manifest](https://github.com/microsoft/WSL/blob/master/distributions/DistributionInfo.json), verified against its SHA-256. Docker Engine is installed from [Docker's official Ubuntu repository](https://docs.docker.com/engine/install/ubuntu/). Runtime storage and downloads are on D:. Docker Desktop was not installed, and Windows was not upgraded.

The file worker uses Python 3.12 slim. Record the actual base-image digest and OS package inventory when building. The Python audit does not cover Docker, Ghidra, Java or base OS packages. Docker Desktop has separate licensing and host requirements.

## External reputation

[VirusTotal API documentation](https://docs.virustotal.com/reference/public-vs-premium-api) defines permitted use. Supply an appropriately licensed key through the private local helper. Following handover, a user-supplied key was verified with one quota-accounted hash lookup; no file was uploaded. The key is stored only in private local configuration and is excluded from source delivery. Scan hash disclosure requires per-scan consent.
# External intelligence workspace (30 October 2026)

The separate workspace uses official VirusTotal v3 contracts: [file lookup](https://docs.virustotal.com/reference/file-info), [URL submission](https://docs.virustotal.com/reference/scan-url), [IP reports](https://docs.virustotal.com/reference/ip-info), [file upload](https://docs.virustotal.com/reference/files-scan), and [analysis polling](https://docs.virustotal.com/reference/analysis). All calls share local quota accounting and use fixed HTTPS provider endpoints with redirects disabled. The application limits external file uploads to 20 MiB.

Unlike the optional hash-only step in local PE analysis, this workspace discloses the selected indicator or full file after explicit consent. VirusTotal may retain/share submissions. Its [public API restrictions](https://docs.virustotal.com/reference/public-vs-premium-api) prohibit commercial-product/service use and specify 4 requests/minute and 500/day. Customer use needs an appropriate license; a functioning key is not proof of entitlement.

Live testing used the empty-file SHA-256, https://example.com/, 8.8.8.8, and an agent-generated harmless text file. No customer file/code was submitted. Analysis response normalization supports both hyphenated and underscore category names observed in the live service. A temporarily missing accepted analysis is polled within the existing budget, without resubmitting the file/URL.
