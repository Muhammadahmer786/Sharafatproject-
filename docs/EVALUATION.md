# Academic evaluation protocol

No detection-accuracy claim or measured malware dataset result is supplied.

1. Obtain supervisor approval for sample sources, handling environment, label provenance, and benign/malicious counts.
2. Start with inert fixtures and authorized benign PE files. Use an isolated VM for suspicious samples; never execute samples.
3. Freeze app/tool versions, provider/model, prompts, import method, hardware, and limits.
4. Keep prompt/decision calibration samples separate from the final evaluation set.
5. Record SHA-256, independent reference label/source, parser outcome, provider outcome/date, AI evidence, reviewer, time, and disagreements.
6. Count failures, unsupported samples, unknown hashes, and unavailable services explicitly.
7. Define any classification decision rule before evaluation. Heuristic severity and provider counts are not calibrated probabilities.
8. Report completion rate, time, useful evidence-supported indicators, false alarms and review effort. Add confusion matrix, precision, recall/F1 and uncertainty only with defensible labels and decision rules.
9. Do not use the same reputation verdict as both input and independent ground truth.
10. Verify document roundtrips using SHA-256 equality, plus wrong key/passphrase, altered payload, malformed PNG, and capacity boundaries.

Automated software tests demonstrate implemented workflow behavior; they do not evaluate real-world malware detection quality or certify security.
