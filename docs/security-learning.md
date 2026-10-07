# Security Learning & Technical Focus

## `~/labs` — Security topics studied & ongoing practice

My study and lab work spans offensive security, defensive analysis and AI security. The technical directions below combine topics already studied with areas for deeper practice; they are not a claim that every technique has been implemented.

### `~/offensive` — Web, network & adversary techniques

- **Web application assessment:** OWASP WSTG and Top 10; deeper practice in authentication and session handling, access-control boundaries, input validation, injection flaws, SSRF, file handling and business-logic abuse. Focus: root cause, reproducible evidence and remediation retesting.
- **Network assessment & pivoting:** service enumeration, routing and segmentation, tunneling concepts and multi-hop access paths. Recorded lab topics include OSPF and EAP-MD5 security; packet captures and full configurations remain to be recovered.
- **Windows privilege escalation:** account and token context, local Administrator versus SYSTEM, and Meterpreter identity verification. My reconstructed `getsystem` lab records a reported SYSTEM identity; deeper study includes service permissions, impersonation concepts and UAC boundaries.
- **Linux privilege escalation:** privilege boundaries and kernel-exploitation concepts; further practice targets SUID/SGID behavior, Linux capabilities, sudo rules, scheduled tasks and writable service configurations.
- **Exploit development & binary analysis:** stack-based buffer overflows, instruction and stack pointers, input offsets, bad-character analysis and crash interpretation. Deeper study: calling conventions, exploit reliability and how memory protections affect control-flow corruption.
- **Kernel security:** Linux and Windows user/kernel boundaries and exploitation concepts. Further study includes kernel attack surfaces, memory-corruption primitives and mitigations; no working kernel exploit is claimed.

### `~/defensive` — Detection, investigation & validation

- **Security analytics:** Elasticsearch SOC practice and continued work toward event normalization, useful search queries, timelines and evidence-based investigation.
- **Detection engineering:** connect offensive behavior to observable host and network activity; develop and evaluate Sigma/YARA rules and MITRE ATT&amp;CK mappings as future lab deliverables.
- **Investigation workflow:** correlate process, authentication, service and network events; distinguish suspicious activity from normal behavior and document visibility gaps.
- **Purple-team validation:** a development goal is to pair an authorized test with captured telemetry, a detection hypothesis, false-positive analysis and a remediation retest.

### `~/ai-security` — LLM, agent & model security

- **LLM security study:** OWASP LLM Top 10, prompt injection, sensitive-information disclosure, unsafe output handling and excessive agency.
- **Advanced evaluation focus:** direct versus indirect prompt injection, retrieval trust boundaries, tool permissions, agent authorization and cross-session data isolation.
- **Evaluation methodology:** planned synthetic test cases with explicit expected behavior, observed results, failure categories and regression checks; garak, PyRIT and promptfoo are exploration targets.
- **ML foundations for security:** recorded exercises include anomaly detection, feature engineering, model evaluation, NLP, sequence modeling and transfer learning. These provide a study foundation; a deployed security model or measured detection performance is not claimed.

### `~/devsecops` — Security automation & delivery

- **Automation:** Python and shell scripting for repeatable checks, structured evidence collection and analysis.
- **Cloud and container security:** build on the linked AWS container-delivery project with deeper work on IAM scope, secrets handling, CI/CD trust boundaries and container permissions.
- **Planned pipeline checks:** dependency and image scanning, static analysis, infrastructure-policy checks and secret detection, with findings triaged and fixes verified.

**Evidence:** linked projects contain the available implementation material. Retrospective lab records are explicitly marked where original scripts, logs or screenshots are missing.


[Lab records](../labs/README.md) · [Back to profile](../README.md)
