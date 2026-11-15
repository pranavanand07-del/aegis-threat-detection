# 3-minute demo script

1. **Hero (20 s).** "Every request gets a score and every score shows its reasons." Point at the ruler and the ledger of rules on the right.
2. **Scoring (30 s).** Scroll to *How it decides*. Click "Run it" on *Evidence stacks up*: 50 + 15 + 40 = 105, blocked. Then *Password guessing*: 45, never blocks alone. "That is the weakness of any per-event score."
3. **Quiet intrusion (80 s, the winning moment).** Open *Attack lab*, press Run on "Quiet intrusion". Say: "Every step stays under 71. The original engine never blocks. Watch the chain on the right fill in." Finish: "Campaign view: BLOCK, 5 of 5 stages."
4. **Proof (30 s).** Scroll to *Proof*: "65 of 65 cases pass against the live code, including false positives we documented ourselves."
5. **Close (20 s).** Runs on one JDK, no cloud, no keys. Logs never leave the machine.

## Questions judges ask

* **Is it machine learning?** No, on purpose. It is an explainable rules engine plus one anomaly detector. Every decision can be traced to a rule and a line of code. ML is a roadmap item.
* **How did you pick the weights?** By hand, from attack severity and how often the rule is wrong (see the last column of the Rules table). They are tunable in one place per detector.
* **False positives?** Additive scoring means one weak rule cannot block. Two are documented in the Proof section.
* **Does campaign risk block?** Not yet. It is advisory so the original engine is unchanged. Next step: a switch that lets it drive blocking.
* **Is the data real?** Every event is labelled Observed, API or Simulated. Lab and simulator traffic are never shown as real.
* **How does it map to industry?** Each rule lists its MITRE ATT&CK technique; the 5-stage chain is a simplified kill chain.
* **What if the Wi-Fi fails?** Everything runs on localhost. Only the web fonts are fetched, with system fallbacks.
