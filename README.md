# Audit Portfolio

Smart-contract security research and findings.

## Audits

| # | Title | Severity | Source | Verified |
|---|-------|----------|--------|----------|
| 01 | [Chakra Cross-Chain Bridge — Missing Duplicate Signature Check](01-chakra-cross-chain-bridge.md) | High | Code4rena (shadow) | ✅ matches official report |
| 02 | [Gamma LM — `_handleReturn` stale state + misdirected fee refund](02-gamma-lm-high-handleReturn-stale-state-and-misdirected-fee-refund.md) | High | CodeHawks 2025-02-gamma (shadow) | ✅ matches official report (Valid High dupes: #21, #53, #224, #342, #427, #428, #438, #443, #572, #573, #745, #1021) |
| 03 | [Gamma LM — `_withdraw` fee/PnL rounding direction favors user](03-gamma-lm-low-withdraw-fee-rounding-direction.md) | Low (official) / Medium (our rating) | CodeHawks 2025-02-gamma (shadow) | 🟡 partial match — official severity Low (#1135), code location confirmed |

Each finding includes root-cause analysis, attack path, Foundry PoC, and recommended mitigation.

Shadow audits are performed independently against closed contests, then self-verified against the published final report. Severity may differ between our writeup and the judges' final classification — the verification note at the bottom of each file documents any mismatch.

— hello@marcomori.net
