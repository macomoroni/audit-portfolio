# [Medium] PerpetualVault: Withdraw-path position-fee conversion uses `prices.shortTokenPrice.max`, rounding the fee against the protocol

## Summary

In `_withdraw` the protocol converts the GMX position fee from USD into collateral-token units by dividing by `prices.shortTokenPrice.max`, while the symmetric deposit path in `afterOrderExecution` divides by `prices.shortTokenPrice.min`. Dividing the fee-in-USD by the *max* price yields the *smallest* possible token amount, i.e. the fee charged to the user is rounded down (and the implicit value left in the pool is rounded down as well). This silently transfers value from the remaining LPs to the withdrawer on every withdrawal, accumulating with volume.

## Vulnerability Details

### Affected Code

`contracts/PerpetualVault.sol`, `_withdraw`, lines 1108-1116:

```solidity
// we always charge the position fee of negative price impact case.
uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.max;
int256 pnl = vaultReader.getPnl(curPositionKey, prices, sizeDeltaInUsd);
if (pnl < 0) {
  collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.max;
} else {
  collateralDeltaAmount = collateralDeltaAmount - feeAmount;
}
```

Compare with the deposit-side fee conversion in `afterOrderExecution`, line 485:

```solidity
uint256 feeAmount = vaultReader.getPositionFeeUsd(market, orderResultData.sizeDeltaUsd, false) / prices.shortTokenPrice.min;
```

### Root Cause

GMX represents prices as a `(min, max)` band that brackets oracle uncertainty:

- `min` ≤ true price ≤ `max`
- Dividing a USD value by `min` yields the *maximum* number of collateral tokens (conservative when charging the user; favorable to the protocol).
- Dividing by `max` yields the *minimum* number of collateral tokens (favorable to the user; the protocol absorbs the uncertainty).

The deposit path correctly uses `min` so that the new depositor is charged the full conservative fee in collateral terms. The withdraw path uses `max`, which yields the smaller token count. Because `feeAmount` is then subtracted from `collateralDeltaAmount` (the amount the withdrawer pulls from the GMX position), a smaller `feeAmount` means *more* collateral routed to the withdrawer and *less* left covering the position. The same direction error compounds the `pnl / max` term when `pnl < 0`: it understates the loss the withdrawer should absorb.

### Attack Path

1. Vault holds a 3x short on ETH-USDC. `sizeDeltaInUsd = 100_000e30` is being withdrawn.
2. `getPositionFeeUsd` returns, say, `60e30` USD.
3. `prices.shortTokenPrice.min = 1.0000e24`, `prices.shortTokenPrice.max = 1.0002e24` (USDC, 6 decimals, with a 2 bps band).
4. With the buggy `max`: `feeAmount = 60e30 / 1.0002e24 ≈ 59.988e6` (USDC).
   With the correct `min`: `feeAmount = 60e30 / 1.0000e24 = 60.000e6`.
5. Difference per withdrawal: `~0.012 USDC` of fee not charged. On a 6 bps band the gap is `~0.036 USDC`. Scale linearly with `sizeDeltaInUsd`.

The amount per withdrawal is small but (a) compounds across the user base, (b) is asymmetric — opportunistic withdrawers exit at moments of wide oracle spread (volatility), so the leak is biased toward exactly the worst conditions for remaining LPs.

The companion bug on the `pnl` line widens the leak when `pnl < 0`: a withdrawer with a negative-PnL share is allowed to leave with more collateral than their pro-rata loss permits.

## Impact

- **Funds at risk:** small per-tx drift, proportional to `sizeDelta` × oracle-band-width × withdrawal-cadence. On a vault with $100M TVL referenced in the README, a 5 bps band and weekly aggregate withdrawals of $10M yields ~$5k per week leaked to early withdrawers, paid by remaining LPs.
- **Likelihood:** triggers on **every** withdrawal that touches `_withdraw` with a non-zero `getPositionFeeUsd`.
- **Permanence:** unrecoverable; each withdrawal locks in the over-distribution.
- **Invariant break:** README invariant *"Depositor Share Value Preservation: The value of a depositor's shares should never decrease due to the actions of other depositors"* — early withdrawers systematically extract value at remaining LPs' expense.

This is **Medium**: small per-transaction loss but recurring, deterministic, affects all remaining depositors, and the symmetry break with the deposit path makes it a clear inversion of intended rounding direction.

## Proof of Concept

```solidity
// test/PoC_RoundingDirection_Withdraw.t.sol
pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "../contracts/PerpetualVault.sol";
import "../contracts/VaultReader.sol";

contract PoC_RoundingDirection_Withdraw is Test {
    // sizeDeltaInUsd large enough to make rounding observable.
    function test_withdraw_fee_under_charged() public pure {
        uint256 sizeDeltaInUsd = 100_000e30;
        uint256 positionFeeFactor = 6e26; // 6 bps in PRECISION=1e30
        uint256 expectedFeeUsd = sizeDeltaInUsd * positionFeeFactor / 1e30; // = 60e30

        uint256 shortMin = 1_000_000_000_000_000_000_000_000;       // 1.0000e24 per USDC unit
        uint256 shortMax = 1_000_200_000_000_000_000_000_000;       // 1.0002e24

        uint256 feeWithMax = expectedFeeUsd / shortMax;             // buggy
        uint256 feeWithMin = expectedFeeUsd / shortMin;             // correct
        assertLt(feeWithMax, feeWithMin);                           // user under-charged
        assertEq(feeWithMin - feeWithMax, 11_998);                  // ~0.012 USDC less per call
    }
}
```

**Run:** `forge test --match-test test_withdraw_fee_under_charged -vvv`

## Tools Used

- Manual cross-reference of fee-conversion direction between deposit and withdraw paths.
- GMX V2 oracle-band reference.

## Recommended Mitigation

Use `prices.shortTokenPrice.min` symmetrically so the protocol charges the conservative (larger) fee in collateral units. Apply the same fix to the `pnl` conversion:

```diff
 // we always charge the position fee of negative price impact case.
-uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.max;
+uint256 feeAmount = vaultReader.getPositionFeeUsd(market, sizeDeltaInUsd, false) / prices.shortTokenPrice.min;
 int256 pnl = vaultReader.getPnl(curPositionKey, prices, sizeDeltaInUsd);
 if (pnl < 0) {
-  collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.max;
+  collateralDeltaAmount = collateralDeltaAmount - feeAmount - uint256(-pnl) / prices.shortTokenPrice.min;
 } else {
   collateralDeltaAmount = collateralDeltaAmount - feeAmount;
 }
```

Document the convention explicitly: *"Fees paid by the user are converted at `.min`, value distributed to the user is converted at `.max`."* This makes audits of future code straightforward.

## References

- GMX V2 `MarketUtils` price-band semantics.
- Common rounding-direction pattern for ERC4626 (`OZ ERC4626._convertToShares` rounding direction).

---
## Self-Verification (against official report)

Status: **PARTIAL-MATCH**

Notes: Direct match found at submission #1135 "`_withdraw` function uses `shortTokenPrice.max` instead of `shortTokenPrice.min` when computing negative PnL adjustment, leading to underestimation of losses and excessive collateral withdrawal" — judged **Low, Valid** by n0kto. Tag: `finding_withdraw_use_prices`. The official finding covers **both** the fee-line (1109) and the PnL-line (1112), exactly as our writeup identifies.

Severity mismatch: we rated this **Medium**; the judge rated it **Low**. Judge rationale: *"every withdraw, position opened, not liquidated, beenShort or not 1, and the difference between minPrice and maxPrice is significant... small part of feeAmount and PnL not deducted from collateralDeltaAmount."* The judge weighted the per-tx leak as small and conditional. Our framing ($5k/week at $100M TVL) is plausible but speculative on band width and cadence.

Related but distinct: submission #526 "_withdraw does not charge negative PnL correctly" (High, Valid) addresses a different bug on the same line (`getPnl` uses hardcoded `true` for `usePositionSizeAsSizeDeltaUsd`, returning full-position PnL instead of user's pro-rata share). Our finding does NOT cover #526's root cause.

Self-correction: finding is real and the code location is correct. Appropriate severity per contest judging is **Low**, not Medium.

Source: https://codehawks.cyfrin.io/c/2025-02-gamma/s/1135
