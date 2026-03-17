# Template Coverage

This file documents the deterministic verification templates currently available in `L5_Auditor`.

## Current Templates

### `delegatecall_vault`

Matched when the target looks like:

- vault/module architecture
- public or weak module update path
- `delegatecall` execution path

Typical issues covered:

- unrestricted module change
- unrestricted delegatecall
- owner takeover via delegatecall
- module-based fee/accounting corruption

### `inflation_vault`

Matched when the target looks like:

- vault with `totalShares`
- share math based on current assets
- `Zero shares minted` style rounding protection

Typical issues covered:

- first depositor inflation
- direct donation share dilution
- zero-share rounding griefing

### `reentrancy_bank`

Matched when the target looks like:

- payable `deposit()`
- `withdraw()`
- low-level ETH send before state reset

Typical issues covered:

- classic reentrancy drain

### `owner_takeover`

Matched when the target looks like:

- `owner` storage
- unrestricted owner-changing function
- privileged sweep/admin function

Typical issues covered:

- ownership takeover
- post-takeover emergency drain

### `fee_accounting_vault`

Matched when the target looks like:

- `pendingFees`
- `totalManagedAssets`
- fee reporting without actual token transfer

Typical issues covered:

- synthetic fee inflation
- depositor dilution
- withdrawal insolvency

## Decision Model

Verification generation now uses this order:

1. Open-ended analysis discovers vulnerabilities and invariants.
2. The system tries to match a deterministic template family.
3. If matched, it generates a fixed template-backed Foundry suite.
4. If not matched, it falls back to general LLM generation.

Templates improve:

- compile reliability
- exploit test stability
- invariant handler discipline
- verification pass rate

## What Still Falls Back To LLM

Anything outside the template families above still falls back to general generation, for example:

- unusual liquidation logic
- auction settlement bugs
- AMM math edge cases not yet templated
- cross-chain bridge accounting bugs
- governance-specific execution flaws
- custom proxy upgrade bugs outside the current vault/module pattern

## Practical Interpretation

The system does not require every vulnerable contract to fit a template in order to be audited.

Templates only affect the verification layer.

- Detection is still open-ended.
- Templates make verification deterministic for known families.
- Unknown families still get analyzed and may still get LLM-generated suites.

## Suggested Next Template Families

- `erc4626_accounting`
- `governance_takeover`
- `oracle_manipulation`
- `liquidation_logic`
- `upgradeable_proxy_admin_takeover`
