// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./VaultStorage.sol";

contract YieldModule is VaultStorage {
    event FeesAccrued(uint256 amount);
    event DrawdownProtected(uint256 lossBps);

    function accrueFees(uint256 amount) external {
        pendingFees += amount;
        lastReport = block.timestamp;
        emit FeesAccrued(amount);
    }

    function pauseOnLargeDrawdown(uint256 lossBps) external {
        if (lossBps > 500) {
            paused = true;
        }
        emit DrawdownProtected(lossBps);
    }
}
