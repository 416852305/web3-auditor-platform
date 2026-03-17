// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ShareMath {
    function toShares(uint256 assets, uint256 totalAssets, uint256 totalShares) internal pure returns (uint256) {
        if (assets == 0) return 0;
        if (totalShares == 0 || totalAssets == 0) return assets;
        return (assets * totalShares) / totalAssets;
    }

    function toAssets(uint256 shares, uint256 totalAssets, uint256 totalShares) internal pure returns (uint256) {
        if (shares == 0 || totalShares == 0) return 0;
        return (shares * totalAssets) / totalShares;
    }
}
