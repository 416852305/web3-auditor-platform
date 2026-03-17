// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

contract InflationVault {
    MockToken public asset;
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = MockToken(_asset);
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        uint256 totalAssets = asset.balanceOf(address(this));
        if (totalShares == 0 || totalAssets == 0) {
            return assets;
        }
        return (assets * totalShares) / totalAssets;
    }

    function deposit(uint256 assets) external {
        require(assets > 0, "zero");
        uint256 shares = previewDeposit(assets);
        require(shares > 0, "Zero shares minted");
        balanceOf[msg.sender] += shares;
        totalShares += shares;
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function withdraw(uint256 shares) external {
        require(balanceOf[msg.sender] >= shares, "shares");
        uint256 assets = (shares * asset.balanceOf(address(this))) / totalShares;
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;
        asset.transfer(msg.sender, assets);
    }
}
