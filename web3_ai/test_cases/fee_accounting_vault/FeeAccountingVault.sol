// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

contract FeeAccountingVault {
    MockToken public asset;
    uint256 public totalShares;
    uint256 public pendingFees;
    mapping(address => uint256) public balanceOf;

    constructor(address _asset) {
        asset = MockToken(_asset);
    }

    function totalManagedAssets() public view returns (uint256) {
        return asset.balanceOf(address(this)) + pendingFees;
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        uint256 managed = totalManagedAssets();
        if (totalShares == 0 || managed == 0) return assets;
        return (assets * totalShares) / managed;
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
        uint256 assets = (shares * totalManagedAssets()) / totalShares;
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;
        asset.transfer(msg.sender, assets);
    }

    function reportFees(uint256 amount) external {
        pendingFees += amount;
    }
}
