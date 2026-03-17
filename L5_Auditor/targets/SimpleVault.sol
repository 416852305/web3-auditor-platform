// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MockToken.sol";

contract SimpleVault {
    MockToken public asset;
    
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf; // 用户持有的股份

    constructor(address _asset) {
        asset = MockToken(_asset);
    }

    // 🔴 存款函数 (含通胀攻击漏洞)
    // Invariant (应通过Fuzzing验证): deposit(x) 应该至少给你 1 share (如果 x 足够大)
    function deposit(uint256 assets) public {
        require(assets > 0, "Deposit must be > 0");

        // 1. 计算当前的资产总额
        uint256 totalAssets = asset.balanceOf(address(this));
        uint256 shares = 0;

        // 2. 计算应得的股份
        if (totalShares == 0) {
            shares = assets;
        } else {
            // 漏洞公式：(assets * totalShares) / totalAssets
            // 如果攻击者先存 1 wei，获得 1 share。
            // 然后攻击者直接给合约转入 100 ETH。此时 totalAssets = 100 ETH + 1 wei。
            // 下一个用户存入 20 ETH。
            // shares = (20 ETH * 1) / (100 ETH) = 0
            // 用户失去了 20 ETH，却得到了 0 shares。
            shares = (assets * totalShares) / totalAssets;
        }

        require(shares > 0, "Zero shares minted"); // 虽然有检查，但攻击者可以控制边界

        // 3. 铸造股份
        _mint(msg.sender, shares);

        // 4. 转移资产
        // 注意：这里是在计算完 shares 之后才转入资产，这是对的。
        // 但是依赖 `asset.balanceOf(this)` 本身就是风险。
        asset.transferFrom(msg.sender, address(this), assets);
    }

    function withdraw(uint256 shares) public {
        require(shares > 0, "Withdraw must be > 0");
        require(balanceOf[msg.sender] >= shares, "Insufficient shares");

        uint256 totalAssets = asset.balanceOf(address(this));
        
        // 计算应赎回的资产
        uint256 amount = (shares * totalAssets) / totalShares;

        _burn(msg.sender, shares);
        asset.transfer(msg.sender, amount);
    }

    function _mint(address to, uint256 amount) internal {
        balanceOf[to] += amount;
        totalShares += amount;
    }

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        totalShares -= amount;
    }
}
