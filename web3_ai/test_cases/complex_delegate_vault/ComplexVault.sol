// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";
import "./ShareMath.sol";
import "./VaultStorage.sol";

contract ComplexVault is VaultStorage {
    using ShareMath for uint256;

    event Deposit(address indexed user, uint256 assets, uint256 shares);
    event Withdraw(address indexed user, uint256 shares, uint256 assets);
    event ModuleUpdated(address indexed newModule);
    event ModuleExecuted(bytes data, bytes result);
    event Sweep(address indexed to, uint256 amount);

    constructor(address _asset, address _module) {
        asset = MockToken(_asset);
        owner = msg.sender;
        module = _module;
        lastReport = block.timestamp;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function totalManagedAssets() public view returns (uint256) {
        return asset.balanceOf(address(this)) + pendingFees;
    }

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return ShareMath.toShares(assets, totalManagedAssets(), totalShares);
    }

    function deposit(uint256 assets) external {
        require(!paused, "paused");
        require(assets > 0, "zero");

        uint256 shares = previewDeposit(assets);
        require(shares > 0, "Zero shares minted");

        balanceOf[msg.sender] += shares;
        totalShares += shares;

        require(asset.transferFrom(msg.sender, address(this), assets), "transferFrom");
        emit Deposit(msg.sender, assets, shares);
    }

    function withdraw(uint256 shares) external {
        require(shares > 0, "zero");
        require(balanceOf[msg.sender] >= shares, "shares");

        uint256 assets = ShareMath.toAssets(shares, totalManagedAssets(), totalShares);
        balanceOf[msg.sender] -= shares;
        totalShares -= shares;

        require(asset.transfer(msg.sender, assets), "transfer");
        emit Withdraw(msg.sender, shares, assets);
    }

    function setModule(address newModule) external {
        module = newModule;
        emit ModuleUpdated(newModule);
    }

    function executeModule(bytes calldata data) external returns (bytes memory result) {
        (bool ok, bytes memory ret) = module.delegatecall(data);
        require(ok, "delegatecall failed");
        emit ModuleExecuted(data, ret);
        return ret;
    }

    function emergencySweep(address to, uint256 amount) external onlyOwner {
        require(asset.transfer(to, amount), "transfer");
        emit Sweep(to, amount);
    }

    function setPaused(bool isPaused) external onlyOwner {
        paused = isPaused;
    }
}
