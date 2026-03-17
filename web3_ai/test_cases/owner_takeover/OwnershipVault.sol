// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

contract OwnershipVault {
    MockToken public asset;
    address public owner;
    mapping(address => uint256) public deposits;

    constructor(address _asset) {
        asset = MockToken(_asset);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        deposits[msg.sender] += amount;
        asset.transferFrom(msg.sender, address(this), amount);
    }

    function claimOwnership(address newOwner) external {
        owner = newOwner;
    }

    function emergencySweep(address to, uint256 amount) external onlyOwner {
        asset.transfer(to, amount);
    }
}
