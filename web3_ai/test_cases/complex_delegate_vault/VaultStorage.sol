// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

abstract contract VaultStorage {
    MockToken public asset;
    address public owner;
    address public module;
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;
    uint256 public pendingFees;
    bool public paused;
    uint256 public lastReport;
}
