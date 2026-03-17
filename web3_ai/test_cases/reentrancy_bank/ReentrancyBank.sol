// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrancyBank {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "empty");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balanceOf[msg.sender] = 0;
    }
}
