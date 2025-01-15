// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../../node_modules/@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract PVETH is ERC20 {
    constructor() ERC20("PVETH", "PETH") {
        _mint(msg.sender, 1e9 * 1e18);
    }
}