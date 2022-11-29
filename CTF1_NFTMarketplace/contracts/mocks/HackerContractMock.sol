// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

interface NFTMarketPlaceI {
    function bid(uint256 nftId) external payable;
}

// Null contract we need to handle failing callbacks
contract HackerContract {

    // Do not accept any Ether back
    fallback(bytes calldata) external payable returns (bytes memory) {
        revert("FAIL");
    }

    function bid(address nftMarketPlace, uint256 nftId) external payable {
        NFTMarketPlaceI marketplace = NFTMarketPlaceI(nftMarketPlace);
        marketplace.bid{value: msg.value}(nftId);
    }
}