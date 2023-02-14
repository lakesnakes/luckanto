pragma solidity 0.8.6;

interface Turnstile {
    function register(address) external returns(uint256);
    function assign(uint256) external returns(uint256);
}