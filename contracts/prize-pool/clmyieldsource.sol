pragma solidity 0.8.6;

import "../interfaces/IPrizePool.sol";
import "../interfaces/ICantoLP.sol";
import "@pooltogether/owner-manager-contracts/contracts/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "../interfaces/IComptroller.sol";
import "../interfaces/IUniswapRouter.sol";
/// @title Defines the functions used to interact with a yield source.  The Prize Pool inherits this contract.
/// @notice Prize Pools subclasses need to implement this interface so that yield can be generated.
// opt 1

interface Turnstile {
    function assign(uint256) external returns(uint256);
    function register(address) external returns(uint256);
}


contract clmyieldsource is Ownable{
    using SafeERC20 for IERC20;
    IPrizePool internal prizePool; // prizepool
    IERC20 internal depositTokenT; // canto lp token
    address internal pool; // CantoLP
    address internal token1;
    address internal token2;
    address internal unirouter;
    address internal feeowner;
    uint public protocalFeeRation = 10;
    mapping(address=>uint256) totalDeposit;
    address public output = 0x826551890Dc65655a0Aceca109aB11AbDbD7a07B;
    address constant public comptroller = 0x5E23dC409Fc2F832f83CEc191E245A191a4bCc5C;
    uint constant public MAX_uint256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
    Turnstile turnstile = Turnstile(0xEcf044C5B4b867CFda001101c617eCd347095B44);

    constructor(address _owner, address dpsTokenAddr, address _pool, address _token1, address _token2, address unirouter_) Ownable(_owner) {
        depositTokenT = IERC20(dpsTokenAddr);
        pool = _pool;
        token1 = _token1;
        token2 = _token2;
        feeowner = _owner;
        unirouter = unirouter_;
        _giveAllowances();
    }

    uint public id;
    function registerTurnstile() public {
        require(msg.sender == feeowner);
        id = turnstile.register(tx.origin);
    }

    function assignTurnstile(uint nftid) public {
        require(msg.sender == feeowner);
        id = nftid;
        turnstile.assign(nftid);
    }

    function setProtocalFeeRation(uint t) public {
        require(msg.sender == feeowner);
        require(t > 0 && t < 100, "error t");
        protocalFeeRation = t;
    }

    function _giveAllowances() internal {
        IERC20(output).approve(pool, MAX_uint256);
        IERC20(output).approve(unirouter, MAX_uint256);

        IERC20(depositTokenT).approve(pool, MAX_uint256);
        IERC20(depositTokenT).approve(unirouter, MAX_uint256);


        IERC20(token1).approve(unirouter, MAX_uint256);


        IERC20(token2).approve(unirouter, MAX_uint256);
    }

    event changePrizePoolAddress(address a);
    function setPrizePool(IPrizePool prizePoolAddress) external onlyOwner {
        prizePool = prizePoolAddress;
        emit changePrizePoolAddress(address(prizePoolAddress));
    }

    function msgSenderIsPrizePool() internal {
        assert(msg.sender == address(prizePool));
    }
    /// @notice Returns the ERC20 asset token used for deposits.
    /// @return The ERC20 asset token address.
    function depositToken() external view returns (address) {
        return address(depositTokenT);
    }

    /// @notice Returns the total balance (in asset tokens).  This includes the deposits and interest.
    /// @return The underlying balance of asset tokens.
    function balanceOfToken(address addr) external returns (uint256) {
        msgSenderIsPrizePool();
        if (IComptroller(comptroller).pendingComptrollerImplementation() == address(0)) {
            IComptroller(comptroller).claimComp(address(this));
            uint256 outputBal = IERC20(output).balanceOf(address(this));
            uint256 deltadepositTokens;
            
            if(outputBal > 0)
            {
                uint256 protocalIncome = outputBal * protocalFeeRation / 100;
                if(protocalIncome > 0) {
                    IERC20(output).transfer(feeowner, protocalIncome);
                }
                deltadepositTokens = swapRewards(outputBal - protocalIncome);
                uint remainLP = IERC20(depositTokenT).balanceOf(address(this));
                ICantoLP(pool).mint(remainLP);
                uint remainLP_t = IERC20(depositTokenT).balanceOf(address(this));
                totalDeposit[msg.sender] += (remainLP - remainLP_t);
            }
            return totalDeposit[msg.sender] + deltadepositTokens;
        } else {
            assert(1 == 2);
        }
    }

    uint swapCantoAmount;
    uint remainwCanto;
    uint ownerGasFee;
    function swapRewards(uint outputBal) internal returns (uint256) {
        swapCantoAmount = outputBal / 2;
        remainwCanto = outputBal - swapCantoAmount;
        if(token1 == output)
        {
            uint[] memory amounts2 = IUniswapRouter(unirouter).swapExactTokensForTokensSimple(remainwCanto, 0, output, token2, false, address(this), block.timestamp);
        }else if(token2 == output)
        {
            uint[] memory amounts1 = IUniswapRouter(unirouter).swapExactTokensForTokensSimple(swapCantoAmount, 0, output, token1, false, address(this), block.timestamp);
        }
        else{
            assert(1 == 2);
        }
        return addLiquidity();
    }

    function addLiquidity() internal returns (uint256) {
        uint t1 = IERC20(depositTokenT).balanceOf(address(this));
        IUniswapRouter(unirouter).addLiquidity(token1, token2, false, IERC20(token1).balanceOf(address(this)), IERC20(token2).balanceOf(address(this)), 0, 0, address(this), block.timestamp);
        uint t2 = IERC20(depositTokenT).balanceOf(address(this));
        return t2 - t1;
    }


    function balanceOfWant() public view returns (uint256) {
        return IERC20(depositTokenT).balanceOf(address(this));
    }

    /// @notice Supplies tokens to the yield source.  Allows assets to be supplied on other user's behalf using the `to` param.
    /// @param amount The amount of asset tokens to be supplied.  Denominated in `depositToken()` as above.
    /// @param to The user whose balance will receive the tokens
    function supplyTokenTo(uint256 amount, address to) external{
        msgSenderIsPrizePool();
        
        IERC20(depositTokenT).transferFrom(msg.sender, address(this), amount);
        totalDeposit[msg.sender] += amount;

        ICantoLP(pool).mint(amount);

    }

    /// @notice Redeems tokens from the yield source.
    /// @param amount The amount of asset tokens to withdraw.  Denominated in `depositToken()` as above.
    /// @return The actual amount of interst bearing tokens that were redeemed.
    function redeemToken(uint256 amount) external returns (uint256){
        msgSenderIsPrizePool();
        totalDeposit[msg.sender] -= amount;
        ICantoLP(pool).redeemUnderlying(amount);
        IERC20(depositTokenT).transfer(msg.sender, amount);
        return amount;
    }
}

