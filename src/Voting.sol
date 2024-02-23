// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.6;

interface iVerifier {
    function verifyProof(
        uint[2] calldata _pA, 
        uint[2][2] calldata _pB, 
        uint[2] calldata _pC, 
        uint[2] calldata _pubSignals
    ) external view returns (bool);
}

/// @title A contract that handles candidates to participate
/// @author Yarix
/// @notice Use it on your own risk
/// @dev It checks ZK proof via call to verifier contract
contract voucherHandler{
    address public _owner;
    uint256 public _ownerCooldown;

    iVerifier public _verifier;

    uint256 constant _minOwnerCooldown = 3 days;
    uint256 constant _maxOwnerCooldown = 4 weeks;

    uint256 public VOUCHERS_REQUIRED;

    struct Participant {
        bool verified;
        bytes32[] vouchers;
    }

    struct pendingOwner {
        uint256 changeOwnerTimestamp;
        address newOwner;
    }

    pendingOwner public _pendingOwner;

    mapping(address => Participant) public _participants;

    constructor(uint256 newOwnerCooldown, uint256 newVouchersRequired, address newVerifier){
        _owner = msg.sender;

        require(newOwnerCooldown >= _minOwnerCooldown, "Too low cooldown!");
        require(newOwnerCooldown <= _maxOwnerCooldown, "Too hight cooldown!");
        _ownerCooldown = newOwnerCooldown;

        require(newVouchersRequired > 0, "Vouchers required must be greater than zero");
        VOUCHERS_REQUIRED = newVouchersRequired;

        require(newVerifier != address(0), "Verifier contract must be existed");
        _verifier = iVerifier(newVerifier);
    }

    modifier onlyOwner(){
        checkOwner();
        _;
    }

    function checkOwner() internal view {
        require(msg.sender == _owner, "Not owner");
    }

    function changeVerifier(address newVerifier) public onlyOwner returns(address){
        require(newVerifier != address(0), "Verifier contract must be existed");
        require(newVerifier != address(_verifier), "That verifier is already in use");
        _verifier = iVerifier(newVerifier);
        return address(_verifier);
    }

    function changeRequiredVouchers(uint256 newVouchersRequired) public onlyOwner returns(uint256){
        require(newVouchersRequired > 0, "Vouchers required must be greater than zero");
        require(newVouchersRequired != VOUCHERS_REQUIRED, "New vouchers required must not be equal the old one");
        VOUCHERS_REQUIRED = newVouchersRequired;
        return VOUCHERS_REQUIRED;
    }

    /// @notice Starts the change owner process
    /// @param newOwner an address who to be a new owner
    function startChangeOwner(address newOwner) public onlyOwner {
        require(_pendingOwner.newOwner == address(0), "Owner is already under change process");
        require(newOwner != address(0), "New owner must not be equal zero");
        require(newOwner != _owner, "New owner must not be equal old owner");
        _pendingOwner.changeOwnerTimestamp = block.timestamp;
        _pendingOwner.newOwner = newOwner;
    }

    /// @notice Finishes the change process, write down a new owner
    /// @return Address of a new owner of the contract
    function finishChangeOwner() public returns(address){
        require(_pendingOwner.newOwner == msg.sender, "not pending owner!");
        require(_pendingOwner.changeOwnerTimestamp + _ownerCooldown < block.timestamp, "Cooldown!");
        _owner = _pendingOwner.newOwner;

        _pendingOwner.newOwner = address(0);
        _pendingOwner.changeOwnerTimestamp = 0;
        return _owner;
    }

    /// @notice Reverts changing owner process
    function revertChangeOwner() public onlyOwner {
        require(block.timestamp < _pendingOwner.changeOwnerTimestamp + _ownerCooldown, "Cooldown is finished or not started");
        _pendingOwner.newOwner = address(0);
        _pendingOwner.changeOwnerTimestamp = 0;
    }

    /// @notice Store anonymous voucher to msg.sender storage
    function handleNewVoucher(
        uint[2] calldata _pA, 
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        bytes32 _voucher
    ) external returns(uint256){
        return handleNewVoucherFor(
        _pA, 
        _pB,
        _pC,
        _voucher,
        msg.sender
        );
    }

    /// @notice Store anonymous voucher to candidate's storage
    /// @dev This function takes verification key params, candidate's address and voucher
    /// @dev then calls the verifier contract and puts all those params
    /// @dev Then it checks if result is returned by the verifier is true
    function handleNewVoucherFor(
        uint[2] calldata _pA, 
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        bytes32 _voucher,
        address _candidate
        ) public returns(uint256){
        require(!_participants[_candidate].verified, "Candidate is already verified");
        bytes32[] memory vouchers = _participants[_candidate].vouchers;

        for(uint256 i = 0; i < vouchers.length; i++){
            if(vouchers[i] == _voucher) revert("Voucher is already exist");
        }
        uint[2] memory pubSignals;
        pubSignals[0] = uint(uint160(_candidate));
        pubSignals[1] = uint(_voucher);

        (bool success, bytes memory data) = address(_verifier).call(
            abi.encodeWithSignature(
                "verifyProof(uint[2],uint[2][2],uint[2],uint[1])", 
                _pA,
                _pB,
                _pC,
                pubSignals)
        );

        _participants[_candidate].vouchers.push(_voucher);

        if (success) {
            return _participants[_candidate].vouchers.length;
        } else {
            if (data.length > 0) {
                assembly {
                    let returndata_size := mload(data)
                    revert(add(32, data), returndata_size)
                }
            } else {
                revert("Call to verifier is failed");
            }
        }
    }

    /// @notice Make a candidate turned to participant
    /// @dev It checks if candidate has enough vouchers to became a particapant
    function getVerified() public returns(bool){
        Participant memory p = _participants[msg.sender];
        require(p.vouchers.length >= VOUCHERS_REQUIRED, "Not enough vouchers");
        require(!p.verified, "Already verified");
        p.verified = true;
        _participants[msg.sender].verified = p.verified;
        return p.verified;
    }
}