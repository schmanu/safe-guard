// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";

import {SafeGuard} from "../src/SafeGuard.sol";
import {ISafe} from "../src/interfaces/ISafe.sol";

contract MockStorage is ISafe {
    uint256 constant TRANSACTION_GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    function getStorageAt(
        uint256 offset,
        uint256 length
    ) external view returns (bytes memory) {
        if (offset == TRANSACTION_GUARD_STORAGE_SLOT) {
            return abi.encode(msg.sender);
        }

        return abi.encode(address(0));
    }
}

contract SafeGuardTest is Test {
    uint256 constant TRANSACTION_GUARD_STORAGE_SLOT =
        0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    SafeGuard public guard;

    ISafe public safe;

    address token = vm.addr(1);
    address multiSendAddr = vm.addr(2);

    function setUp() public {
        guard = new SafeGuard();
        safe = new MockStorage();

        // Overwrite storage slot to "enable" guard
        bytes32 slot = bytes32(TRANSACTION_GUARD_STORAGE_SLOT);
        vm.store(
            address(safe),
            slot,
            bytes32(bytes20(uint160(address(guard))))
        );
    }

    function test_native_transfer() public {
        SafeGuard.Authorization[]
            memory delegates = new SafeGuard.Authorization[](1);
        delegates[0] = SafeGuard.Authorization({
            addr: multiSendAddr,
            authorized: true
        });

        SafeGuard.Authorization[]
            memory modules = new SafeGuard.Authorization[](0);

        SafeGuard.Authorization[]
            memory transferTargets = new SafeGuard.Authorization[](1);
        transferTargets[0] = SafeGuard.Authorization({
            addr: address(0x123),
            authorized: true
        });

        // Construct the Configuration struct
        SafeGuard.Configuration memory config = SafeGuard.Configuration({
            delegates: delegates,
            modules: modules,
            transferTargets: transferTargets
        });

        // Call initialize function on target contract
        vm.prank(address(safe));
        guard.initialize(config);

        // Benign tx ERC20
        vm.prank(address(safe));
        guard.checkTransaction(
            address(0x123),
            69,
            "",
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );

        // malicious tx
        vm.prank(address(safe));
        vm.expectRevert(
            abi.encodeWithSelector(
                SafeGuard.UnauthorizedTransferCall.selector,
                address(safe),
                address(0xbad)
            )
        );
        guard.checkTransaction(
            address(0xbad),
            420,
            "",
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );
    }

    function test_erc20_transfer() public {
        SafeGuard.Authorization[]
            memory delegates = new SafeGuard.Authorization[](0);

        SafeGuard.Authorization[]
            memory modules = new SafeGuard.Authorization[](0);

        SafeGuard.Authorization[]
            memory transferTargets = new SafeGuard.Authorization[](1);
        transferTargets[0] = SafeGuard.Authorization({
            addr: address(0x123),
            authorized: true
        });

        // Construct the Configuration struct
        SafeGuard.Configuration memory config = SafeGuard.Configuration({
            delegates: delegates,
            modules: modules,
            transferTargets: transferTargets
        });

        // Call initialize function on target contract
        vm.prank(address(safe));
        guard.initialize(config);

        // Try to execute a transfer to the target address
        bytes memory goodData = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0x123),
            uint256(200)
        );

        bytes memory badData = abi.encodeWithSelector(
            bytes4(keccak256("transfer(address,uint256)")),
            address(0xbad),
            uint256(200)
        );
        // Benign tx ERC20
        vm.prank(address(safe));
        guard.checkTransaction(
            token,
            0,
            goodData,
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );

        // malicious tx
        vm.prank(address(safe));
        vm.expectRevert(
            abi.encodeWithSelector(
                SafeGuard.UnauthorizedTransferCall.selector,
                address(safe),
                address(0xbad)
            )
        );
        guard.checkTransaction(
            token,
            0,
            badData,
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );
    }

    function test_erc20_approve() public {
        SafeGuard.Authorization[]
            memory delegates = new SafeGuard.Authorization[](0);

        SafeGuard.Authorization[]
            memory modules = new SafeGuard.Authorization[](0);

        SafeGuard.Authorization[]
            memory transferTargets = new SafeGuard.Authorization[](1);
        transferTargets[0] = SafeGuard.Authorization({
            addr: address(0x123),
            authorized: true
        });

        // Construct the Configuration struct
        SafeGuard.Configuration memory config = SafeGuard.Configuration({
            delegates: delegates,
            modules: modules,
            transferTargets: transferTargets
        });

        // Call initialize function on target contract
        vm.prank(address(safe));
        guard.initialize(config);

        // Try to execute a transfer to the target address
        bytes memory goodData = abi.encodeWithSelector(
            bytes4(keccak256("approve(address,uint256)")),
            address(0x123),
            uint256(200)
        );

        // Try to execute a transfer to the target address
        bytes memory revokeData = abi.encodeWithSelector(
            bytes4(keccak256("approve(address,uint256)")),
            address(0xbad),
            uint256(0)
        );

        bytes memory badData = abi.encodeWithSelector(
            bytes4(keccak256("approve(address,uint256)")),
            address(0xbad),
            uint256(200)
        );
        // Benign approval
        vm.prank(address(safe));
        guard.checkTransaction(
            token,
            0,
            goodData,
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );

        // Revoking any approval is possible
        vm.prank(address(safe));
        guard.checkTransaction(
            token,
            0,
            revokeData,
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );

        // malicious approval
        vm.prank(address(safe));
        vm.expectRevert(
            abi.encodeWithSelector(
                SafeGuard.UnauthorizedTransferCall.selector,
                address(safe),
                address(0xbad)
            )
        );
        guard.checkTransaction(
            token,
            0,
            badData,
            0,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );
    }

    function testMultiSend() public {
        SafeGuard.Authorization[]
            memory delegates = new SafeGuard.Authorization[](1);

        delegates[0] = SafeGuard.Authorization({
            addr: multiSendAddr,
            authorized: true
        });

        SafeGuard.Authorization[]
            memory modules = new SafeGuard.Authorization[](0);

        SafeGuard.Authorization[]
            memory transferTargets = new SafeGuard.Authorization[](1);
        transferTargets[0] = SafeGuard.Authorization({
            addr: address(0x123),
            authorized: true
        });

        // Construct the Configuration struct
        SafeGuard.Configuration memory config = SafeGuard.Configuration({
            delegates: delegates,
            modules: modules,
            transferTargets: transferTargets
        });

        // Call initialize function on target contract
        vm.prank(address(safe));
        guard.initialize(config);

        // Multisend with two native transfers to 0x00..00123
        bytes
            memory nativeTransfers = hex"8d80ff0a000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000001230000000000000000000000000000000000000000000000001bc16d674ec8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001230000000000000000000000000000000000000000000000000de0b6b3a7640000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        bytes
            memory erc20Transfers = hex"8d80ff0a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000132005afe3855358e112b5647b952709e6165e1c1eeee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000000001a4005afe3855358e112b5647b952709e6165e1c1eeee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000000000450000000000000000000000000000";

        // Contains one transfer to a non allow listed address
        bytes
            memory maliciousTransfer = hex"8d80ff0a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000132005afe3855358e112b5647b952709e6165e1c1eeee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000000000000000000000000000000000000000000bad00000000000000000000000000000000000000000000000000000000000001a4005afe3855358e112b5647b952709e6165e1c1eeee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000000000000000000000000000000000000000012300000000000000000000000000000000000000000000000000000000000000450000000000000000000000000000";

        vm.prank(address(safe));
        guard.checkTransaction(
            multiSendAddr,
            0,
            nativeTransfers,
            1,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );

        vm.prank(address(safe));
        guard.checkTransaction(
            multiSendAddr,
            0,
            erc20Transfers,
            1,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );

        vm.prank(address(safe));
        vm.expectRevert(
            abi.encodeWithSelector(
                SafeGuard.UnauthorizedTransferCall.selector,
                address(safe),
                address(0xbad)
            )
        );
        guard.checkTransaction(
            multiSendAddr,
            0,
            maliciousTransfer,
            1,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            payable(address(0)),
            abi.encode(uint8(0)),
            address(0)
        );
    }
}
