// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.20;

import {IERC165} from "./interfaces/IERC165.sol";
import {IModuleGuard} from "./interfaces/IModuleGuard.sol";
import {ISafe, TRANSACTION_GUARD_STORAGE_SLOT} from "./interfaces/ISafe.sol";
import {ITransactionGuard} from "./interfaces/ITransactionGuard.sol";

contract SafeGuard is IModuleGuard, ITransactionGuard {
    struct Account {
        bool initialized;
        bytes32 configurationHash;
        uint256 timelock;
    }

    struct Authorization {
        address addr;
        bool authorized;
    }

    struct Configuration {
        Authorization[] delegates;
        Authorization[] modules;
        Authorization[] transferTargets;
    }

    // ERC20 function selectors
    bytes4 private constant APPROVE_SELECTOR =
        bytes4(keccak256("approve(address,uint256)"));
    bytes4 private constant TRANSFER_SELECTOR =
        bytes4(keccak256("transfer(address,uint256)"));
    bytes4 private constant MULTISEND_SELECTOR =
        bytes4(keccak256("multiSend(bytes)"));

    uint256 public constant TIMELOCK = 7 days;
    bytes32 public constant DISABLE =
        bytes32(uint256(keccak256("disable")) - 1);

    mapping(address safe => Account account) public accounts;
    mapping(address delegate => mapping(address safe => bool authorized))
        public delegates;
    mapping(address module => mapping(address safe => bool authorized))
        public modules;
    mapping(address transferTarget => mapping(address safe => bool authorized))
        public transferTargets;

    event Initialized(address indexed safe);
    event Configured(address indexed safe, bytes32 configurationHash);
    event DelegateAuthorization(
        address indexed safe,
        address indexed delegate,
        bool authorized
    );
    event ModuleAuthorization(
        address indexed safe,
        address indexed module,
        bool authorized
    );
    event TransferAuthorization(
        address indexed safe,
        address indexed transferTarget,
        bool authorized
    );
    event ConfigurationScheduled(
        address indexed safe,
        bytes32 configurationHash,
        uint256 timelock
    );
    event DisableScheduled(address indexed safe, uint256 timelock);

    error NotEnabled(address safe);
    error AlreadyInitialized(address safe);
    error NotInitialized(address safe);
    error UnauthorizedDelegateCall(address safe, address to);
    error UnauthorizedTransferCall(address safe, address to);
    error UnauthorizedModule(address safe, address module);
    error UnauthorizedConfiguration(address safe, bytes32 configurationHash);
    error UnauthorizedDisable(address safe);
    error InvalidMultisendData();

    function initialize(Configuration calldata configuration) external {
        if (!_isEnabled(msg.sender)) {
            revert NotEnabled(msg.sender);
        }

        Account storage account = accounts[msg.sender];
        if (accounts[msg.sender].initialized) {
            revert AlreadyInitialized(msg.sender);
        }

        account.initialized = true;
        account.configurationHash = bytes32(0);
        account.timelock = 0;

        _applyConfiguration(configuration);
        emit Initialized(msg.sender);
    }

    function configure(Configuration calldata configuration) external {
        bytes32 configurationHash = keccak256(abi.encode(configuration));

        Account storage account = accounts[msg.sender];
        if (
            account.configurationHash != configurationHash ||
            account.timelock > block.timestamp
        ) {
            revert UnauthorizedConfiguration(msg.sender, configurationHash);
        }

        account.configurationHash = bytes32(0);
        account.timelock = 0;

        _applyConfiguration(configuration);
        emit Configured(msg.sender, configurationHash);
    }

    function scheduleConfiguration(bytes32 configurationHash) external {
        Account storage account = accounts[msg.sender];
        if (!account.initialized) {
            revert NotInitialized(msg.sender);
        }

        uint256 timelock = block.timestamp + TIMELOCK;
        account.configurationHash = configurationHash;
        account.timelock = timelock;

        emit ConfigurationScheduled(msg.sender, configurationHash, timelock);
    }

    function scheduleDisabling() external {
        Account storage account = accounts[msg.sender];
        if (!account.initialized) {
            revert NotInitialized(msg.sender);
        }

        uint256 timelock = block.timestamp + TIMELOCK;
        account.configurationHash = DISABLE;
        account.timelock = timelock;

        emit DisableScheduled(msg.sender, timelock);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) external pure returns (bool supported) {
        supported =
            interfaceId == type(IERC165).interfaceId ||
            interfaceId == type(IModuleGuard).interfaceId ||
            interfaceId == type(ITransactionGuard).interfaceId;
    }

    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        address module
    ) external returns (bytes32) {
        _checkTransaction(msg.sender, to, data, value, operation);
        if (!modules[msg.sender][module]) {
            revert UnauthorizedModule(msg.sender, module);
        }
        return bytes32(0);
    }

    function checkAfterModuleExecution(bytes32, bool) external {
        _checkAfterExecution(msg.sender);
    }

    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes calldata,
        address
    ) external {
        _checkTransaction(msg.sender, to, data, value, operation);
    }

    function checkAfterExecution(bytes32, bool) external {
        _checkAfterExecution(msg.sender);
    }

    function _applyConfiguration(
        Configuration calldata configuration
    ) internal {
        for (uint256 i = 0; i < configuration.delegates.length; i++) {
            Authorization calldata delegate = configuration.delegates[i];
            delegates[msg.sender][delegate.addr] = delegate.authorized;
            emit DelegateAuthorization(
                msg.sender,
                delegate.addr,
                delegate.authorized
            );
        }
        for (uint256 i = 0; i < configuration.modules.length; i++) {
            Authorization calldata module = configuration.modules[i];
            modules[msg.sender][module.addr] = module.authorized;
            emit ModuleAuthorization(
                msg.sender,
                module.addr,
                module.authorized
            );
        }

        for (uint256 i = 0; i < configuration.transferTargets.length; i++) {
            Authorization calldata transferTarget = configuration
                .transferTargets[i];
            transferTargets[msg.sender][transferTarget.addr] = transferTarget
                .authorized;
            emit TransferAuthorization(
                msg.sender,
                transferTarget.addr,
                transferTarget.authorized
            );
        }
    }

    function _isEnabled(address safe) internal view returns (bool enabled) {
        address transactionGuard = abi.decode(
            ISafe(safe).getStorageAt(TRANSACTION_GUARD_STORAGE_SLOT, 1),
            (address)
        );
        enabled = transactionGuard == address(this);
    }

    function _checkTransaction(
        address safe,
        address to,
        bytes calldata data,
        uint256 value,
        uint8 operation
    ) internal {
        Account storage account = accounts[safe];
        if (account.initialized) {
            // Check delegate calls
            if (operation == 1 && !delegates[safe][to]) {
                revert UnauthorizedDelegateCall(safe, to);
            }

            // Check transfer function
            if (_isApproveOrTransfer(data)) {
                (
                    address erc20To,
                    uint256 erc20Value
                ) = _decodeApproveOrTransfer(data);
                if (erc20Value > 0 && !transferTargets[safe][erc20To]) {
                    revert UnauthorizedTransferCall(safe, erc20To);
                }
            }

            if (value > 0 && !transferTargets[safe][to]) {
                revert UnauthorizedTransferCall(safe, to);
            }

            // decode multiSend and call _checkTransaction recursively
            if (operation == 1 && _isMultiSend(data)) {
                // decode data
                bytes memory transactions = abi.decode(
                    data[4:data.length],
                    (bytes)
                );
                this._checkMultiSend(safe, transactions);
            }
        }
    }

    function _checkAfterExecution(address safe) internal {
        if (!_isEnabled(safe)) {
            Account storage account = accounts[safe];
            if (
                (account.initialized && account.configurationHash != DISABLE) ||
                account.timelock > block.timestamp
            ) {
                revert UnauthorizedDisable(safe);
            }

            account.initialized = false;
            account.configurationHash = bytes32(0);
            account.timelock = 0;
        }
    }

    function _isApproveOrTransfer(
        bytes calldata data
    ) internal pure returns (bool) {
        if (data.length < 4) {
            return false; // Not enough data to contain a function selector
        }

        bytes4 selector = bytes4(data[0:4]);
        return selector == APPROVE_SELECTOR || selector == TRANSFER_SELECTOR;
    }

    function _isMultiSend(bytes calldata data) internal pure returns (bool) {
        if (data.length < 4) {
            return false; // Not enough data to contain a function selector
        }
        bytes4 selector = bytes4(data[0:4]);
        return selector == MULTISEND_SELECTOR;
    }

    function _checkMultiSend(address safe, bytes calldata transactions) public {
        // Iterate over transactions
        uint256 length = transactions.length;
        uint256 i = 0;

        while (i < length) {
            if (length < i + 85) {
                revert InvalidMultisendData();
            }
            uint8 operation = uint8(bytes1(transactions[i:(i + 1)]));

            address to = address(bytes20(transactions[(i + 1):(i + 21)]));
            uint256 value = uint256(bytes32(transactions[(i + 21):(i + 53)]));
            uint256 dataLength = uint256(
                bytes32(transactions[(i + 53):(i + 85)])
            );
            bytes calldata data = transactions[(i + 85):(i + 85 + dataLength)];

            _checkTransaction(safe, to, data, value, operation);

            i = i + 85 + dataLength;
        }
    }

    function _decodeApproveOrTransfer(
        bytes calldata data
    ) internal pure returns (address, uint256) {
        require(data.length == 4 + 32 + 32, "Invalid data length");

        bytes4 selector;
        address recipient;
        uint256 amount;

        assembly {
            selector := calldataload(data.offset)
            recipient := calldataload(add(data.offset, 4))
            amount := calldataload(add(data.offset, 36))
        }

        require(
            selector == APPROVE_SELECTOR || selector == TRANSFER_SELECTOR,
            "Invalid function selector"
        );
        return (recipient, amount);
    }
}
