// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@matterlabs/zksync-contracts/l2/system-contracts/interfaces/IAccount.sol";
import "@matterlabs/zksync-contracts/l2/system-contracts/libraries/TransactionHelper.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
// Used for signature validation
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
// Access ZKsync system contracts for nonce validation via NONCE_HOLDER_SYSTEM_CONTRACT
import "@matterlabs/zksync-contracts/l2/system-contracts/Constants.sol";
// to call non-view function of system contracts
import "@matterlabs/zksync-contracts/l2/system-contracts/libraries/SystemContractsCaller.sol";

import {ValidationData, ValidAfter, ValidUntil, parseValidationData} from "./types/Types.sol";
import {IERC7579Account} from "./interfaces/IERC7579Account.sol";
import {ModuleLib} from "./utils/ModuleLib.sol";
import {
    ValidationManager,
    ValidationMode,
    ValidationId,
    ValidatorLib,
    ValidationType,
    PermissionId,
    PassFlag,
    SKIP_SIGNATURE
} from "./core/ValidationManager.sol";
import {HookManager} from "./core/HookManager.sol";
import {ExecutorManager} from "./core/ExecutorManager.sol";
import {SelectorManager} from "./core/SelectorManager.sol";
import {IModule, IValidator, IHook, IExecutor, IFallback, IPolicy, ISigner} from "./interfaces/IERC7579Modules.sol";
import {EIP712} from "./utils/EIP712.sol";
import {ExecLib, ExecMode, CallType, ExecType, ExecModeSelector, ExecModePayload} from "./utils/ExecLib.sol";
import {
    CALLTYPE_SINGLE,
    CALLTYPE_DELEGATECALL,
    ERC1967_IMPLEMENTATION_SLOT,
    VALIDATION_TYPE_ROOT,
    VALIDATION_TYPE_VALIDATOR,
    VALIDATION_TYPE_PERMISSION,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_POLICY,
    MODULE_TYPE_SIGNER,
    EXECTYPE_TRY,
    EXECTYPE_DEFAULT,
    EXEC_MODE_DEFAULT,
    CALLTYPE_DELEGATECALL,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_STATIC
} from "./types/Constants.sol";



 contract  AAwesomeAccount is IAccount, IERC7579Account, ValidationManager {
    // to get transaction hash
    using TransactionHelper for Transaction;

    // state variable for account owner
    address public owner;

    bytes4 constant EIP1271_SUCCESS_RETURN_VALUE = 0x1626ba7e;

    mapping(bytes32 txHash => IHook) internal executionHook;


    modifier onlyBootloader() {
        require(
            msg.sender == BOOTLOADER_FORMAL_ADDRESS,
            "Only bootloader can call this method"
        );
        // Continue execution if called from the bootloader.
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function validateTransaction(
        bytes32,
        bytes32 ,
        Transaction calldata _transaction
    ) external payable override onlyBootloader returns (bytes4 magic) {

           SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(
                INonceHolder.incrementMinNonceIfEquals,
                (_transaction.nonce)
            )
        );
        magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;

    }

    function _validateTransaction(
        Transaction calldata _transaction
    ) internal returns (bytes4 magic) {
        // Incrementing the nonce of the account.
        // Note, that reserved[0] by convention is currently equal to the nonce passed in the transaction
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(
                INonceHolder.incrementMinNonceIfEquals,
                (_transaction.nonce)
            )
        );

        bytes32 txHash;
        // While the suggested signed hash is usually provided, it is generally
        // not recommended to rely on it to be present, since in the future
        // there may be tx types with no suggested signed hash.

        // ValidationStorage storage vs = _validationStorage();

        // (, ValidationType vType, ValidationId vId) = ValidatorLib.decodeNonce(_transaction.nonce);
        // if (vType == VALIDATION_TYPE_ROOT) {
        //     vId = vs.rootValidator;
        // }
        // ValidationConfig memory vc = vs.validationConfig[vId];
        // // allow when nonce is not revoked or vType is sudo
        // if (vType != VALIDATION_TYPE_ROOT && vc.nonce < vs.validNonceFrom) {
        //     revert InvalidNonce();
        // }
        // IHook execHook = vc.hook;
        // if (address(execHook) == address(0)) {
        //     revert InvalidValidator();
        // }
        // executionHook[txHash] = execHook;

        // if (address(execHook) == address(1)) {
        //     // does not require hook
        //     if (vType != VALIDATION_TYPE_ROOT && !vs.allowedSelectors[vId][bytes4(_transaction.data[0:4])]) {
        //         revert InvalidValidator();
        //     }
        // } else {
        //     // requires hook
        //     if (vType != VALIDATION_TYPE_ROOT && !vs.allowedSelectors[vId][bytes4(_transaction.data[4:8])]) {
        //         revert InvalidValidator();
        //     }
        //     if (bytes4(_transaction.data[0:4]) != this.executeTransaction.selector) {
        //         revert();
        //     }
        // }


        // The fact there is are enough balance for the account
        // should be checked explicitly to prevent user paying for fee for a
        // transaction that wouldn't be included on Ethereum.
        // uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        // require(
        //     totalRequiredBalance <= address(this).balance,
        //     "Not enough balance for fee + value"
        // );

            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;

    }

    function executeTransaction(
        bytes32 _txHash,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        _executeTransaction(_txHash, _transaction);
    }

    function _executeTransaction(bytes32 _txHash, Transaction calldata _transaction) internal {

        bytes memory context;
        IHook hook = executionHook[_txHash];
        if (address(hook) != address(1)) {
            // removed 4bytes selector
            context = _doPreHook(hook, msg.value, _transaction.data[4:]);
        }
        (bool success, bytes memory ret) = ExecLib.executeDelegatecall(address(this), _transaction.data[4:]);
        if (!success) {
            revert();
        }
        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        }

        // if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
        //     uint32 gas = Utils.safeCastToU32(gasleft());

        //     // Note, that the deployer contract can only be called
        //     // with a "systemCall" flag.
        //     SystemContractsCaller.systemCallWithPropagatedRevert(
        //         gas,
        //         to,
        //         value,
        //         data
        //     );
        // } else {
        //     bool success;
        //     assembly {
        //         success := call(
        //             gas(),
        //             to,
        //             value,
        //             add(data, 0x20),
        //             mload(data),
        //             0,
        //             0
        //         )
        //     }
        //     require(success);
        // }
    }

    function executeTransactionFromOutside(
        Transaction calldata _transaction
    ) external payable {
        bytes4 magic = _validateTransaction(_transaction);
        require(magic == ACCOUNT_VALIDATION_SUCCESS_MAGIC, "NOT VALIDATED");
        // _executeTransaction(_txHash,_transaction);
    }
function executeFromExecutor(ExecMode execMode, bytes calldata executionCalldata)
        external
        payable
        returns (bytes[] memory returnData)
    {
        // no modifier needed, checking if msg.sender is registered executor will replace the modifier
        IHook hook = _executorConfig(IExecutor(msg.sender)).hook;
        if (address(hook) == address(0)) {
            revert();
        }
        bytes memory context;
        if (address(hook) != address(1)) {
            context = _doPreHook(hook, msg.value, msg.data);
        }
        returnData = ExecLib.execute(execMode, executionCalldata);
        if (address(hook) != address(1)) {
            _doPostHook(hook, context);
        }
    }

    function execute(ExecMode execMode, bytes calldata executionCalldata) external payable onlyBootloader() {
        ExecLib.execute(execMode, executionCalldata);
    }



    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        ValidationStorage storage vs = _validationStorage();
        (ValidationId vId, bytes calldata sig) = ValidatorLib.decodeSignature(signature);
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_ROOT) {
            vId = vs.rootValidator;
        }
        if (address(vs.validationConfig[vId].hook) == address(0)) {
            revert InvalidValidator();
        }
        if (ValidatorLib.getType(vId) == VALIDATION_TYPE_VALIDATOR) {
            IValidator validator = ValidatorLib.getValidator(vId);
            return validator.isValidSignatureWithSender(msg.sender, _toWrappedHash(hash), sig);
        } else {
            PermissionId pId = ValidatorLib.getPermissionId(vId);
            PassFlag permissionFlag = vs.permissionConfig[pId].permissionFlag;
            if (PassFlag.unwrap(permissionFlag) & PassFlag.unwrap(SKIP_SIGNATURE) != 0) {
                revert PermissionNotAlllowedForSignature();
            }
            return _checkPermissionSignature(pId, msg.sender, hash, sig);
        }
    }

    function payForTransaction(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        bool success = _transaction.payToTheBootloader();
        require(success, "Failed to pay the fee to the operator");
    }


    function installModule(uint256 moduleType, address module, bytes calldata initData)
        external
        payable
        override
        onlyBootloader()
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            ValidationStorage storage vs = _validationStorage();
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            if (vs.validationConfig[vId].nonce == vs.currentNonce) {
                // only increase currentNonce when vId's currentNonce is same
                unchecked {
                    vs.currentNonce++;
                }
            }
            ValidationConfig memory config =
                ValidationConfig({nonce: vs.currentNonce, hook: IHook(address(bytes20(initData[0:20])))});
            bytes calldata validatorData;
            bytes calldata hookData;
            bytes calldata selectorData;
            assembly {
                validatorData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 20)))
                validatorData.length := calldataload(sub(validatorData.offset, 32))
                hookData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 52)))
                hookData.length := calldataload(sub(hookData.offset, 32))
                selectorData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 84)))
                selectorData.length := calldataload(sub(selectorData.offset, 32))
            }
            _installValidation(vId, config, validatorData, hookData);
            if (selectorData.length == 4) {
                // NOTE: we don't allow configure on selector data on v3.1, but using bytes instead of bytes4 for selector data to make sure we are future proof
                _setSelector(vId, bytes4(selectorData[0:4]), true);
            }
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            bytes calldata executorData;
            bytes calldata hookData;
            assembly {
                executorData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 20)))
                executorData.length := calldataload(sub(executorData.offset, 32))
                hookData.offset := add(add(initData.offset, 52), calldataload(add(initData.offset, 52)))
                hookData.length := calldataload(sub(hookData.offset, 32))
            }
            IHook hook = IHook(address(bytes20(initData[0:20])));
            _installExecutor(IExecutor(module), executorData, hook);
            _installHook(hook, hookData);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            bytes calldata selectorData;
            bytes calldata hookData;
            assembly {
                selectorData.offset := add(add(initData.offset, 56), calldataload(add(initData.offset, 24)))
                selectorData.length := calldataload(sub(selectorData.offset, 32))
                hookData.offset := add(add(initData.offset, 56), calldataload(add(initData.offset, 56)))
                hookData.length := calldataload(sub(hookData.offset, 32))
            }
            _installSelector(bytes4(initData[0:4]), module, IHook(address(bytes20(initData[4:24]))), selectorData);
            _installHook(IHook(address(bytes20(initData[4:24]))), hookData);
        } else if (moduleType == MODULE_TYPE_HOOK) {
            // force call onInstall for hook
            // NOTE: for hook, kernel does not support independent hook install,
            // hook is expected to be paired with proper validator/executor/selector
            IHook(module).onInstall(initData);
            emit ModuleInstalled(moduleType, module);
        } else if (moduleType == MODULE_TYPE_POLICY) {
            // force call onInstall for policy
            // NOTE: for policy, kernel does not support independent policy install,
            // policy is expected to be paired with proper permissionId
            // to "ADD" permission, use "installValidations()" function
            IPolicy(module).onInstall(initData);
            emit ModuleInstalled(moduleType, module);
        } else if (moduleType == MODULE_TYPE_SIGNER) {
            // force call onInstall for signer
            // NOTE: for signer, kernel does not support independent signer install,
            // signer is expected to be paired with proper permissionId
            // to "ADD" permission, use "installValidations()" function
            ISigner(module).onInstall(initData);
            emit ModuleInstalled(moduleType, module);
        } else {
            revert();
        }
    }

    function installValidations(
        ValidationId[] calldata vIds,
        ValidationConfig[] memory configs,
        bytes[] calldata validationData,
        bytes[] calldata hookData
    ) external payable onlyBootloader() {
        _installValidations(vIds, configs, validationData, hookData);
    }

    function uninstallValidation(ValidationId vId, bytes calldata deinitData, bytes calldata hookDeinitData)
        external
        payable
        onlyBootloader()
    {
        IHook hook = _uninstallValidation(vId, deinitData);
        _uninstallHook(hook, hookDeinitData);
    }

    function invalidateNonce(uint32 nonce) external payable onlyBootloader() {
        _invalidateNonce(nonce);
    }

    function uninstallModule(uint256 moduleType, address module, bytes calldata deInitData)
        external
        payable
        override
        onlyBootloader()
    {
        if (moduleType == 1) {
            ValidationId vId = ValidatorLib.validatorToIdentifier(IValidator(module));
            _uninstallValidation(vId, deInitData);
        } else if (moduleType == 2) {
            _uninstallExecutor(IExecutor(module), deInitData);
        } else if (moduleType == 3) {
            bytes4 selector = bytes4(deInitData[0:4]);
            _uninstallSelector(selector, deInitData[4:]);
        } else if (moduleType == 4) {
            ValidationId vId = _validationStorage().rootValidator;
            if (_validationStorage().validationConfig[vId].hook == IHook(module)) {
                // when root validator hook is being removed
                // remove hook on root validator to prevent kernel from being locked
                _validationStorage().validationConfig[vId].hook = IHook(address(1));
            }
            // force call onUninstall for hook
            // NOTE: for hook, kernel does not support independent hook install,
            // hook is expected to be paired with proper validator/executor/selector
            ModuleLib.uninstallModule(module, deInitData);
            emit ModuleUninstalled(moduleType, module);
        } else if (moduleType == 5) {
            ValidationId rootValidator = _validationStorage().rootValidator;
            bytes32 permissionId = bytes32(deInitData[0:32]);
            if (ValidatorLib.getType(rootValidator) == VALIDATION_TYPE_PERMISSION) {
                if (permissionId == bytes32(PermissionId.unwrap(ValidatorLib.getPermissionId(rootValidator)))) {
                    revert RootValidatorCannotBeRemoved();
                }
            }
            // force call onUninstall for policy
            // NOTE: for policy, kernel does not support independent policy install,
            // policy is expected to be paired with proper permissionId
            // to "REMOVE" permission, use "uninstallValidation()" function
            ModuleLib.uninstallModule(module, deInitData);
            emit ModuleUninstalled(moduleType, module);
        } else if (moduleType == 6) {
            ValidationId rootValidator = _validationStorage().rootValidator;
            bytes32 permissionId = bytes32(deInitData[0:32]);
            if (ValidatorLib.getType(rootValidator) == VALIDATION_TYPE_PERMISSION) {
                if (permissionId == bytes32(PermissionId.unwrap(ValidatorLib.getPermissionId(rootValidator)))) {
                    revert RootValidatorCannotBeRemoved();
                }
            }
            // force call onUninstall for signer
            // NOTE: for signer, kernel does not support independent signer install,
            // signer is expected to be paired with proper permissionId
            // to "REMOVE" permission, use "uninstallValidation()" function
            ModuleLib.uninstallModule(module, deInitData);
            emit ModuleUninstalled(moduleType, module);
        } else {
            revert();
        }
    }

    function supportsModule(uint256 moduleTypeId) external pure override returns (bool) {
        if (moduleTypeId < 7) {
            return true;
        } else {
            return false;
        }
    }

    function isModuleInstalled(uint256 moduleType, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            return _validationStorage().validationConfig[ValidatorLib.validatorToIdentifier(IValidator(module))].hook
                != IHook(address(0));
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            return address(_executorConfig(IExecutor(module)).hook) != address(0);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            return _selectorConfig(bytes4(additionalContext[0:4])).target == module;
        } else {
            return false;
        }
    }

    function accountId() external pure override returns (string memory accountImplementationId) {
        return "zksync.advanced.v0.0.1";
    }

    function supportsExecutionMode(ExecMode mode) external pure override returns (bool) {
        (CallType callType, ExecType execType, ExecModeSelector selector, ExecModePayload payload) =
            ExecLib.decode(mode);
        if (
            callType != CALLTYPE_BATCH && callType != CALLTYPE_SINGLE && callType != CALLTYPE_DELEGATECALL
                && callType != CALLTYPE_STATIC
        ) {
            return false;
        }

        if (
            ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_TRY)
                && ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)
        ) {
            return false;
        }

        if (ExecModeSelector.unwrap(selector) != ExecModeSelector.unwrap(EXEC_MODE_DEFAULT)) {
            return false;
        }

        if (ExecModePayload.unwrap(payload) != bytes22(0)) {
            return false;
        }
        return true;
    }

    function prepareForPaymaster(
        bytes32, // _txHash
        bytes32, // _suggestedSignedHash
        Transaction calldata _transaction
    ) external payable override onlyBootloader {
        _transaction.processPaymasterInput();
    }

    fallback() external {
        // fallback of default account shouldn't be called by bootloader under no circumstances
        assert(msg.sender != BOOTLOADER_FORMAL_ADDRESS);

        // If the contract is called directly, behave like an EOA
    }

    receive() external payable {
        // If the contract is called directly, behave like an EOA.
        // Note, that is okay if the bootloader sends funds with no calldata as it may be used for refunds/operator payments
    }
}

