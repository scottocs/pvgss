pragma solidity ^0.8.0;



interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint);
}

contract Dex
{
	// p = p(u) = 36u^4 + 36u^3 + 24u^2 + 6u + 1
    uint256 constant FIELD_ORDER = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // Number of elements in the field (often called `q`)
    // n = n(u) = 36u^4 + 36u^3 + 18u^2 + 6u + 1
    uint256 constant GEN_ORDER = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    uint256 constant CURVE_B = 3;
    // a = (p+1) / 4
    uint256 constant CURVE_A = 0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52;
	struct G1Point {
		uint X;
		uint Y;
	}

	// Encoding of field elements is: X[0] * z + X[1]
	struct G2Point {
		uint[2] X;
		uint[2] Y;
	}

    //Generator
    G1Point G1 = G1Point(1, 2);
    G2Point G2 = G2Point(
        [11559732032986387107991004021392285783925812861821192530917403151452391805634,
        10857046999023057135944570762232829481370756359578518086990519993285655852781],
        [4082367875863433681332203403145435568316851327593401208105741076214120093531,
        8495653923123431417604973247489272438418190587263600148770280649306958101930]
    );

	/// return the sum of two points of G1
	function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
		}
		require(success);
	}

	/// return the product of a point on G1 and a scalar, i.e.
	/// p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
	function g1mul(G1Point memory p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
		}
		require (success);
	}

	/// return the result of computing the pairing check
	/// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
	/// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
	/// return true.
	function pairing(G1Point[] memory p1, G2Point[] memory p2) view internal returns (bool) {
		require(p1.length == p2.length);
		uint elements = p1.length;
		uint inputSize = elements * 6;
		uint[] memory input = new uint[](inputSize);
		for (uint i = 0; i < elements; i++)
		{
			input[i * 6 + 0] = p1[i].X;
			input[i * 6 + 1] = p1[i].Y;
			input[i * 6 + 2] = p2[i].X[0];
			input[i * 6 + 3] = p2[i].X[1];
			input[i * 6 + 4] = p2[i].Y[0];
			input[i * 6 + 5] = p2[i].Y[1];
		}
		uint[1] memory out;
		bool success;
		assembly {
			success := staticcall(sub(gas()	, 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
		}
		require(success);
		return out[0] != 0;
	}

	/// Convenience method for a pairing check for two pairs.
	function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](2);
		G2Point[] memory p2 = new G2Point[](2);
		p1[0] = a1;
		p1[1] = b1;
		p2[0] = a2;
		p2[1] = b2;
		return pairing(p1, p2);
	}
	
	uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    /**
     * @notice Get the field modulus
     * @return The field modulus
     */
    function GetFieldModulus() public pure returns (uint256) {
        return FIELD_MODULUS;
    }

    function submod2(uint256 a, uint256 b, uint256 n) internal pure returns (uint256) {
        return addmod(a, n - b, n);
    }

    function _modInv(uint256 a, uint256 n) internal view returns (uint256 result) {
        bool success;
        assembly {
            let freemem := mload(0x40)
            mstore(freemem, 0x20)
            mstore(add(freemem,0x20), 0x20)
            mstore(add(freemem,0x40), 0x20)
            mstore(add(freemem,0x60), a)
            mstore(add(freemem,0x80), sub(n, 2))
            mstore(add(freemem,0xA0), n)
            success := staticcall(sub(gas(), 2000), 5, freemem, 0xC0, freemem, 0x20)
            result := mload(freemem)
        }
        require(success);
    }

	function equals(
			G1Point memory a, G1Point memory b			
	) view internal returns (bool) {		
		return a.X==b.X && a.Y==b.Y;
	}

	function negate(G1Point memory p) public payable returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    }

    function g1PointToBytes32(G1Point memory point) internal pure returns (bytes32) {
        return keccak256(abi.encode(point.X, point.Y));
    }
    struct Node {
        bool IsLeaf;
        uint256[] Children; // Child nodes ID
        uint256 Childrennum; // Child nodes numbers
        uint256 T; //Threshold
        uint256 Idx; //The local index of the node under its parent
    }

    struct Prf {
        G1Point[] Cp;
        uint256 Xc;
        uint256 Shat;
        uint256[] ShatArray;
    }

    bool[] VerifyResult;
    bool[] KeyVerifyResult;

    Prf prf;

    mapping(uint256 => Node) public nodes;
    uint256[] public XChildId;
    uint256[] public rootChildId;

    // ===== Node =====
    function CreatePath(uint256 n, uint256 t, uint256 flag) public payable {
        // root
        createNode(0, 0, false, 3, 2);
        // A
        createNode(0, 1, true, 0, 1);
        // B
        createNode(0, 2, true, 0, 1);
        // X t of n
        createNode(0, 3, false, n, t);
        XChildId = new uint256[](n);
        for(uint256 i = 0; i < n; i++) {
            XChildId[i] = i+1;
            createNode(3, i+1, true, 0, 1);
        }
        // add child nodes for X
        addChild(3, XChildId);
        // add child nodes for root
        rootChildId = new uint256[](2);
        if (flag == 1) { //A and B
            rootChildId[0] = 1;
            rootChildId[1] = 2;
            addChild(0, rootChildId);
        } 
        else if (flag == 2) { // A and Watchers
            rootChildId[0] = 1;
            rootChildId[1] = 3;
            addChild(0, rootChildId);
        }
        else if (flag == 3) {
            rootChildId[0] = 2;
            rootChildId[1] = 3;
            addChild(0, rootChildId);
        }
    }
    // Create a node
    function createNode(uint256 parentIdx, uint256 idx, bool isLeaf, uint256 childNum, uint256 t) public payable {
        // Node's ID = parents' ID * 100 + child's ID
        uint256 nodeId = parentIdx * 100 + idx;
        Node storage newNode = nodes[nodeId];
        newNode.IsLeaf = isLeaf;
        newNode.Childrennum = childNum;
        newNode.T = t;
        newNode.Idx = idx;
    }

    // add child nodes for some node
    function addChild(uint256 parentIdx,uint256[] memory childIdxs) public payable {
        uint256 parentNodeId = parentIdx;
        require(nodes[parentNodeId].Childrennum >= childIdxs.length,"Too many child");
        Node storage parentNode = nodes[parentNodeId];
        for (uint256 i = 0; i < childIdxs.length; i++) {
            uint256 childNodeId = parentIdx * 100 + childIdxs[i];
            parentNode.Children.push(childNodeId);
        }
    }

    // ===== SSS and GSS =====
    function evaluatePolynomial(uint256 x,uint256[] memory coefficients) internal returns (uint256) {
        uint256 result = coefficients[0]; 
        uint256 xPower = x;
        for (uint256 i = 1; i < coefficients.length; i++) {
            uint256 term = mulmod(coefficients[i], xPower, GEN_ORDER);

            result = addmod(result, term, GEN_ORDER);
            
            // xPoewr = x^i
            xPower = mulmod(xPower, x, GEN_ORDER);
        }
        return result;
    }

    function PrecomputeLagrangeCoefficients(uint256[] memory I) internal view returns (uint256[] memory) {
        uint256 k = I.length;
        uint256[] memory lambdas = new uint256[](k);
        // Compute all Lagrange coefficients
        for(uint256 i = 0; i < k; i++) {
            uint256 lambda_i = 1;
            for(uint256 j = 0; j < k; j++) {
                if(i != j) {
                    uint256 num = I[j]; // Negate I[j] modulo ORDER
                    uint256 den = submod2(I[j], I[i], GEN_ORDER);
                    // compute modular inverse of den
                    uint256 den_inv = _modInv(den,GEN_ORDER);
                    lambda_i = mulmod(lambda_i, num, GEN_ORDER);
                    lambda_i = mulmod(lambda_i, den_inv, GEN_ORDER);
                }
            }
            lambdas[i] = lambda_i;
        }
        return lambdas;
    }

    function SSSRecon(uint256[] memory Q, uint256[] memory I) internal view returns (uint256 secret) {
        uint256 k = I.length;
        uint256[] memory lambdas = new uint256[](k);
        lambdas = PrecomputeLagrangeCoefficients(I);
        uint256 secret = 0;
        for(uint256 i = 0; i < k; i++) {
            uint256 lambda_i = lambdas[i];
            uint256 temp = mulmod(Q[i], lambda_i, GEN_ORDER);
            secret = addmod(secret, temp, GEN_ORDER);
        }
        return secret;
    }

    function GSSRecon(uint256 nodeId,uint256[] memory Q, uint256 startIdx) public view returns (uint256, uint256) {
        // get current node
        Node storage AA = nodes[nodeId];

        if(AA.IsLeaf) {
            return (Q[startIdx],AA.Idx);
        }
        // child nodes
        uint256[] memory childShares = new uint256[](AA.T);
        uint256[] memory childIdx = new uint256[](AA.T);

        for(uint256 i = 0; i < AA.T; i++) {
            uint256 childNodeId = AA.Children[i];
            uint256 share;
            uint256 childIdxValue;
            (share,childIdxValue) = GSSRecon(childNodeId, Q, startIdx + i);

            childShares[i] = share;
            childIdx[i] = childIdxValue;
        }
        require(childShares.length >= AA.T,"Insuficient shares for reconstruction");

        return (SSSRecon(childShares, childIdx),AA.Idx);
    }

    function PVGSSVerify(G1Point[] memory C,G1Point[] memory PK, uint256[] memory I) public payable returns (bool) {
        uint256 nodeId = 0;
        uint256 startIdx = 0;
        uint256[] memory Q = new uint256[](I.length);
        for(uint256 i = 0; i < I.length; i++) {
            Q[i] = prf.ShatArray[I[i]];
        }
        for(uint i = 0; i < prf.ShatArray.length;i++) {
            G1Point memory left = prf.Cp[i];
            G1Point memory temp1 = g1mul(C[i],prf.Xc);
            G1Point memory temp2 = g1mul(PK[i],prf.ShatArray[i]);
            G1Point memory right = g1add(temp1,temp2);
            if (!equals(left,right)) {
                VerifyResult.push(false);
                return false;
            }
            (uint256 recovershat, uint256 idx) = GSSRecon(nodeId,Q,startIdx);
            if (prf.Shat != recovershat) {
                VerifyResult.push(false);
                return false;
            }
            VerifyResult.push(true);

            // delete proof
            delete prf.Cp;
            delete prf.ShatArray;
        }
        return true;
    }

    // Upload Prfs
    function UploadProof(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray) public payable {
        // delete prev proof
        delete prf.Cp;
        delete prf.ShatArray;
        for (uint i = 0; i < shatArray.length;i++){
            prf.Cp.push(cp[i]);
            prf.ShatArray.push(shatArray[i]);
        }
        prf.Xc = xc;
        prf.Shat = shat;
    }

    function PVGSSKeyVrf(G1Point memory C, G1Point memory decShare, G2Point memory pk2,G2Point memory g2) public payable returns (bool) {
        bool isKeyValid = pairingProd2(decShare, pk2, negate(C), g2);
        KeyVerifyResult.push(isKeyValid);
        return isKeyValid;
    }
    
    // store ERC20 token balance: balances[user addr][token addr]
    mapping(address => mapping(address => uint256)) public balances;

    // store freeze_balance   
    mapping(address => mapping(uint256 => mapping(address => uint256))) public freeze_balances;

    // store staked eth
    mapping(address => uint256) public stakedETH;

    // watcher list
    address[] public watcherList;

    // store pubkey of users
    mapping(address => G1Point) public pubkey1;

    mapping(bytes32 => address) public pubkeyhashToAddress;

    mapping(address => G2Point) private pubkey2;

    uint constant MINIMAL_EXCHANGER_STAKE = 1 ether; 
    uint constant MINIMAL_WATCHER_STAKE = 1 ether; 

    struct Order {
        address seller;    //Order creator
        address tokenSell; // Token to sell (e.g., ETH)
        uint256 amountSell; // Amount to sell (e.g., 2 ETH)
        address tokenBuy; // Token to buy (e.g., USDT)
        uint256 amountBuy; // Amount to buy (e.g., 7000 USDT)
        bool isActive;     // Order state
    }
    // Store orders
    mapping(uint256 => Order) public orders;
    uint256 public nextOrderId;

    // State variable to track session state
    // Active: session created  halfSwap1:one execute swap1  finishSwap1: two execute swap1 halfSwap2: one execute swap2
    enum SessionState { Active, halfSwap1, finishSwap1, halfSwap2, Complain, Success, Failure }
    struct Session {
        SessionState state; // Session state
        address[] exchangers; // seller as exchanger[0], buyer as exchanger[1] in the session
        address[] watchers; // Watchers in the session
        mapping(address => G1Point) shares; // decshare collect
        mapping(address => G1Point) Cshares1; //shares from seller
        mapping(address => G1Point) Cshares2; //shares from buyer
        uint256 expiration1; // First expiration time
        uint256 expiration2; // Second expiration time
        bool[2] seller_flag; // swap flag of seller
        bool[2] buyer_flag;  // swap flag of buyer
        mapping(address => bool) watcher_flag; //submit flag of watcher
    }
    //Store sessions
    mapping(uint256 => Session) public sessions;

    // event
    event TokensReceived(address indexed token, address indexed from, uint256 amount);
    event TokensFrozen(address indexed token, address indexed from, uint256 amount, uint256 sessionId);
    event TokensSwapped(address indexed token, address indexed from, uint256 amount, uint256 sessionId);
    event ComplaintFiled(address indexed complainer, uint256 sessionId);
    event SessionStateUpdated(uint256 sessionId, SessionState state);
    event UserNotified(uint256 sessionId, address indexed user);
    event OrderCreated(uint256 orderId, address indexed seller, address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy);
    event Incentivized(address indexed exchanger, uint256 amount);
    event Penalized(address indexed exchanger, uint256 amount);
    event SessionCreated(uint256 indexed orderId, address seller, address buyer, address[] watchers, uint256 expiration1, uint256 expiration2);

    modifier onlyExchanger(uint256 id) {
        require(msg.sender == sessions[id].exchangers[0] || msg.sender == sessions[id].exchangers[1], "Invalid exchanger");
        _;
    }

    //register pubkey
    function register(G1Point memory _pubkey1, G2Point memory _pubkey2) external {
        pubkey1[msg.sender] = _pubkey1;
        pubkeyhashToAddress[g1PointToBytes32(_pubkey1)] = msg.sender;
        pubkey2[msg.sender] = _pubkey2;
    }

    // Deposit ERC20 tokens into the contract
    function deposit(address token, uint256 amount) external {
        IERC20 erc20Token = IERC20(token);

        //check allowance before transferFrom
        uint256 _allow = erc20Token.allowance(msg.sender, address(this));
        require(amount > 0, "Deposit amount must be greater than 0");
        require(amount <= _allow, "Insufficient allowance");
        
        //update balance
        balances[msg.sender][token] += amount;

        //transfer from sender to this contract
        erc20Token.transferFrom(msg.sender, address(this), amount);

        emit TokensReceived(token, msg.sender, amount);
    }

    // Withdraw ERC20 tokens from the contract
    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender][token] >= amount, "Insufficient balance");

        balances[msg.sender][token] -= amount;

        //withdraw to sender
        IERC20(token).transfer(msg.sender, amount);
    }

    // stake ETH
    function stakeETH(bool asWatcher) external payable {
        require(msg.value > 0, "Must send ETH to stake");
        if (asWatcher) {
            watcherList.push(msg.sender);
        }
        stakedETH[msg.sender] += msg.value;
    }

    // unstake ETH
    function unstakeETH(uint256 amount) external {
        require(stakedETH[msg.sender] >= amount, "Insufficient staked ETH");
        stakedETH[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    // Create an order
    function createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy) external returns (uint256){
        require(balances[msg.sender][tokenSell] >= amountSell, "Insufficient balance to create order");

        // Freeze seller's funds
        balances[msg.sender][tokenSell] -= amountSell;
        freeze_balances[msg.sender][nextOrderId][tokenSell] += amountSell;

        // Create the order
        orders[nextOrderId] = Order({
            seller: msg.sender,
            tokenSell: tokenSell,
            amountSell: amountSell,
            tokenBuy: tokenBuy,
            amountBuy: amountBuy,
            isActive: true
        });

        emit TokensFrozen(tokenSell, msg.sender, amountSell, nextOrderId);
        emit OrderCreated(nextOrderId, msg.sender, tokenSell, amountSell, tokenBuy, amountBuy);

        // Return the order ID
        uint256 currentOrderId = nextOrderId;
        nextOrderId++; // Increment for the next order

        return currentOrderId;
    }

    // Cancel an order
    function cancelOrder(uint256 orderId) external {
        Order storage order = orders[orderId];
        // Check if the order exists and is active
        require(order.isActive, "Order is not active or does not exist");
        // Check if the caller is the seller
        require(msg.sender == order.seller, "Only the seller can cancel the order");

        // Mark the order as inactive
        order.isActive = false;

        // Unfreeze the seller's funds
        balances[msg.sender][order.tokenSell] += order.amountSell;
        freeze_balances[msg.sender][orderId][order.tokenSell] -= order.amountSell;
    }

    // Accept order
    function acceptOrder(uint256 orderId, uint256 watcherNum) external {
        Order storage _order = orders[orderId];
        require(_order.isActive, "Order is not active");
        require(balances[msg.sender][_order.tokenBuy] >= _order.amountBuy, "Insufficient balance to accept order");
        require(watcherList.length >= watcherNum, "watcher num invalid");

        // Freeze buyer's funds
        balances[msg.sender][_order.tokenBuy] -= _order.amountBuy;
        freeze_balances[msg.sender][orderId][_order.tokenBuy] += _order.amountBuy;

        // Mark order as accepted
        _order.isActive = false;

        // Initialize the session
        Session storage newSession = sessions[orderId];
        newSession.state = SessionState.Active; // Initial state
        newSession.exchangers.push(_order.seller); // Add seller (Alice)
        newSession.exchangers.push(msg.sender); // Add buyer (Bob)
        newSession.expiration1 = block.timestamp + 1 minutes ; // Set expiration1
        newSession.expiration2 = block.timestamp + 2 minutes; // Set expiration2
        
        //add watchers
        //uint256 randomIndex = uint256(keccak256(abi.encodePacked(block.timestamp, orderId)));
        for (uint256 i = 0; i < watcherNum; i++) {
            // newSession.watchers[i] = watcherList[(randomIndex + i) % watcherList.length];
            newSession.watchers.push(watcherList[i]);
            newSession.watcher_flag[watcherList[i]] = false;
        }
        
        emit TokensFrozen(_order.tokenBuy, msg.sender, _order.amountBuy, orderId);
        emit SessionCreated(orderId, _order.seller, msg.sender, newSession.watchers, newSession.expiration1, newSession.expiration2);
    }

    //session swap1: shares validity check
    function swap1(uint256 id, G1Point[] memory C, G1Point[] memory PK, uint256[] memory I) external onlyExchanger(id){
        Session storage session = sessions[id];
        // Check session state
        require(session.state == SessionState.Active || session.state == SessionState.halfSwap1, "Session state is invalid for swap1");
        // Check Expiration1
        require(block.timestamp <= session.expiration1, "Session is expired t1");
        // Check stake
        require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");
        // Check validity of shares PVGSSVerify()
        require(PVGSSVerify(C, PK, I) == true, "pvgss verify failed");

        // Store C_i
        if (msg.sender == session.exchangers[0]) {
            for (uint i = 0; i < PK.length; i++) {
                address user = pubkeyhashToAddress[g1PointToBytes32(PK[i])];
                session.Cshares1[user] = C[i];
            }
            session.seller_flag[0] = true;
        } else {
            for (uint i = 0; i < PK.length; i++) {
                address user = pubkeyhashToAddress[g1PointToBytes32(PK[i])];
                session.Cshares2[user] = C[i];
            }
            session.buyer_flag[0] = true;
        }
    
        if (session.state == SessionState.Active) {
            session.state = SessionState.halfSwap1;
        } else if (session.state == SessionState.halfSwap1) {
            session.state = SessionState.finishSwap1;
        }

        // Update session state based on current state
        emit SessionStateUpdated(id, session.state);
    }

    function swap2(uint256 id, G1Point memory decShare) external onlyExchanger(id){
        Session storage session = sessions[id];
        // Check session state
        require(session.state == SessionState.finishSwap1 || session.state == SessionState.halfSwap2, "Session state is invalid for swap2");
        // Check stake
        require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");
        // Check PVGSSKeyVrf and store decShare
        require (PVGSSKeyVrf(session.Cshares1[msg.sender], decShare, pubkey2[msg.sender], G2) == true, "KeyVrf failed");

        session.shares[msg.sender] = decShare;
        if (msg.sender == session.exchangers[0]) {
            session.seller_flag[1] = true;
        } else {
            session.buyer_flag[1] = true;
        }

        if (session.state == SessionState.finishSwap1) {
            session.state = SessionState.halfSwap2;
        } else if (session.state == SessionState.halfSwap2) {
            session.state = SessionState.Success;
        }
        emit SessionStateUpdated(id, session.state);
    }

    //complain
    function complain(uint256 id) external {
        Session storage session = sessions[id];
        require(block.timestamp > session.expiration1, "Complaint period has not started");
        require(block.timestamp <= session.expiration2, "Session is out of t2");
        require(session.state == SessionState.halfSwap2, "Session state is not valid");

        // Check msg.sender is Alice or Bob
        require(msg.sender == session.exchangers[0] || msg.sender == session.exchangers[1], "Complainer is not valid");
        // Check stake
        require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");
        // Update state to Complain
        session.state = SessionState.Complain;

        // Notify watchers
        for (uint i = 0; i < session.watchers.length; i++) {
            emit UserNotified(id, session.watchers[i]);
        }

        emit ComplaintFiled(msg.sender, id);
    }

    // Watcher submits S_i to resolve dispute
    function submitWatcherShare(uint256 id, G1Point memory decShare) external {
        Session storage session = sessions[id];

        require(session.state == SessionState.Complain, "Session is not complained");
        require(block.timestamp <= session.expiration2, "Session is out of t2");
        require(isWatcher(id, msg.sender), "Only watchers can submit share");

        require(PVGSSKeyVrf(session.Cshares1[msg.sender], decShare, pubkey2[msg.sender], G2) == true, "KeyVrf failed");
        session.shares[msg.sender] = decShare;
        session.watcher_flag[msg.sender] = true;
    }

    // Check if an address is a watcher for a session
    function isWatcher(uint256 id, address addr) internal view returns (bool) {
        Session storage session = sessions[id];
        for (uint i = 0; i < session.watchers.length; i++) {
            if (session.watchers[i] == addr) {
                return true;
            }
        }
        return false;
    }

    // Get the number of watchers who have submitted shares
    function getSubmittedWatchersCount(Session storage session) internal view returns (uint256) {
        uint256 count = 0;
        for (uint i = 0; i < session.watchers.length; i++) {
            if (session.watcher_flag[session.watchers[i]]) {
                count++;
            }
        }
        return count;
    }

    function determine(uint256 orderId) external {
        Session storage session = sessions[orderId];

        // Check if session has expired
        require(block.timestamp > session.expiration2, "Session has not expired t2");

        // Determine the final state based on conditions
        if (session.state == SessionState.Success) {
            // Both exchangers have completed swap2
            incentivizeAllWatchers(session);
        } else if (session.state == SessionState.Complain) {
            if (getSubmittedWatchersCount(session) > 1) { //set threshold=2 now
                //dispute resolved  
                session.state = SessionState.Success;
            } else {
                //dispute unresolved
                session.state = SessionState.Failure;
            }
            incentivizePartWatchers(session);
            penalizeFaultyExchangers(session);
        } else {
            //at least one not swap1
            if (session.state == SessionState.Active || session.state == SessionState.halfSwap1) {
                penalizeFaultyExchangers(session);
            } else if (session.state == SessionState.finishSwap1) {
                //both finish swap1
                incentivizeAllWatchers(session);
            } 
            // set final state Failure
            session.state = SessionState.Failure;
        }

        // Execute token transfers based on the final state
        if (session.state == SessionState.Success) {
            // Transfer tokens between exchangers
            address seller = session.exchangers[0];
            address buyer = session.exchangers[1];
            Order storage order = orders[orderId];

            freeze_balances[seller][orderId][order.tokenSell] -= order.amountSell;
            freeze_balances[buyer][orderId][order.tokenBuy] -= order.amountBuy;

            // Transfer seller's tokens to buyer
            IERC20(order.tokenSell).transfer(buyer, order.amountSell);
            // Transfer buyer's tokens to seller
            IERC20(order.tokenBuy).transfer(seller, order.amountBuy);
        } else if (session.state == SessionState.Failure) {
            // Return frozen tokens to exchangers
            address seller = session.exchangers[0];
            address buyer = session.exchangers[1];
            Order storage order = orders[orderId];

            // Return seller's tokens
            balances[seller][order.tokenSell] += order.amountSell;
            freeze_balances[seller][orderId][order.tokenSell] -= order.amountSell;

            // Return buyer's tokens
            balances[buyer][order.tokenBuy] += order.amountBuy;
            freeze_balances[buyer][orderId][order.tokenBuy] -= order.amountBuy;
        }
        emit SessionStateUpdated(orderId, session.state);
    }

    //Incentivize all watchers
    function incentivizeAllWatchers(Session storage session) internal {
        for (uint i = 0; i < session.watchers.length; i++) {
            address watcher = session.watchers[i];
            payable(watcher).transfer(0.01 ether); // Incentivize with 0.01 eth token
            emit Incentivized(watcher, 0.01 ether);
        }
    }

    //Incentivize honest and penalize other watchers
    function incentivizePartWatchers(Session storage session) internal {
        for (uint i = 0; i < session.watchers.length; i++) {
            address watcher = session.watchers[i];
            if(session.watcher_flag[watcher]) {
                payable(watcher).transfer(0.01 ether); // Incentivize with 0.01 eth token
                emit Incentivized(watcher, 0.01 ether);
            } else {
                stakedETH[watcher] -= 0.1 ether; // Penalize with 0.1 eth token
                emit Penalized(watcher, 0.1 ether);
            }
        }
    }

    //Faulty exchanger: (not swap1) or (both swap1 not finish swap2)
    function penalizeFaultyExchangers(Session storage session) internal {
        address seller = session.exchangers[0];
        address buyer = session.exchangers[1];

        //(both swap1 not finish swap2)
        if (session.seller_flag[0] && session.buyer_flag[0]) {
            if (!session.seller_flag[1]) {
                stakedETH[seller] -= 0.1 ether; // Penalize with 0.1 eth
                emit Penalized(seller, 0.1 ether);
            }
            if (!session.buyer_flag[1]) {
                stakedETH[buyer] -= 0.1 ether; // Penalize with 0.1 eth
                emit Penalized(buyer, 0.1 ether);
            }
        } else {
            //(not swap1)
            if (!session.seller_flag[0]) {
                stakedETH[seller] -= 0.1 ether; // Penalize with 0.1 eth
                emit Penalized(seller, 0.1 ether);
            }
            if (!session.buyer_flag[0]) {
                stakedETH[buyer] -= 0.1 ether; // Penalize with 0.1 eth
                emit Penalized(buyer, 0.1 ether);
            }
        }
    }
}