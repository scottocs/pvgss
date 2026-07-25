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
    G1Point G1 = G1Point(1, 2);
	/// return the sum of two points of G1
	function g1add(G1Point memory p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require(success);
	}

	function g1addCalldata(G1Point calldata p1, G1Point memory p2) view internal returns (G1Point memory r) {
		uint[4] memory input;
		input[0] = p1.X;
		input[1] = p1.Y;
		input[2] = p2.X;
		input[3] = p2.Y;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 6, input, 0x80, r, 0x40)
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
			success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require (success);
	}

	function g1mulCalldata(G1Point calldata p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
		}
		require (success);
	}

	function g1mulStorage(G1Point storage p, uint s) view internal returns (G1Point memory r) {
		uint[3] memory input;
		input[0] = p.X;
		input[1] = p.Y;
		input[2] = s;
		bool success;
		assembly {
			success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
		}
		require (success);
	}

	uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

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
			//success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            result := mload(freemem)
        }
        require(success);
    }

	function equals(
			G1Point memory a, G1Point memory b			
	) pure internal returns (bool) {		
		return a.X==b.X && a.Y==b.Y;
	}

	function equalsCalldata(
			G1Point calldata a, G1Point memory b
	) pure internal returns (bool) {
		return a.X==b.X && a.Y==b.Y;
	}

    // ========================== PVGSS-SSS Verification ===============================

    struct Node {
        bool IsLeaf;
        uint256[] Children; // Child nodes ID
        uint256 ChildrenNum; // Child nodes numbers
        uint256 T; //Threshold
        uint256 Idx; //The local index of the node under its parent
    }
    mapping(uint256 => Node) public nodes;
    uint256[] public XChildId;
    uint256[] public rootChildId;

    struct Prf {
        G1Point[] Cp;
        uint256 Xc;
        uint256 Shat;
        uint256[] ShatArray;
    }

    function _appendPolicy(bytes memory encoded, uint256 nodeId) internal view returns (bytes memory) {
        Node storage node = nodes[nodeId];
        encoded = abi.encodePacked(
            encoded,
            node.IsLeaf,
            node.ChildrenNum,
            node.T
        );
        for (uint256 i = 0; i < node.Children.length; i++) {
            encoded = _appendPolicy(encoded, node.Children[i]);
        }
        return encoded;
    }

    function _sharingChallenge(
        G1Point[] memory PK,
        G1Point[] memory C,
        G1Point[] memory cp
    ) internal view returns (uint256) {
        bytes memory encoded = _appendPolicy(bytes("PVGSS-SHARE-v1"), 0);
        for (uint256 i = 0; i < PK.length; i++) {
            encoded = abi.encodePacked(encoded, PK[i].X, PK[i].Y);
        }
        for (uint256 i = 0; i < C.length; i++) {
            encoded = abi.encodePacked(encoded, C[i].X, C[i].Y);
        }
        for (uint256 i = 0; i < cp.length; i++) {
            encoded = abi.encodePacked(encoded, cp[i].X, cp[i].Y);
        }
        return uint256(sha256(encoded)) % GEN_ORDER;
    }

    function _dleqChallenge(
        G1Point memory C,
        G1Point memory pk1,
        G1Point memory decShare,
        G1Point memory com1,
        G1Point memory com2
    ) internal view returns (uint256) {
        return uint256(sha256(abi.encodePacked(
            "PVGSS-DLEQ-v1",
            G1.X, G1.Y,
            decShare.X, decShare.Y,
            pk1.X, pk1.Y,
            C.X, C.Y,
            com1.X, com1.Y,
            com2.X, com2.Y
        ))) % GEN_ORDER;
    }

    function _dualTestSeed(
        uint256[] memory shares,
        G1Point[] memory PK,
        G1Point[] memory C,
        G1Point[] memory cp
    ) internal view returns (bytes32) {
        bytes memory encoded = _appendPolicy(bytes("PVGSS-DUAL-v1"), 0);
        for (uint256 i = 0; i < shares.length; i++) {
            encoded = abi.encodePacked(encoded, shares[i]);
        }
        for (uint256 i = 0; i < PK.length; i++) {
            encoded = abi.encodePacked(encoded, PK[i].X, PK[i].Y);
        }
        for (uint256 i = 0; i < C.length; i++) {
            encoded = abi.encodePacked(encoded, C[i].X, C[i].Y);
        }
        for (uint256 i = 0; i < cp.length; i++) {
            encoded = abi.encodePacked(encoded, cp[i].X, cp[i].Y);
        }
        encoded = abi.encodePacked(encoded, block.timestamp);
        return sha256(encoded);
    }



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
            // XChildId[i] = i+1;
            // createNode(3, i+1, true, 0, 1);
            uint256 childLocalIdx = i + 10;  // 使用更大的范围避免冲突
            XChildId[i] = childLocalIdx;     // 存储本地索引
            createNode(3, childLocalIdx, true, 0, 1);
        }
        // add child nodes for X
        addChild(3, XChildId);
        // add child nodes for root

        if (flag == 1) { //A and B
            rootChildId = new uint256[](2);
            rootChildId[0] = 1;
            rootChildId[1] = 2;
            addChild(0, rootChildId);
        } 
        else if (flag == 2) { // A and Watchers
            rootChildId = new uint256[](2);
            rootChildId[0] = 1;
            rootChildId[1] = 3;
            addChild(0, rootChildId);
        }
        else if (flag == 3) {
            rootChildId = new uint256[](2);
            rootChildId[0] = 2;
            rootChildId[1] = 3;
            addChild(0, rootChildId);
        }
        else if (flag == 4) { // A and B and Watchers
            rootChildId = new uint256[](3);
            rootChildId[0] = 1;
            rootChildId[1] = 2;
            rootChildId[2] = 3;
            addChild(0,rootChildId);
        }
    }
    // Create a node
    function createNode(uint256 parentIdx, uint256 idx, bool isLeaf, uint256 childNum, uint256 t) public payable {
        // Node's ID = parents' ID * 100 + child's ID
        uint256 nodeId = parentIdx * 100 + idx;
        Node storage newNode = nodes[nodeId];
        newNode.IsLeaf = isLeaf;
        delete newNode.Children;
        newNode.ChildrenNum = childNum;
        newNode.T = t;
        newNode.Idx = idx;
    }

    // add child nodes for some node
    function addChild(uint256 parentIdx,uint256[] memory childIdxs) public payable {
        uint256 parentNodeId = parentIdx;
        require(nodes[parentNodeId].ChildrenNum >= childIdxs.length,"Too many child");
        Node storage parentNode = nodes[parentNodeId];
        for (uint256 i = 0; i < childIdxs.length; i++) {
            uint256 childNodeId = parentIdx * 100 + childIdxs[i];
            parentNode.Children.push(childNodeId);
        }
    }

    //======================================GSS Testing================================//
    //===========Method 1============
   function ReconPolynomial(uint256 rootNodeId, uint256[] memory shares) public view returns (bool success) {
        Node memory AA = nodes[rootNodeId];
        if (AA.Children.length == 0 && !AA.IsLeaf) {
            return false;
        }
        (, , bool verifySuccess) = verifyRecursiveRP(AA, shares, 0);
        if (!verifySuccess) {
            return false;
        }
        return true;
    }

    function verifyRecursiveRP(Node memory AA, uint256[] memory shares, uint256 offset) 
        public view returns (uint256 consumed, uint256 secret, bool success) {
        
        if (AA.IsLeaf) {
            if (offset >= shares.length) {
                return (0, 0, false);
            }
            secret = shares[offset];
            return (1, secret, true);
        }

        uint256[] memory childSecrets = new uint256[](AA.ChildrenNum);
        uint256 currentOffset = offset;
        
        for(uint256 i = 0; i < AA.ChildrenNum; i++) {
            if (i >= AA.Children.length) {
                return (0, 0, false);
            }
            uint256 childNodeId = AA.Children[i];
            Node memory child = nodes[childNodeId];
            (uint256 childConsumed, uint256 childSecret, bool childSuccess) = verifyRecursiveRP(child, shares, currentOffset);
            if (!childSuccess) {
                return (0, 0, false);
            }
            childSecrets[i] = childSecret;
            currentOffset += childConsumed;
        }
        
        if (childSecrets.length < AA.T) {
            return (0, 0, false);
        }
        
        uint256[] memory sharesVal = new uint256[](AA.T);
        for(uint256 i = 0; i < AA.T; i++) {
            sharesVal[i] = childSecrets[i];
        }

        secret = interpolateAt(sharesVal, 0);

        for(uint256 i = AA.T; i < childSecrets.length; i++) {
            uint256 expectedVal = childSecrets[i];
            uint256 calculatedVal = interpolateAt(sharesVal, i + 1);

            if (expectedVal != calculatedVal) {
                return (0, 0, false);
            }
        }
        
        consumed = currentOffset - offset;
        return (consumed, secret, true);
    }

    //===========Method 2============

    function RecurRSCode(uint256 nodeId, uint256[] memory shares) 
        public view returns (bool success) {
            
        if (shares.length == 0) {
            return false;
        }

        G1Point[] memory empty = new G1Point[](0);
        bytes32 seed = _dualTestSeed(shares, empty, empty, empty);
        (uint256 _consumed, uint256 _secret, bool verifySuccess) = verifyRecursiveRS(nodeId, shares, 0, seed);

        return verifySuccess;
    }

    function verifyRecursiveRS(uint256 nodeId, uint256[] memory shares, uint256 offset, bytes32 seed)
        internal view returns (uint256 consumed, uint256 secret, bool success) {
        
        Node memory node = nodes[nodeId];
        
        // 1. 叶子节点处理
        if (node.IsLeaf) {
            if (offset >= shares.length) {
                return (0, 0, false); // Insufficient shares
            }
            secret = shares[offset];
            return (1, secret, true);
        }

        // 2. 非叶子节点：递归收集子节点的秘密值
        uint256[] memory childSecrets = new uint256[](node.ChildrenNum);
        uint256 currentOffset = offset;

        for (uint256 i = 0; i < node.ChildrenNum; i++) {
            if (i >= node.Children.length) {
                return (0, 0, false); // Children count mismatch
            }
            
            uint256 childNodeId = node.Children[i];
            
            uint256 childConsumed;
            uint256 childSecret;
            bool childSuccess;

            (childConsumed, childSecret, childSuccess) = verifyRecursiveRS(childNodeId, shares, currentOffset, seed);
            if (!childSuccess) {
                return (0, 0, false);
            }
            
            childSecrets[i] = childSecret;
            currentOffset += childConsumed;
        }
        
        // 3. 获取子秘密数量并检查阈值
        uint256 n = node.ChildrenNum; // number of child secrets
        uint256 k = node.T;          // threshold
        
        if (n < k) {
            return (0, 0, false); // Insufficient child secrets
        }

        // 4. 调用 rscodeVerify 算法检查所有子份额是否有效
        if (!rscodeVerify(childSecrets, k, seed, nodeId)) {
            return (0, 0, false); // RS Code verification failed
        }

        // 5. 验证成功后，重构当前节点的秘密（使用前 k 个点）
        // 创建用于重构的份额数组
        uint256[] memory sharesForRecon = new uint256[](k);
        for (uint256 i = 0; i < k; i++) {
            sharesForRecon[i] = childSecrets[i];
        }
        
        secret = interpolateAt(sharesForRecon, 0);
        consumed = currentOffset - offset;
        success = true;
        
        return (consumed, secret, success);
    }
    

    function rscodeVerify(uint256[] memory shares, uint256 k, bytes32 seed, uint256 nodeId)
        internal view returns (bool) {
            uint256 n = shares.length;

            if (n == k) {
                return true; 
            }
            if (n < k) {
                return false;
            }
            uint256 degF = n - k - 1;
            uint256[] memory fCoeffs = new uint256[](degF + 1);

            for (uint256 i = 0; i <= degF; i++) {
                fCoeffs[i] = uint256(sha256(abi.encodePacked(
                    "PVGSS-DUAL-NODE-v1", seed, nodeId, i
                ))) % GEN_ORDER;
            }

            uint256[] memory factorial = new uint256[](n);
            factorial[0] = 1;
            for (uint256 i = 1; i < n; i++) {
                factorial[i] = mulmod(factorial[i - 1], i, GEN_ORDER);
            }

            uint256 innerProduct = 0;
            for (uint256 i = 0; i < n; i++) {
                uint256 x_i = i + 1;
                uint256 denom = mulmod(factorial[i], factorial[n - 1 - i], GEN_ORDER);
                if (i % 2 == 1) {
                    denom = submod2(0, denom, GEN_ORDER);
                }

                uint256 v_i = _modInv(denom, GEN_ORDER);
                uint256 fVal = evaluatePolynomial(x_i, fCoeffs); 
                uint256 term = mulmod(shares[i], mulmod(v_i, fVal, GEN_ORDER), GEN_ORDER);
                innerProduct = addmod(innerProduct, term, GEN_ORDER);
            }

            return innerProduct == 0;
    }

    function interpolate(uint256[] memory points) 
        internal view returns (uint256 secret) {
            return interpolateAt(points, 0);
    }

    function interpolateAt(uint256[] memory points, uint256 target) 
        internal view returns (uint256 secret) {
            uint k = points.length;
            require(k > 0, "no points provided");
            secret = 0;

            for (uint i = 0; i < k; i++) {
                uint x_i = i + 1;
                uint num = 1;
                uint den = 1;

                for (uint j = 0; j < k; j++) {
                    if (i == j) continue;
                    uint x_j = j + 1;
                    num = mulmod(num, submod2(target, x_j, GEN_ORDER), GEN_ORDER);
                    den = mulmod(den, submod2(x_i, x_j, GEN_ORDER), GEN_ORDER);
                }   

                uint denInv = _modInv(den, GEN_ORDER);
                uint coeff = mulmod(num, denInv, GEN_ORDER);

                uint term = mulmod(points[i], coeff, GEN_ORDER);
                secret = addmod(secret, term, GEN_ORDER);
            }
            return secret;
    }
    // ===== SSS and GSS =====
    function evaluatePolynomial(uint256 x,uint256[] memory coefficients) internal pure returns (uint256) {
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

        // require(startIdx < Q.length,"Start index out of bounds");

        if(AA.IsLeaf) {
            // if(Q.length == 0) {
            //     // recSecret = 0;
            //     return (0,0);
            // }
            // recSecret = Q[startIdx];
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

        // recSecret = SSSRecon(childShares, childIdx);
        return (SSSRecon(childShares, childIdx),AA.Idx);
    }

    // ===== PVGSS-SSS Verification =====
    function PVGSSVerify(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C,G1Point[] memory PK, uint256[] memory I) public payable returns (bool) {
        return _PVGSSVerify(cp, xc, shat, shatArray, C, PK, I, false);
    }

    function PVGSSVerifyDual(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C,G1Point[] memory PK, uint256[] memory I) public payable returns (bool) {
        return _PVGSSVerify(cp, xc, shat, shatArray, C, PK, I, true);
    }

    function _PVGSSVerify(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C,G1Point[] memory PK, uint256[] memory I, bool useDualTest) internal view returns (bool) {
        if (C.length == 0 || C.length != PK.length || C.length != cp.length || C.length != shatArray.length) {
            return false;
        }
        if (xc != _sharingChallenge(PK, C, cp)) {
            return false;
        }
        bool gssVerified;
        if (useDualTest) {
            bytes32 dualSeed = _dualTestSeed(shatArray, PK, C, cp);
            (, , gssVerified) = verifyRecursiveRS(0, shatArray, 0, dualSeed);
        } else {
            gssVerified = ReconPolynomial(0, shatArray);
        }
        if (!gssVerified){
            return false;
        }
        uint256 nodeId = 0;
        uint256 startIdx = 0;
        uint256[] memory Q = new uint256[](I.length);
        for(uint256 i = 0; i < I.length; i++) {
            Q[i] = shatArray[I[i]];
        }
        for(uint i = 0; i < shatArray.length;i++) {
            G1Point memory temp1 = g1mul(C[i],xc);
            G1Point memory temp2 = g1mul(PK[i],shatArray[i]);
            G1Point memory right = g1add(temp1,temp2);
            if (!equals(cp[i],right)) {
                return false;
            }
        }
        (uint256 recovershat, uint256 idx) = GSSRecon(nodeId,Q,startIdx);
        if (shat != recovershat) {
            return false;
        }
        return true;
    }

    function PVGSSKeyVrf(G1Point calldata C, G1Point calldata decShare, G1Point calldata pk1, G1Point calldata com1, G1Point calldata com2, uint256 challenge, uint256 response) external payable returns (bool) {
        if (challenge != _dleqChallenge(C, pk1, decShare, com1, com2)) {
            return false;
        }
        G1Point memory L1 = g1mul(G1, response);
        G1Point memory R1_term = g1mulCalldata(pk1, challenge);
        G1Point memory R1 = g1addCalldata(com1, R1_term);

        if (L1.X != R1.X || L1.Y != R1.Y) {
            return false;
        }

        G1Point memory L2 = g1mulCalldata(decShare, response);
        G1Point memory R2_term = g1mulCalldata(C, challenge);
        G1Point memory R2 = g1addCalldata(com2, R2_term);
        
        if (L2.X != R2.X || L2.Y != R2.Y) {
            return false;
        }

        return true;
    }

    function _PVGSSKeyVrf(G1Point storage C, G1Point calldata decShare, G1Point storage pk1, G1Point calldata com1, G1Point calldata com2, uint256 challenge, uint256 response) internal view returns (bool) {
        if (challenge != _dleqChallenge(C, pk1, decShare, com1, com2)) {
            return false;
        }
        G1Point memory L1 = g1mul(G1, response);
        G1Point memory R1_term = g1mulStorage(pk1, challenge);
        G1Point memory R1 = g1addCalldata(com1, R1_term);

        if (L1.X != R1.X || L1.Y != R1.Y) {
            return false;
        }

        G1Point memory L2 = g1mulCalldata(decShare, response);
        G1Point memory R2_term = g1mulStorage(C, challenge);
        G1Point memory R2 = g1addCalldata(com2, R2_term);
        
        if (L2.X != R2.X || L2.Y != R2.Y) {
            return false;
        }

        return true;
    }

    // ========================== PVGSS-SSS Verification End ===============================

    // ========================== PVGSS-LSSS Verification ===============================

    function LSSSPVGSSVerify(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C,G1Point[] memory PK, uint256[] memory weights, uint256[] memory weights1 ,uint256[] memory I, uint256[] memory I1) public payable returns (bool) {
         return _LSSSPVGSSVerify(cp, xc, shat, shatArray, C, PK, weights, weights1, I, I1, false);
     }

    function LSSSPVGSSVerifyDual(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C,G1Point[] memory PK, uint256[] memory weights, uint256[] memory weights1 ,uint256[] memory I, uint256[] memory I1) public payable returns (bool) {
         return _LSSSPVGSSVerify(cp, xc, shat, shatArray, C, PK, weights, weights1, I, I1, true);
     }

    function _LSSSPVGSSVerify(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C,G1Point[] memory PK, uint256[] memory weights, uint256[] memory weights1 ,uint256[] memory I, uint256[] memory I1, bool useDualTest) internal view returns (bool) {
         if (C.length == 0 || C.length != PK.length || C.length != cp.length || C.length != shatArray.length) {
             return false;
         }
         if (xc != _sharingChallenge(PK, C, cp)) {
             return false;
         }
         bool gssVerified;
         if (useDualTest) {
             bytes32 dualSeed = _dualTestSeed(shatArray, PK, C, cp);
             (, , gssVerified) = verifyRecursiveRS(0, shatArray, 0, dualSeed);
         } else {
             gssVerified = ReconPolynomial(0, shatArray);
         }
         if (!gssVerified){
             return false;
         }
         for(uint i = 0; i < shatArray.length;i++) {
             G1Point memory right = g1add(g1mul(C[i],xc),g1mul(PK[i],shatArray[i]));
             if (!equals(cp[i],right)) {
                 return false;
             }
         }
         uint256 recovershat = LSSSRecon(weights,shatArray,I);
         if (shat != recovershat) {
             return false;
         }
         uint256 recovershat1 = LSSSRecon(weights1,shatArray,I1);
         if (shat != recovershat1) {
             return false;
         }
         return true;
     }

     // LSSSRecon
	     function LSSSRecon(uint256[] memory weights, uint256[] memory shares, uint256[] memory I) public pure returns (uint256) {
	         uint256 rows = I.length;
             require(weights.length == rows, "invalid reconstruction weights");
	         uint256 reconS = 0;
	         for(uint256 i = 0; i < rows; i++) {
	             reconS = addmod(reconS, mulmod(weights[i], shares[I[i]], GEN_ORDER), GEN_ORDER);
	         }
	         return reconS;
	     }

    //========================== PVGSS-LSSS Verification End ===============================

    
    // store contract balance   users A token B balance: balances[userA addr][tokenB addr]
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
    // Ready means that both exchanger openings have been verified but settlement has not executed.
    enum SessionState { Active, halfSwap1, finishSwap1, halfSwap2, Ready, Complain, Success, Failure }
    struct Session {
        SessionState state; // Session state
        address[] exchangers; // seller as exchanger[0], buyer as exchanger[1] in the session
        address[] watchers; // Watchers in the session
        mapping(address => G1Point) shares; // decshare collect
        mapping(address => G1Point) Cshares1; //shares from seller
        mapping(address => G1Point) Cshares2; //shares from buyer
        uint256 expiration1; // First expiration time
        uint256 expiration2; // Second expiration time
        uint256 recoveryThreshold; // Required watcher responses after a complaint
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
    event SessionCreated(uint256 indexed orderId, address seller, address buyer, address[] watchers, uint256 recoveryThreshold, uint256 expiration1, uint256 expiration2);


    modifier onlyExchanger(uint256 id) {
        require(msg.sender == sessions[id].exchangers[0] || msg.sender == sessions[id].exchangers[1], "Invalid exchanger");
        _;
    }

    function _validateSessionPolicy(Session storage session, uint256 statementLength) internal view {
        require(nodes[3].T == session.recoveryThreshold, "PVGSS threshold does not match session");
        require(nodes[3].ChildrenNum == session.watchers.length, "PVGSS watcher set size does not match session");
        require(statementLength == session.watchers.length + 2, "PVGSS participant count does not match session");
    }

    //register pubkey
    function register(G1Point memory _pubkey1) external {
        pubkey1[msg.sender] = _pubkey1;
        pubkeyhashToAddress[g1PointToBytes32(_pubkey1)] = msg.sender;
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
        require(erc20Token.transferFrom(msg.sender, address(this), amount), "Token deposit failed");

        emit TokensReceived(token, msg.sender, amount);
    }

    // Withdraw tokens from the contract
    function withdraw(address token, uint256 amount) external {
        require(balances[msg.sender][token] >= amount, "Insufficient balance");

        balances[msg.sender][token] -= amount;

        //withdraw to sender
        require(IERC20(token).transfer(msg.sender, amount), "Token withdrawal failed");
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

    // // Cancel an order
    // function cancelOrder(uint256 orderId) external {
    //     Order storage order = orders[orderId];

    //     // Check if the order exists and is active
    //     require(order.isActive, "Order is not active or does not exist");

    //     // Check if the caller is the seller
    //     require(msg.sender == order.seller, "Only the seller can cancel the order");

    //     // Mark the order as inactive
    //     order.isActive = false;

    //     // Unfreeze the seller's funds
    //     balances[msg.sender][order.tokenSell] += order.amountSell;
    //     freeze_balances[msg.sender][orderId][order.tokenSell] -= order.amountSell;
    // }

    // Accept order
    function acceptOrder(uint256 orderId, uint256 watcherNum, uint256 recoveryThreshold) external {
        Order storage _order = orders[orderId];
        require(_order.isActive, "Order is not active");
        require(balances[msg.sender][_order.tokenBuy] >= _order.amountBuy, "Insufficient balance to accept order");
        require(watcherList.length >= watcherNum, "watcher num invalid");
        require(recoveryThreshold > 0 && recoveryThreshold <= watcherNum, "recovery threshold invalid");

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
        newSession.expiration1 = block.timestamp + 30 seconds ; // Set expiration1
        newSession.expiration2 = block.timestamp + 1 minutes; // Set expiration2
        newSession.recoveryThreshold = recoveryThreshold;
        
        //add watchers
        //uint256 randomIndex = uint256(keccak256(abi.encodePacked(block.timestamp, orderId)));
        for (uint256 i = 0; i < watcherNum; i++) {
            // newSession.watchers[i] = watcherList[(randomIndex + i) % watcherList.length];
            newSession.watchers.push(watcherList[i]);
            newSession.watcher_flag[watcherList[i]] = false;
        }
        
        emit TokensFrozen(_order.tokenBuy, msg.sender, _order.amountBuy, orderId);
        emit SessionCreated(orderId, _order.seller, msg.sender, newSession.watchers, recoveryThreshold, newSession.expiration1, newSession.expiration2);
    }

    //session swap1: shares validity check
    function swap1(uint256 id, G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C, G1Point[] memory PK, uint256[] memory I) external onlyExchanger(id){
        _swap1(id, cp, xc, shat, shatArray, C, PK, I, false);
    }

    function swap1Dual(uint256 id, G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C, G1Point[] memory PK, uint256[] memory I) external onlyExchanger(id){
        _swap1(id, cp, xc, shat, shatArray, C, PK, I, true);
    }

    function _swap1(uint256 id, G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray,G1Point[] memory C, G1Point[] memory PK, uint256[] memory I, bool useDualTest) internal {
        Session storage session = sessions[id];

        // Check session state
        require(session.state == SessionState.Active || session.state == SessionState.halfSwap1, "Session state is invalid for swap1");

        // Check Expiration1
        require(block.timestamp <= session.expiration1, "Session is expired t1");

        // Check stake
        require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");
        _validateSessionPolicy(session, PK.length);
        // Check validity of shares PVGSSVerify()
        require(_PVGSSVerify(cp, xc, shat, shatArray, C, PK, I, useDualTest) == true, "pvgss verify failed");

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

    function swap2(uint256 id, G1Point calldata decShare, G1Point calldata com1, G1Point calldata com2, uint256 challenge, uint256 response) external onlyExchanger(id){
        Session storage session = sessions[id];
        // Check session state
        require(session.state == SessionState.finishSwap1 || session.state == SessionState.halfSwap2, "Session state is invalid for swap2");

        // Check stake
        require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");

        // Invoke PVGSSKeyVrf and store decShare
        if (msg.sender == session.exchangers[0]) {
            require(_PVGSSKeyVrf(session.Cshares1[msg.sender], decShare, pubkey1[msg.sender], com1, com2, challenge, response), "KeyVrf failed");
        } else {
            require(_PVGSSKeyVrf(session.Cshares2[msg.sender], decShare, pubkey1[msg.sender], com1, com2, challenge, response), "KeyVrf failed");
        }

        session.shares[msg.sender] = decShare;
        if (msg.sender == session.exchangers[0]) {
            session.seller_flag[1] = true;
        } else {
            session.buyer_flag[1] = true;
        }

        if (session.state == SessionState.finishSwap1) {
            session.state = SessionState.halfSwap2;
        } else if (session.state == SessionState.halfSwap2) {
            session.state = SessionState.Ready;
        }
        emit SessionStateUpdated(id, session.state);
    }

     function lswap1(uint256 id, G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray, G1Point[] memory C, G1Point[] memory PK, uint256[] memory weights, uint256[] memory weights1 ,uint256[] memory I, uint256[] memory I1) external onlyExchanger(id){
         _lswap1(id, cp, xc, shat, shatArray, C, PK, weights, weights1, I, I1, false);
     }

     function lswap1Dual(uint256 id, G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray, G1Point[] memory C, G1Point[] memory PK, uint256[] memory weights, uint256[] memory weights1 ,uint256[] memory I, uint256[] memory I1) external onlyExchanger(id){
         _lswap1(id, cp, xc, shat, shatArray, C, PK, weights, weights1, I, I1, true);
     }

     function _lswap1(uint256 id, G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray, G1Point[] memory C, G1Point[] memory PK, uint256[] memory weights, uint256[] memory weights1 ,uint256[] memory I, uint256[] memory I1, bool useDualTest) internal {
         Session storage session = sessions[id];

         // Check session state
         require(session.state == SessionState.Active || session.state == SessionState.halfSwap1, "Session state is invalid for swap1");

         // Check Expiration1
         require(block.timestamp <= session.expiration1, "Session is expired t1");

         // Check stake
         require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");
         _validateSessionPolicy(session, PK.length);
         // Check validity of shares PVGSSVerify()
         require(_LSSSPVGSSVerify(cp, xc, shat, shatArray, C, PK, weights, weights1, I, I1, useDualTest) == true, "pvgss verify failed");

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

    //complaint
    function complain(uint256 id) external {
        Session storage session = sessions[id];

        require(block.timestamp > session.expiration1, "Complaint period has not started");
        require(block.timestamp <= session.expiration2, "Session is out of t2");
        require(session.state == SessionState.halfSwap2, "Session state is not valid");

        // Check msg.sender is Alice or Bob
        require(msg.sender == session.exchangers[0] || msg.sender == session.exchangers[1], "Complainer is not valid");
        require(
            (msg.sender == session.exchangers[0] && session.seller_flag[1] && !session.buyer_flag[1]) ||
            (msg.sender == session.exchangers[1] && session.buyer_flag[1] && !session.seller_flag[1]),
            "Only the exchanger that opened may complain"
        );

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
    function submitWatcherShare(uint256 id, G1Point calldata decShare, G1Point calldata com1, G1Point calldata com2, uint256 challenge, uint256 response) external {
        Session storage session = sessions[id];

        require(session.state == SessionState.Complain, "Session is not complained");
        require(block.timestamp <= session.expiration2, "Session is out of t2");
        require(isWatcher(id, msg.sender), "Only watchers can submit share");
        require(!session.watcher_flag[msg.sender], "Watcher response already submitted");

        if (!session.seller_flag[1]) {
            require(_PVGSSKeyVrf(session.Cshares1[msg.sender], decShare, pubkey1[msg.sender], com1, com2, challenge, response), "KeyVrf failed");
        } else {
            require(_PVGSSKeyVrf(session.Cshares2[msg.sender], decShare, pubkey1[msg.sender], com1, com2, challenge, response), "KeyVrf failed");
        }
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
        require(session.state != SessionState.Success && session.state != SessionState.Failure, "Session already finalized");

        if (session.state == SessionState.Ready) {
            session.state = SessionState.Success;
            incentivizeAllWatchers(session);
        } else if (session.state == SessionState.Complain) {
            if (getSubmittedWatchersCount(session) >= session.recoveryThreshold) {
                session.state = SessionState.Success;
                incentivizePartWatchers(session);
                penalizeFaultyExchangers(session);
            } else {
                require(block.timestamp > session.expiration2, "Recovery threshold not reached");
                session.state = SessionState.Failure;
            }
        } else {
            require(block.timestamp > session.expiration2, "Session has not expired t2");
            if (session.state == SessionState.Active || session.state == SessionState.halfSwap1) {
                penalizeFaultyExchangers(session);
            } else if (session.state == SessionState.finishSwap1) {
                incentivizeAllWatchers(session);
            }
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
            require(IERC20(order.tokenSell).transfer(buyer, order.amountSell), "Seller token transfer failed");
            // Transfer buyer's tokens to seller
            require(IERC20(order.tokenBuy).transfer(seller, order.amountBuy), "Buyer token transfer failed");
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

	    function g1PointToBytes32(G1Point memory point) internal pure returns (bytes32) {
	        return keccak256(abi.encode(point.X, point.Y));
	    }

	    function g1PointToBytes32Calldata(G1Point calldata point) internal pure returns (bytes32) {
	        return keccak256(abi.encode(point.X, point.Y));
	    }
	}
