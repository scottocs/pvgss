pragma solidity ^0.8.0;



interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint);
}

contract Dex
{
	// using bn128G2 for *;
//	using strings for *;
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

	// (P+1) / 4
	function A() pure internal returns (uint256) {
		return CURVE_A;
	}

	function N() pure internal returns (uint256) {
		return GEN_ORDER;
	}

	/// return the generator of G1
	function P1() pure internal returns (G1Point memory) {
		return G1Point(1, 2);
	}
    G1Point G1 = G1Point(1, 2);
    G2Point G2 = G2Point(
        [11559732032986387107991004021392285783925812861821192530917403151452391805634,
        10857046999023057135944570762232829481370756359578518086990519993285655852781],
        [4082367875863433681332203403145435568316851327593401208105741076214120093531,
        8495653923123431417604973247489272438418190587263600148770280649306958101930]
    );
    // function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
    //     internal view returns (uint256 retval)
    // {
    //     bool success;
    //     uint256[1] memory output;
    //     uint[6] memory input;
    //     input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
    //     input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
    //     input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
    //     input[3] = _base;
    //     input[4] = _exponent;
    //     input[5] = _modulus;
    //     assembly {
    //         success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
    //         // Use "invalid" to make gas estimation work
    //         //switch success case 0 { invalid }
    //     }
    //     require(success);
    //     return output[0];
    // }


	/// return the generator of G2
	function P2() pure internal returns (G2Point memory) {
		return G2Point(
			[11559732032986387107991004021392285783925812861821192530917403151452391805634,
			 10857046999023057135944570762232829481370756359578518086990519993285655852781],
			[4082367875863433681332203403145435568316851327593401208105741076214120093531,
			 8495653923123431417604973247489272438418190587263600148770280649306958101930]
		);
	}

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
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
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
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
		}
		require (success);
	}

    // function negate(G1Point memory p) public payable returns (G1Point memory) {
    //     if (p.X == 0 && p.Y == 0)
    //         return G1Point(0, 0);
    //     return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    // }

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
			// Use "invalid" to make gas estimation work
			//switch success case 0 { invalid }
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

	// function pairingProd4(
	// 		G1Point memory a1, G2Point memory a2,
	// 		G1Point memory b1, G2Point memory b2,
	// 		G1Point memory c1, G2Point memory c2,
	// 		G1Point memory d1, G2Point memory d2
	// ) view internal returns (bool) {
	// 	G1Point[] memory p1 = new G1Point[](4);
	// 	G2Point[] memory p2 = new G2Point[](4);
	// 	p1[0] = a1;
	// 	p1[1] = b1;
	// 	p1[2] = c1;
	// 	p1[3] = d1;
	// 	p2[0] = a2;
	// 	p2[1] = b2;
	// 	p2[2] = c2;
	// 	p2[3] = d2;
	// 	return pairing(p1, p2);
	// }
	
	uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
	// uint256 internal constant TWISTBX = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    // uint256 internal constant TWISTBY = 0x9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2;
    // uint internal constant PTXX = 0;
    // uint internal constant PTXY = 1;
    // uint internal constant PTYX = 2;
    // uint internal constant PTYY = 3;
    // uint internal constant PTZX = 4;
    // uint internal constant PTZY = 5;

    // /**
    //  * @notice Add two twist points
    //  * @param pt1xx Coefficient 1 of x on point 1
    //  * @param pt1xy Coefficient 2 of x on point 1
    //  * @param pt1yx Coefficient 1 of y on point 1
    //  * @param pt1yy Coefficient 2 of y on point 1
    //  * @param pt2xx Coefficient 1 of x on point 2
    //  * @param pt2xy Coefficient 2 of x on point 2
    //  * @param pt2yx Coefficient 1 of y on point 2
    //  * @param pt2yy Coefficient 2 of y on point 2
    //  * @return (pt3xx, pt3xy, pt3yx, pt3yy)
    //  */
    // function ECTwistAdd(
    //     uint256 pt1xx, uint256 pt1xy,
    //     uint256 pt1yx, uint256 pt1yy,
    //     uint256 pt2xx, uint256 pt2xy,
    //     uint256 pt2yx, uint256 pt2yy
    // ) public view returns (
    //     uint256, uint256,
    //     uint256, uint256
    // ) {
    //     if (
    //         pt1xx == 0 && pt1xy == 0 &&
    //         pt1yx == 0 && pt1yy == 0
    //     ) {
    //         if (!(
    //             pt2xx == 0 && pt2xy == 0 &&
    //             pt2yx == 0 && pt2yy == 0
    //         )) {
    //             assert(_isOnCurve(
    //                 pt2xx, pt2xy,
    //                 pt2yx, pt2yy
    //             ));
    //         }
    //         return (
    //             pt2xx, pt2xy,
    //             pt2yx, pt2yy
    //         );
    //     } else if (
    //         pt2xx == 0 && pt2xy == 0 &&
    //         pt2yx == 0 && pt2yy == 0
    //     ) {
    //         assert(_isOnCurve(
    //             pt1xx, pt1xy,
    //             pt1yx, pt1yy
    //         ));
    //         return (
    //             pt1xx, pt1xy,
    //             pt1yx, pt1yy
    //         );
    //     }

    //     assert(_isOnCurve(
    //         pt1xx, pt1xy,
    //         pt1yx, pt1yy
    //     ));
    //     assert(_isOnCurve(
    //         pt2xx, pt2xy,
    //         pt2yx, pt2yy
    //     ));

    //     uint256[6] memory pt3 = _ECTwistAddJacobian(
    //         pt1xx, pt1xy,
    //         pt1yx, pt1yy,
    //         1,     0,
    //         pt2xx, pt2xy,
    //         pt2yx, pt2yy,
    //         1,     0
    //     );

    //     return _fromJacobian(
    //         pt3[PTXX], pt3[PTXY],
    //         pt3[PTYX], pt3[PTYY],
    //         pt3[PTZX], pt3[PTZY]
    //     );
    // }

    // /**
    //  * @notice Multiply a twist point by a scalar
    //  * @param s     Scalar to multiply by
    //  * @param pt1xx Coefficient 1 of x
    //  * @param pt1xy Coefficient 2 of x
    //  * @param pt1yx Coefficient 1 of y
    //  * @param pt1yy Coefficient 2 of y
    //  * @return (pt2xx, pt2xy, pt2yx, pt2yy)
    //  */
    // function ECTwistMul(
    //     uint256 s,
    //     uint256 pt1xx, uint256 pt1xy,
    //     uint256 pt1yx, uint256 pt1yy
    // ) public view returns (
    //     uint256, uint256,
    //     uint256, uint256
    // ) {
    //     uint256 pt1zx = 1;
    //     if (
    //         pt1xx == 0 && pt1xy == 0 &&
    //         pt1yx == 0 && pt1yy == 0
    //     ) {
    //         pt1xx = 1;
    //         pt1yx = 1;
    //         pt1zx = 0;
    //     } else {
    //         assert(_isOnCurve(
    //             pt1xx, pt1xy,
    //             pt1yx, pt1yy
    //         ));
    //     }

    //     uint256[6] memory pt2 = _ECTwistMulJacobian(
    //         s,
    //         pt1xx, pt1xy,
    //         pt1yx, pt1yy,
    //         pt1zx, 0
    //     );

    //     return _fromJacobian(
    //         pt2[PTXX], pt2[PTXY],
    //         pt2[PTYX], pt2[PTYY],
    //         pt2[PTZX], pt2[PTZY]
    //     );
    // }

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

    // function _FQ2Mul(
    //     uint256 xx, uint256 xy,
    //     uint256 yx, uint256 yy
    // ) internal pure returns (uint256, uint256) {
    //     return (
    //         submod2(mulmod(xx, yx, FIELD_MODULUS), mulmod(xy, yy, FIELD_MODULUS), FIELD_MODULUS),
    //         addmod(mulmod(xx, yy, FIELD_MODULUS), mulmod(xy, yx, FIELD_MODULUS), FIELD_MODULUS)
    //     );
    // }

    // function _FQ2Muc(
    //     uint256 xx, uint256 xy,
    //     uint256 c
    // ) internal pure returns (uint256, uint256) {
    //     return (
    //         mulmod(xx, c, FIELD_MODULUS),
    //         mulmod(xy, c, FIELD_MODULUS)
    //     );
    // }

    // function _FQ2Add(
    //     uint256 xx, uint256 xy,
    //     uint256 yx, uint256 yy
    // ) internal pure returns (uint256, uint256) {
    //     return (
    //         addmod(xx, yx, FIELD_MODULUS),
    //         addmod(xy, yy, FIELD_MODULUS)
    //     );
    // }

    // function _FQ2Sub(
    //     uint256 xx, uint256 xy,
    //     uint256 yx, uint256 yy
    // ) internal pure returns (uint256 rx, uint256 ry) {
    //     return (
    //         submod2(xx, yx, FIELD_MODULUS),
    //         submod2(xy, yy, FIELD_MODULUS)
    //     );
    // }

    // function _FQ2Div(
    //     uint256 xx, uint256 xy,
    //     uint256 yx, uint256 yy
    // ) internal view returns (uint256, uint256) {
    //     (yx, yy) = _FQ2Inv(yx, yy);
    //     return _FQ2Mul(xx, xy, yx, yy);
    // }

    // function _FQ2Inv(uint256 x, uint256 y) internal view returns (uint256, uint256) {
    //     uint256 inv = _modInv(addmod(mulmod(y, y, FIELD_MODULUS), mulmod(x, x, FIELD_MODULUS), FIELD_MODULUS), FIELD_MODULUS);
    //     return (
    //         mulmod(x, inv, FIELD_MODULUS),
    //         FIELD_MODULUS - mulmod(y, inv, FIELD_MODULUS)
    //     );
    // }

    // function _isOnCurve(
    //     uint256 xx, uint256 xy,
    //     uint256 yx, uint256 yy
    // ) internal pure returns (bool) {
    //     uint256 yyx;
    //     uint256 yyy;
    //     uint256 xxxx;
    //     uint256 xxxy;
    //     (yyx, yyy) = _FQ2Mul(yx, yy, yx, yy);
    //     (xxxx, xxxy) = _FQ2Mul(xx, xy, xx, xy);
    //     (xxxx, xxxy) = _FQ2Mul(xxxx, xxxy, xx, xy);
    //     (yyx, yyy) = _FQ2Sub(yyx, yyy, xxxx, xxxy);
    //     (yyx, yyy) = _FQ2Sub(yyx, yyy, TWISTBX, TWISTBY);
    //     return yyx == 0 && yyy == 0;
    // }

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


    // function _fromJacobian(
    //     uint256 pt1xx, uint256 pt1xy,
    //     uint256 pt1yx, uint256 pt1yy,
    //     uint256 pt1zx, uint256 pt1zy
    // ) internal view returns (
    //     uint256 pt2xx, uint256 pt2xy,
    //     uint256 pt2yx, uint256 pt2yy
    // ) {
    //     uint256 invzx;
    //     uint256 invzy;
    //     (invzx, invzy) = _FQ2Inv(pt1zx, pt1zy);
    //     (pt2xx, pt2xy) = _FQ2Mul(pt1xx, pt1xy, invzx, invzy);
    //     (pt2yx, pt2yy) = _FQ2Mul(pt1yx, pt1yy, invzx, invzy);
    // }

    // function _ECTwistAddJacobian(
    //     uint256 pt1xx, uint256 pt1xy,
    //     uint256 pt1yx, uint256 pt1yy,
    //     uint256 pt1zx, uint256 pt1zy,
    //     uint256 pt2xx, uint256 pt2xy,
    //     uint256 pt2yx, uint256 pt2yy,
    //     uint256 pt2zx, uint256 pt2zy) internal pure returns (uint256[6] memory pt3) {
    //         if (pt1zx == 0 && pt1zy == 0) {
    //             (
    //                 pt3[PTXX], pt3[PTXY],
    //                 pt3[PTYX], pt3[PTYY],
    //                 pt3[PTZX], pt3[PTZY]
    //             ) = (
    //                 pt2xx, pt2xy,
    //                 pt2yx, pt2yy,
    //                 pt2zx, pt2zy
    //             );
    //             return pt3;
    //         } else if (pt2zx == 0 && pt2zy == 0) {
    //             (
    //                 pt3[PTXX], pt3[PTXY],
    //                 pt3[PTYX], pt3[PTYY],
    //                 pt3[PTZX], pt3[PTZY]
    //             ) = (
    //                 pt1xx, pt1xy,
    //                 pt1yx, pt1yy,
    //                 pt1zx, pt1zy
    //             );
    //             return pt3;
    //         }

    //         (pt2yx,     pt2yy)     = _FQ2Mul(pt2yx, pt2yy, pt1zx, pt1zy); // U1 = y2 * z1
    //         (pt3[PTYX], pt3[PTYY]) = _FQ2Mul(pt1yx, pt1yy, pt2zx, pt2zy); // U2 = y1 * z2
    //         (pt2xx,     pt2xy)     = _FQ2Mul(pt2xx, pt2xy, pt1zx, pt1zy); // V1 = x2 * z1
    //         (pt3[PTZX], pt3[PTZY]) = _FQ2Mul(pt1xx, pt1xy, pt2zx, pt2zy); // V2 = x1 * z2

    //         if (pt2xx == pt3[PTZX] && pt2xy == pt3[PTZY]) {
    //             if (pt2yx == pt3[PTYX] && pt2yy == pt3[PTYY]) {
    //                 (
    //                     pt3[PTXX], pt3[PTXY],
    //                     pt3[PTYX], pt3[PTYY],
    //                     pt3[PTZX], pt3[PTZY]
    //                 ) = _ECTwistDoubleJacobian(pt1xx, pt1xy, pt1yx, pt1yy, pt1zx, pt1zy);
    //                 return pt3;
    //             }
    //             (
    //                 pt3[PTXX], pt3[PTXY],
    //                 pt3[PTYX], pt3[PTYY],
    //                 pt3[PTZX], pt3[PTZY]
    //             ) = (
    //                 1, 0,
    //                 1, 0,
    //                 0, 0
    //             );
    //             return pt3;
    //         }

    //         (pt2zx,     pt2zy)     = _FQ2Mul(pt1zx, pt1zy, pt2zx,     pt2zy);     // W = z1 * z2
    //         (pt1xx,     pt1xy)     = _FQ2Sub(pt2yx, pt2yy, pt3[PTYX], pt3[PTYY]); // U = U1 - U2
    //         (pt1yx,     pt1yy)     = _FQ2Sub(pt2xx, pt2xy, pt3[PTZX], pt3[PTZY]); // V = V1 - V2
    //         (pt1zx,     pt1zy)     = _FQ2Mul(pt1yx, pt1yy, pt1yx,     pt1yy);     // V_squared = V * V
    //         (pt2yx,     pt2yy)     = _FQ2Mul(pt1zx, pt1zy, pt3[PTZX], pt3[PTZY]); // V_squared_times_V2 = V_squared * V2
    //         (pt1zx,     pt1zy)     = _FQ2Mul(pt1zx, pt1zy, pt1yx,     pt1yy);     // V_cubed = V * V_squared
    //         (pt3[PTZX], pt3[PTZY]) = _FQ2Mul(pt1zx, pt1zy, pt2zx,     pt2zy);     // newz = V_cubed * W
    //         (pt2xx,     pt2xy)     = _FQ2Mul(pt1xx, pt1xy, pt1xx,     pt1xy);     // U * U
    //         (pt2xx,     pt2xy)     = _FQ2Mul(pt2xx, pt2xy, pt2zx,     pt2zy);     // U * U * W
    //         (pt2xx,     pt2xy)     = _FQ2Sub(pt2xx, pt2xy, pt1zx,     pt1zy);     // U * U * W - V_cubed
    //         (pt2zx,     pt2zy)     = _FQ2Muc(pt2yx, pt2yy, 2);                    // 2 * V_squared_times_V2
    //         (pt2xx,     pt2xy)     = _FQ2Sub(pt2xx, pt2xy, pt2zx,     pt2zy);     // A = U * U * W - V_cubed - 2 * V_squared_times_V2
    //         (pt3[PTXX], pt3[PTXY]) = _FQ2Mul(pt1yx, pt1yy, pt2xx,     pt2xy);     // newx = V * A
    //         (pt1yx,     pt1yy)     = _FQ2Sub(pt2yx, pt2yy, pt2xx,     pt2xy);     // V_squared_times_V2 - A
    //         (pt1yx,     pt1yy)     = _FQ2Mul(pt1xx, pt1xy, pt1yx,     pt1yy);     // U * (V_squared_times_V2 - A)
    //         (pt1xx,     pt1xy)     = _FQ2Mul(pt1zx, pt1zy, pt3[PTYX], pt3[PTYY]); // V_cubed * U2
    //         (pt3[PTYX], pt3[PTYY]) = _FQ2Sub(pt1yx, pt1yy, pt1xx,     pt1xy);     // newy = U * (V_squared_times_V2 - A) - V_cubed * U2
    // }

    // function _ECTwistDoubleJacobian(
    //     uint256 pt1xx, uint256 pt1xy,
    //     uint256 pt1yx, uint256 pt1yy,
    //     uint256 pt1zx, uint256 pt1zy
    // ) internal pure returns (
    //     uint256 pt2xx, uint256 pt2xy,
    //     uint256 pt2yx, uint256 pt2yy,
    //     uint256 pt2zx, uint256 pt2zy
    // ) {
    //     (pt2xx, pt2xy) = _FQ2Muc(pt1xx, pt1xy, 3);            // 3 * x
    //     (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1xx, pt1xy); // W = 3 * x * x
    //     (pt1zx, pt1zy) = _FQ2Mul(pt1yx, pt1yy, pt1zx, pt1zy); // S = y * z
    //     (pt2yx, pt2yy) = _FQ2Mul(pt1xx, pt1xy, pt1yx, pt1yy); // x * y
    //     (pt2yx, pt2yy) = _FQ2Mul(pt2yx, pt2yy, pt1zx, pt1zy); // B = x * y * S
    //     (pt1xx, pt1xy) = _FQ2Mul(pt2xx, pt2xy, pt2xx, pt2xy); // W * W
    //     (pt2zx, pt2zy) = _FQ2Muc(pt2yx, pt2yy, 8);            // 8 * B
    //     (pt1xx, pt1xy) = _FQ2Sub(pt1xx, pt1xy, pt2zx, pt2zy); // H = W * W - 8 * B
    //     (pt2zx, pt2zy) = _FQ2Mul(pt1zx, pt1zy, pt1zx, pt1zy); // S_squared = S * S
    //     (pt2yx, pt2yy) = _FQ2Muc(pt2yx, pt2yy, 4);            // 4 * B
    //     (pt2yx, pt2yy) = _FQ2Sub(pt2yx, pt2yy, pt1xx, pt1xy); // 4 * B - H
    //     (pt2yx, pt2yy) = _FQ2Mul(pt2yx, pt2yy, pt2xx, pt2xy); // W * (4 * B - H)
    //     (pt2xx, pt2xy) = _FQ2Muc(pt1yx, pt1yy, 8);            // 8 * y
    //     (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1yx, pt1yy); // 8 * y * y
    //     (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt2zx, pt2zy); // 8 * y * y * S_squared
    //     (pt2yx, pt2yy) = _FQ2Sub(pt2yx, pt2yy, pt2xx, pt2xy); // newy = W * (4 * B - H) - 8 * y * y * S_squared
    //     (pt2xx, pt2xy) = _FQ2Muc(pt1xx, pt1xy, 2);            // 2 * H
    //     (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1zx, pt1zy); // newx = 2 * H * S
    //     (pt2zx, pt2zy) = _FQ2Mul(pt1zx, pt1zy, pt2zx, pt2zy); // S * S_squared
    //     (pt2zx, pt2zy) = _FQ2Muc(pt2zx, pt2zy, 8);            // newz = 8 * S * S_squared
    // }

    // function _ECTwistMulJacobian(
    //     uint256 d,
    //     uint256 pt1xx, uint256 pt1xy,
    //     uint256 pt1yx, uint256 pt1yy,
    //     uint256 pt1zx, uint256 pt1zy
    // ) internal pure returns (uint256[6] memory pt2) {
    //     while (d != 0) {
    //         if ((d & 1) != 0) {
    //             pt2 = _ECTwistAddJacobian(
    //                 pt2[PTXX], pt2[PTXY],
    //                 pt2[PTYX], pt2[PTYY],
    //                 pt2[PTZX], pt2[PTZY],
    //                 pt1xx, pt1xy,
    //                 pt1yx, pt1yy,
    //                 pt1zx, pt1zy);
    //         }
    //         (
    //             pt1xx, pt1xy,
    //             pt1yx, pt1yy,
    //             pt1zx, pt1zy
    //         ) = _ECTwistDoubleJacobian(
    //             pt1xx, pt1xy,
    //             pt1yx, pt1yy,
    //             pt1zx, pt1zy
    //         );

    //         d = d / 2;
    //     }
    // }

	function equals(
			G1Point memory a, G1Point memory b			
	) view internal returns (bool) {		
		return a.X==b.X && a.Y==b.Y;
	}

	// function equals2(
	// 		G2Point memory a, G2Point memory b			
	// ) view internal returns (bool) {		
	// 	return a.X[0]==b.X[0] && a.X[1]==b.X[1] && a.Y[0]==b.Y[0] && a.Y[1]==b.Y[1];
	// }

	// function HashToG1(string memory str) public payable returns (G1Point memory){
		
	// 	return g1mul(P1(), uint256(keccak256(abi.encodePacked(str))));
	// }

	function negate(G1Point memory p) public payable returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    }

    // function checkkey_eq2(
	// 	G2Point memory EK1Arr,
	// 	G2Point memory EK1pArr,
	// 	uint256 c,
	// 	uint256 w3
	// )  
	// public payable
	// 	returns (bool)
	// {
	// 	ECTwistPoint memory tmp1;

	// 	(tmp1.xx,tmp1.xy,tmp1.yx,tmp1.yy)=ECTwistMul(c,EK1Arr.X[1],EK1Arr.X[0],EK1Arr.Y[1],EK1Arr.Y[0]);

	// 	ECTwistPoint memory tmp2;
	// 	(tmp2.xx,tmp2.xy,tmp2.yx,tmp2.yy)=ECTwistAdd(EK1pArr.X[1],EK1pArr.X[0],EK1pArr.Y[1],EK1pArr.Y[0],tmp1.xx,tmp1.xy,tmp1.yx,tmp1.yy);
		
	// 	(tmp1.xx,tmp1.xy,tmp1.yx,tmp1.yy)=ECTwistMul(w3, G2.X[1], G2.X[0], G2.Y[1], G2.Y[0]);  //G2 generator

	// 	require(tmp1.xx==tmp2.xx && tmp1.xy==tmp2.xy && tmp1.yx==tmp2.yx && tmp1.yy==tmp2.yy);
	// 	return (true);
	// }
    // G1Point Checkkeyresult;
	// function Checkkey(
	// 	G1Point[][] memory p1,
	// 	G2Point[][] memory p2, 
	// 	uint256[][] memory tmp,
    //     string  memory gid, 
    //     string[]  memory attr,
    //     G1Point memory pk)
    // public payable returns (G1Point memory Checkkeyresult)
	// {
    //     for (uint256 i=0;i<p1.length;i++){
    //         require(equals(g1add(p1[i][1],g1mul(p1[i][0],tmp[i][0])),
    //             g1add(g1add(g1mul(pk, tmp[i][1]),g1mul(HashToG1(gid), tmp[i][2])), g1mul(HashToG1(attr[i]), tmp[i][3]))),"eq1");  //eq1 TODO not work
    //         require(checkkey_eq2(p2[i][0],p2[i][1],tmp[i][0],tmp[i][3]),"eq2");  //eq2

 	// 		 require(pairingProd4(pk,p2[i][2],HashToG1(gid),p2[i][3],HashToG1(attr[i]),p2[i][0],negate(p1[i][1]), P2()),"eq3");  //eq3
	// 	}
	//     return Checkkeyresult;
	// }

//     function Checkkeyp(
//         G1Point[][] memory p1,
//         G2Point[][] memory p2,
//         uint256[][] memory tmp,
//         string  memory gid,
//         string[]  memory attr,
//         G1Point memory pk)
//     public
//     returns (bool)
//     {
//         G1Point memory hg1;
//         G1Point memory hgid= HashToG1(gid);
//         for (uint256 i=0;i<p1.length;i++){
//             hg1= HashToG1(attr[i]);
//             require(equals(g1add(p1[i][1],g1mul(p1[i][0],tmp[i][0])),
//                 g1add(g1add(g1mul(pk, tmp[i][1]),g1mul(hgid, tmp[i][2])), g1mul(hg1, tmp[i][3]))),"eq1");  //eq1 TODO not work
//             require(equals(g1mul(G1,tmp[i][3]), g1add(p1[i][4],g1mul(p1[i][2],tmp[i][0]))));  //eq2
//             G1Point[] memory p1Arr = new G1Point[](2);
// 		    G2Point[] memory p2Arr = new G2Point[](2);
//             p1Arr[0] = negate(p1[i][2]);
//             p1Arr[1] = G1;
//             p2Arr[0] = G2;
//             p2Arr[1] = p2[i][0];
//             require(pairing(p1Arr, p2Arr));  //eq3
// //            require(pairingProd2(negate(p1[i][2]), G2, G1, p2[i][0]));  //eq3
//             G1Point[] memory pp1= new G1Point[](4);
//             pp1[0]=pk;
//             pp1[1]=hgid;
//             pp1[2]=hg1;
//             pp1[3]=negate(p1[i][1]);
//             G2Point[] memory pp2= new G2Point[](4);
//             pp2[0]=p2[i][2];
//             pp2[1]=p2[i][3];
//             pp2[2]=p2[i][0];
//             pp2[3]=G2;
//             require(pairing(pp1, pp2));
// //            pairingProd4(pk,p2[i][2],hgid,p2[i][3],hg1,p2[i][0],negate(p1[i][1]), G2));  //eq4
//         }
//         return true;
//     }


    // ========================== PVGSS-SSS Verification ===============================

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

    // function getChildren(uint256 nodeId) public view returns (uint256[] memory) {
    //     return nodes[nodeId].Children;
    // }

    // function getNodeData(uint256 nodeId) public view returns (bool, uint256, uint256, uint256) {
    //     Node storage node = nodes[nodeId];
    //     return (node.IsLeaf,node.Childrennum,node.T,node.Idx);
    // }

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
    function PVGSSVerify(G1Point[] memory C,G1Point[] memory PK,uint256 nodeId,uint256[] memory Q, uint256 startIdx) public payable returns (bool) {
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
        }
        return true;
    }

    function GetVerifyResult() public view returns (bool []memory) {
        return VerifyResult;
    }

    // Upload Prfs
    function UploadProof(G1Point[] memory cp, uint256 xc, uint256 shat, uint256[] memory shatArray) public payable {
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

    function GetKeyVrfResult() public view returns (bool []memory) {
        return KeyVerifyResult;
    }

    // ========================== PVGSS-SSS Verification End ===============================

	struct ECTwistPoint {
    	uint256 xx;
    	uint256 xy;
    	uint256 yx;
    	uint256 yy;
	}

    //参考 https://github.com/Uniswap/v2-core/tree/master
    
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

    //TODO:check
    mapping(address => G2Point) private pubkey2;

    uint constant MINIMAL_EXCHANGER_STAKE = 1 ether; 
    uint constant MINIMAL_WATCHER_STAKE = 1 ether; 

    struct Order {
        address seller;
        address tokenSell; // Token to sell (e.g., ETH)
        uint256 amountSell; // Amount to sell (e.g., 2 ETH)
        address tokenBuy; // Token to buy (e.g., USDT)
        uint256 amountBuy; // Amount to buy (e.g., 7000 USDT)
        bool isActive;
    }
    // Store orders
    mapping(uint256 => Order) public orders;
    uint256 public nextOrderId;


    // State variable to track session state
    // Active: session created  halfSwap1:one execute swap1  finishSwap1: two execute swap1
    // halfSwap2: one execute swap2
    enum SessionState { Active, halfSwap1, finishSwap1, halfSwap2, Complain, Success, Failure }
    struct Session {
        SessionState state; // Session state
        address[] exchangers; // seller as exchanger[0], buyer as exchanger[1] in the session
        address[3] watchers; // Watchers in the session
        mapping(address => G1Point) shares; // decshare collect
        mapping(address => G1Point) Cshares1;
        mapping(address => G1Point) Cshares2;
        uint256 expiration1; // First expiration time
        uint256 expiration2; // Second expiration time
        bool[2] seller_flag;
        bool[2] buyer_flag;   
        mapping(address => bool) watcher_flag; 
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
    event SessionCreated(uint256 indexed orderId, address seller, address buyer, address[3] watchers, uint256 expiration1, uint256 expiration2);


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

    // Withdraw tokens from the contract
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
    function acceptOrder(uint256 orderId) external {
        Order storage _order = orders[orderId];
        require(_order.isActive, "Order is not active");
        require(balances[msg.sender][_order.tokenBuy] >= _order.amountBuy, "Insufficient balance to accept order");

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
        newSession.expiration1 = block.timestamp + 6 minutes; // Set expiration1
        newSession.expiration2 = block.timestamp + 10 minutes; // Set expiration2
        
        //add 3 watchers
        uint256 randomIndex = uint256(keccak256(abi.encodePacked(block.timestamp, orderId)));
        for (uint256 i = 0; i < 3; i++) {
            // newSession.watchers[i] = watcherList[(randomIndex + i) % watcherList.length];
            newSession.watchers[i] = watcherList[i];
            newSession.watcher_flag[newSession.watchers[i]] = false;
        }
        
        emit TokensFrozen(_order.tokenBuy, msg.sender, _order.amountBuy, orderId);
        emit SessionCreated(orderId, _order.seller, msg.sender, newSession.watchers, newSession.expiration1, newSession.expiration2);
    }

    //session swap1: shares validity check
    function swap1(uint256 id, G1Point[] memory C, G1Point[] memory PK, uint256 nodeId,uint256[] memory Q, uint256 startIdx) external onlyExchanger(id){
        Session storage session = sessions[id];

        // Check session state
        require(session.state == SessionState.Active || session.state == SessionState.halfSwap1, "Session state is invalid for swap1");

        // Check Expiration1
        require(block.timestamp <= session.expiration1, "Session is expired t1");

        // Check stake
        require(stakedETH[msg.sender] >= MINIMAL_EXCHANGER_STAKE, "Insufficient stake");
        // Check validity of shares PVGSSVerify()
        require(PVGSSVerify(C, PK, nodeId, Q, startIdx) == true, "pvgss verify failed");

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

        // Invoke PVGSSKeyVrf and store decShare
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

    //complaint
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

        // case 1 in paper:optimistic
        if (session.state == SessionState.Success) {
            // Both exchangers have completed swap2
            incentivizeAllWatchers(session);
        } else if (session.state == SessionState.Complain) {
            if (getSubmittedWatchersCount(session) > 1) { //TODO: set threshold=2 now
                // case 2 in paper: dispute resolved  
                session.state = SessionState.Success;
            } else {
                // case 6 in paper: dispute unresolved
                session.state = SessionState.Failure;
            }
            incentivizePartWatchers(session);
            penalizeFaultyExchangers(session);
        } else {
            //case 4 in paper: at least one not swap1
            if (session.state == SessionState.Active || session.state == SessionState.halfSwap1) {
                penalizeFaultyExchangers(session);
            } else if (session.state == SessionState.finishSwap1) {
                //case 5 in paper: both finish swap1
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
}

//DEX test
//register account1 to account10 (account 3-10 as watcher)
//stake eth  account1 to account10
//account1 deposit 10 PVETH   account2 deposit 10000 PVUSDT

//account1 create order : (sell 1 PVETH to 3000 PVUSDT)  call createOrder(address tokenSell, uint256 amountSell, address tokenBuy, uint256 amountBuy)
//---log:
// TokensFrozen Event:
//   Token: 0x1FFB519EeE5AAc2c95994Df195c0E636a9F55610
//   From: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Amount: 1000000000000000000
//   Session ID: 0
// OrderCreated Event:
//   Order ID: 0
//   Seller: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Token Sell: 0x1FFB519EeE5AAc2c95994Df195c0E636a9F55610
//   Amount Sell: 1000000000000000000
//   Token Buy: 0x7621eea52693Fb18022BD36d8C772F8D59CceE61
//   Amount Buy: 3000000000000000000000
// On-chain CreateOrder Gas cost =  203476

//account2 accept order :  call acceptOrder(uint256 orderId)

// TokensFrozen Event:
//   Token: 0x7621eea52693Fb18022BD36d8C772F8D59CceE61
//   From: 0xf18522dbD0E6eA3B4E0A932588a12A876245E98d
//   Amount: 3000000000000000000000
//   Session ID: 0
// SessionCreated Event:
//   Order ID: 0
//   Seller: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Buyer: 0xf18522dbD0E6eA3B4E0A932588a12A876245E98d
//   Watchers: [0xf18522dbD0E6eA3B4E0A932588a12A876245E98d 0x83f1eAA3A744c510DBc76C3381d29A9f2AE98B3d 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1]
//   Expiration1: 1737169842
//   Expiration2: 1737170262

//get watchers through event and set access structure


//case1: optimistic   pass  TODO: test pvgssverify
//account2 call swap1 in t1


//account1 call swap1 and swap2 in t1

//account2 call swap2 in t1

//after t2 determine


// account2 swap1 in t1
// SessionStateUpdated Event:
//   Session ID: 1
//   State: 1
// On-chain Swap1 Gas cost =  298753
// account1 swap1 in t1
// SessionStateUpdated Event:
//   Session ID: 1
//   State: 2
// account1 swap2 in t1
// On-chain Swap2 Gas cost =  243971
// account2 swap2 in t1

// account2 determine after t2
// Incentivized Event:
//   Exchanger: 0x83f1eAA3A744c510DBc76C3381d29A9f2AE98B3d
//   Amount: 10000000000000000
// Incentivized Event:
//   Exchanger: 0x094926F5Fc17638e14C74C3a5d3cf467fA1feF7C
//   Amount: 10000000000000000
// Incentivized Event:
//   Exchanger: 0x70a5a954Cd03ae4E94b844bb7DffAf8b34B5A6cF
//   Amount: 10000000000000000
// SessionStateUpdated Event:
//   Session ID: 1
//   State: 5
// On-chain Determine Gas cost =  94321


//case2: dispute solved in t2

//account2 call swap1 in t1

//account1 call swap1 and swap2 in t1

//** after t1, account1 complain

//3 watchers call submitWatcherShare(id, decShare)

// Listening for all events...
// TokensFrozen Event:
//   Token: 0x1FFB519EeE5AAc2c95994Df195c0E636a9F55610
//   From: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Amount: 10000000000000000
//   Session ID: 5
// OrderCreated Event:
//   Order ID: 5
//   Seller: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Token Sell: 0x1FFB519EeE5AAc2c95994Df195c0E636a9F55610
//   Amount Sell: 10000000000000000
//   Token Buy: 0x7621eea52693Fb18022BD36d8C772F8D59CceE61
//   Amount Buy: 30000000000000000000
// On-chain CreateOrder Gas cost =  188464
// On-chain AcceptOrder Gas cost =  241204
// TokensFrozen Event:
//   Token: 0x7621eea52693Fb18022BD36d8C772F8D59CceE61
//   From: 0xf18522dbD0E6eA3B4E0A932588a12A876245E98d
//   Amount: 30000000000000000000
//   Session ID: 5
// SessionCreated Event:
//   Order ID: 5
//   Seller: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Buyer: 0xf18522dbD0E6eA3B4E0A932588a12A876245E98d
//   Watchers: [0x83f1eAA3A744c510DBc76C3381d29A9f2AE98B3d 0x094926F5Fc17638e14C74C3a5d3cf467fA1feF7C 0x70a5a954Cd03ae4E94b844bb7DffAf8b34B5A6cF]
//   Expiration1: 1737281305
//   Expiration2: 1737281545
// Of-chain Verfication result =  true
// decshares[2]: 0x140002001e0
// Of-chain KeyVerification result =  [true true true true true]
// account2 swap1 in t1
// SessionStateUpdated Event:
//   Session ID: 5
//   State: 1
// On-chain Swap1 Gas cost =  298741
// On-chain Verfication result =  []
// account1 swap1 in t1
// SessionStateUpdated Event:
//   Session ID: 5
//   State: 2
// account1 swap2 in t1
// On-chain Swap2 Gas cost =  214021
// sleep until t2
// account1 complain in t2
// UserNotified Event:
//   Session ID: 5
//   User: 0x83f1eAA3A744c510DBc76C3381d29A9f2AE98B3d
// UserNotified Event:
//   Session ID: 5
//   User: 0x094926F5Fc17638e14C74C3a5d3cf467fA1feF7C
// UserNotified Event:
//   Session ID: 5
//   User: 0x70a5a954Cd03ae4E94b844bb7DffAf8b34B5A6cF
// ComplaintFiled Event:
//   Complainer: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Session ID: 5
// On-chain Complain Gas cost =  41219
// enough watchers submit share in t2
// On-chain SubmitWatcherShare Gas cost =  227367
// On-chain SubmitWatcherShare Gas cost =  228348
// On-chain SubmitWatcherShare Gas cost =  229377
// sleep until t2 end
// value: 3000000000000000000000
// account2 determine after t2
// On-chain Determine Gas cost =  116517
// Incentivized Event:
//   Exchanger: 0x83f1eAA3A744c510DBc76C3381d29A9f2AE98B3d
//   Amount: 10000000000000000
// Incentivized Event:
//   Exchanger: 0x094926F5Fc17638e14C74C3a5d3cf467fA1feF7C
//   Amount: 10000000000000000
// Incentivized Event:
//   Exchanger: 0x70a5a954Cd03ae4E94b844bb7DffAf8b34B5A6cF
//   Amount: 10000000000000000
// Penalized Event:
//   Exchanger: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Amount: 100000000000000000
// Penalized Event:
//   Exchanger: 0xf18522dbD0E6eA3B4E0A932588a12A876245E98d
//   Amount: 100000000000000000
// SessionStateUpdated Event:
//   Session ID: 5
//   State: 5
// value: 3030000000000000000000


//case6: dispute not solved in t2

//account2 call swap1 in t1

//account1 call swap1 and swap2 in t1

//** after t1, account1 complain

//0 or 1 watchers call submitWatcherShare(id, decShare)




//case 4 in paper: at least one not swap1  测试通过

//no one call swap1 in t1

//after t2 determine



// account2 determine after t2
// Listening for all events...
// Penalized Event:
//   Exchanger: 0x98a6440BD41B3028f97B8b3d5bB1C59A96DC67a1
//   Amount: 100000000000000000
// Penalized Event:
//   Exchanger: 0xf18522dbD0E6eA3B4E0A932588a12A876245E98d
//   Amount: 100000000000000000
// SessionStateUpdated Event:
//   Session ID: 0
//   State: 6
// On-chain Determine Gas cost =  75151


//case 5 in paper: both finish swap1

//account2 call swap1 in t1

//account1 call swap1 in t1

//after t2 determine
