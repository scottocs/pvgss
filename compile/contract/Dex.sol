pragma solidity ^0.8.0;



interface IERC20 {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
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
    function expMod(uint256 _base, uint256 _exponent, uint256 _modulus)
        internal view returns (uint256 retval)
    {
        bool success;
        uint256[1] memory output;
        uint[6] memory input;
        input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
        input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
        input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
        input[3] = _base;
        input[4] = _exponent;
        input[5] = _modulus;
        assembly {
            success := staticcall(sub(gas(), 2000), 5, input, 0xc0, output, 0x20)
            // Use "invalid" to make gas estimation work
            //switch success case 0 { invalid }
        }
        require(success);
        return output[0];
    }


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

	function pairingProd4(
			G1Point memory a1, G2Point memory a2,
			G1Point memory b1, G2Point memory b2,
			G1Point memory c1, G2Point memory c2,
			G1Point memory d1, G2Point memory d2
	) view internal returns (bool) {
		G1Point[] memory p1 = new G1Point[](4);
		G2Point[] memory p2 = new G2Point[](4);
		p1[0] = a1;
		p1[1] = b1;
		p1[2] = c1;
		p1[3] = d1;
		p2[0] = a2;
		p2[1] = b2;
		p2[2] = c2;
		p2[3] = d2;
		return pairing(p1, p2);
	}
	
	uint256 internal constant FIELD_MODULUS = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
	uint256 internal constant TWISTBX = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 internal constant TWISTBY = 0x9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2;
    uint internal constant PTXX = 0;
    uint internal constant PTXY = 1;
    uint internal constant PTYX = 2;
    uint internal constant PTYY = 3;
    uint internal constant PTZX = 4;
    uint internal constant PTZY = 5;

    /**
     * @notice Add two twist points
     * @param pt1xx Coefficient 1 of x on point 1
     * @param pt1xy Coefficient 2 of x on point 1
     * @param pt1yx Coefficient 1 of y on point 1
     * @param pt1yy Coefficient 2 of y on point 1
     * @param pt2xx Coefficient 1 of x on point 2
     * @param pt2xy Coefficient 2 of x on point 2
     * @param pt2yx Coefficient 1 of y on point 2
     * @param pt2yy Coefficient 2 of y on point 2
     * @return (pt3xx, pt3xy, pt3yx, pt3yy)
     */
    function ECTwistAdd(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy
    ) public view returns (
        uint256, uint256,
        uint256, uint256
    ) {
        if (
            pt1xx == 0 && pt1xy == 0 &&
            pt1yx == 0 && pt1yy == 0
        ) {
            if (!(
                pt2xx == 0 && pt2xy == 0 &&
                pt2yx == 0 && pt2yy == 0
            )) {
                assert(_isOnCurve(
                    pt2xx, pt2xy,
                    pt2yx, pt2yy
                ));
            }
            return (
                pt2xx, pt2xy,
                pt2yx, pt2yy
            );
        } else if (
            pt2xx == 0 && pt2xy == 0 &&
            pt2yx == 0 && pt2yy == 0
        ) {
            assert(_isOnCurve(
                pt1xx, pt1xy,
                pt1yx, pt1yy
            ));
            return (
                pt1xx, pt1xy,
                pt1yx, pt1yy
            );
        }

        assert(_isOnCurve(
            pt1xx, pt1xy,
            pt1yx, pt1yy
        ));
        assert(_isOnCurve(
            pt2xx, pt2xy,
            pt2yx, pt2yy
        ));

        uint256[6] memory pt3 = _ECTwistAddJacobian(
            pt1xx, pt1xy,
            pt1yx, pt1yy,
            1,     0,
            pt2xx, pt2xy,
            pt2yx, pt2yy,
            1,     0
        );

        return _fromJacobian(
            pt3[PTXX], pt3[PTXY],
            pt3[PTYX], pt3[PTYY],
            pt3[PTZX], pt3[PTZY]
        );
    }

    /**
     * @notice Multiply a twist point by a scalar
     * @param s     Scalar to multiply by
     * @param pt1xx Coefficient 1 of x
     * @param pt1xy Coefficient 2 of x
     * @param pt1yx Coefficient 1 of y
     * @param pt1yy Coefficient 2 of y
     * @return (pt2xx, pt2xy, pt2yx, pt2yy)
     */
    function ECTwistMul(
        uint256 s,
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy
    ) public view returns (
        uint256, uint256,
        uint256, uint256
    ) {
        uint256 pt1zx = 1;
        if (
            pt1xx == 0 && pt1xy == 0 &&
            pt1yx == 0 && pt1yy == 0
        ) {
            pt1xx = 1;
            pt1yx = 1;
            pt1zx = 0;
        } else {
            assert(_isOnCurve(
                pt1xx, pt1xy,
                pt1yx, pt1yy
            ));
        }

        uint256[6] memory pt2 = _ECTwistMulJacobian(
            s,
            pt1xx, pt1xy,
            pt1yx, pt1yy,
            pt1zx, 0
        );

        return _fromJacobian(
            pt2[PTXX], pt2[PTXY],
            pt2[PTYX], pt2[PTYY],
            pt2[PTZX], pt2[PTZY]
        );
    }

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

    function _FQ2Mul(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (uint256, uint256) {
        return (
            submod2(mulmod(xx, yx, FIELD_MODULUS), mulmod(xy, yy, FIELD_MODULUS), FIELD_MODULUS),
            addmod(mulmod(xx, yy, FIELD_MODULUS), mulmod(xy, yx, FIELD_MODULUS), FIELD_MODULUS)
        );
    }

    function _FQ2Muc(
        uint256 xx, uint256 xy,
        uint256 c
    ) internal pure returns (uint256, uint256) {
        return (
            mulmod(xx, c, FIELD_MODULUS),
            mulmod(xy, c, FIELD_MODULUS)
        );
    }

    function _FQ2Add(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (uint256, uint256) {
        return (
            addmod(xx, yx, FIELD_MODULUS),
            addmod(xy, yy, FIELD_MODULUS)
        );
    }

    function _FQ2Sub(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (uint256 rx, uint256 ry) {
        return (
            submod2(xx, yx, FIELD_MODULUS),
            submod2(xy, yy, FIELD_MODULUS)
        );
    }

    function _FQ2Div(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal view returns (uint256, uint256) {
        (yx, yy) = _FQ2Inv(yx, yy);
        return _FQ2Mul(xx, xy, yx, yy);
    }

    function _FQ2Inv(uint256 x, uint256 y) internal view returns (uint256, uint256) {
        uint256 inv = _modInv(addmod(mulmod(y, y, FIELD_MODULUS), mulmod(x, x, FIELD_MODULUS), FIELD_MODULUS), FIELD_MODULUS);
        return (
            mulmod(x, inv, FIELD_MODULUS),
            FIELD_MODULUS - mulmod(y, inv, FIELD_MODULUS)
        );
    }

    function _isOnCurve(
        uint256 xx, uint256 xy,
        uint256 yx, uint256 yy
    ) internal pure returns (bool) {
        uint256 yyx;
        uint256 yyy;
        uint256 xxxx;
        uint256 xxxy;
        (yyx, yyy) = _FQ2Mul(yx, yy, yx, yy);
        (xxxx, xxxy) = _FQ2Mul(xx, xy, xx, xy);
        (xxxx, xxxy) = _FQ2Mul(xxxx, xxxy, xx, xy);
        (yyx, yyy) = _FQ2Sub(yyx, yyy, xxxx, xxxy);
        (yyx, yyy) = _FQ2Sub(yyx, yyy, TWISTBX, TWISTBY);
        return yyx == 0 && yyy == 0;
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


    function _fromJacobian(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy
    ) internal view returns (
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy
    ) {
        uint256 invzx;
        uint256 invzy;
        (invzx, invzy) = _FQ2Inv(pt1zx, pt1zy);
        (pt2xx, pt2xy) = _FQ2Mul(pt1xx, pt1xy, invzx, invzy);
        (pt2yx, pt2yy) = _FQ2Mul(pt1yx, pt1yy, invzx, invzy);
    }

    function _ECTwistAddJacobian(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy,
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy,
        uint256 pt2zx, uint256 pt2zy) internal pure returns (uint256[6] memory pt3) {
            if (pt1zx == 0 && pt1zy == 0) {
                (
                    pt3[PTXX], pt3[PTXY],
                    pt3[PTYX], pt3[PTYY],
                    pt3[PTZX], pt3[PTZY]
                ) = (
                    pt2xx, pt2xy,
                    pt2yx, pt2yy,
                    pt2zx, pt2zy
                );
                return pt3;
            } else if (pt2zx == 0 && pt2zy == 0) {
                (
                    pt3[PTXX], pt3[PTXY],
                    pt3[PTYX], pt3[PTYY],
                    pt3[PTZX], pt3[PTZY]
                ) = (
                    pt1xx, pt1xy,
                    pt1yx, pt1yy,
                    pt1zx, pt1zy
                );
                return pt3;
            }

            (pt2yx,     pt2yy)     = _FQ2Mul(pt2yx, pt2yy, pt1zx, pt1zy); // U1 = y2 * z1
            (pt3[PTYX], pt3[PTYY]) = _FQ2Mul(pt1yx, pt1yy, pt2zx, pt2zy); // U2 = y1 * z2
            (pt2xx,     pt2xy)     = _FQ2Mul(pt2xx, pt2xy, pt1zx, pt1zy); // V1 = x2 * z1
            (pt3[PTZX], pt3[PTZY]) = _FQ2Mul(pt1xx, pt1xy, pt2zx, pt2zy); // V2 = x1 * z2

            if (pt2xx == pt3[PTZX] && pt2xy == pt3[PTZY]) {
                if (pt2yx == pt3[PTYX] && pt2yy == pt3[PTYY]) {
                    (
                        pt3[PTXX], pt3[PTXY],
                        pt3[PTYX], pt3[PTYY],
                        pt3[PTZX], pt3[PTZY]
                    ) = _ECTwistDoubleJacobian(pt1xx, pt1xy, pt1yx, pt1yy, pt1zx, pt1zy);
                    return pt3;
                }
                (
                    pt3[PTXX], pt3[PTXY],
                    pt3[PTYX], pt3[PTYY],
                    pt3[PTZX], pt3[PTZY]
                ) = (
                    1, 0,
                    1, 0,
                    0, 0
                );
                return pt3;
            }

            (pt2zx,     pt2zy)     = _FQ2Mul(pt1zx, pt1zy, pt2zx,     pt2zy);     // W = z1 * z2
            (pt1xx,     pt1xy)     = _FQ2Sub(pt2yx, pt2yy, pt3[PTYX], pt3[PTYY]); // U = U1 - U2
            (pt1yx,     pt1yy)     = _FQ2Sub(pt2xx, pt2xy, pt3[PTZX], pt3[PTZY]); // V = V1 - V2
            (pt1zx,     pt1zy)     = _FQ2Mul(pt1yx, pt1yy, pt1yx,     pt1yy);     // V_squared = V * V
            (pt2yx,     pt2yy)     = _FQ2Mul(pt1zx, pt1zy, pt3[PTZX], pt3[PTZY]); // V_squared_times_V2 = V_squared * V2
            (pt1zx,     pt1zy)     = _FQ2Mul(pt1zx, pt1zy, pt1yx,     pt1yy);     // V_cubed = V * V_squared
            (pt3[PTZX], pt3[PTZY]) = _FQ2Mul(pt1zx, pt1zy, pt2zx,     pt2zy);     // newz = V_cubed * W
            (pt2xx,     pt2xy)     = _FQ2Mul(pt1xx, pt1xy, pt1xx,     pt1xy);     // U * U
            (pt2xx,     pt2xy)     = _FQ2Mul(pt2xx, pt2xy, pt2zx,     pt2zy);     // U * U * W
            (pt2xx,     pt2xy)     = _FQ2Sub(pt2xx, pt2xy, pt1zx,     pt1zy);     // U * U * W - V_cubed
            (pt2zx,     pt2zy)     = _FQ2Muc(pt2yx, pt2yy, 2);                    // 2 * V_squared_times_V2
            (pt2xx,     pt2xy)     = _FQ2Sub(pt2xx, pt2xy, pt2zx,     pt2zy);     // A = U * U * W - V_cubed - 2 * V_squared_times_V2
            (pt3[PTXX], pt3[PTXY]) = _FQ2Mul(pt1yx, pt1yy, pt2xx,     pt2xy);     // newx = V * A
            (pt1yx,     pt1yy)     = _FQ2Sub(pt2yx, pt2yy, pt2xx,     pt2xy);     // V_squared_times_V2 - A
            (pt1yx,     pt1yy)     = _FQ2Mul(pt1xx, pt1xy, pt1yx,     pt1yy);     // U * (V_squared_times_V2 - A)
            (pt1xx,     pt1xy)     = _FQ2Mul(pt1zx, pt1zy, pt3[PTYX], pt3[PTYY]); // V_cubed * U2
            (pt3[PTYX], pt3[PTYY]) = _FQ2Sub(pt1yx, pt1yy, pt1xx,     pt1xy);     // newy = U * (V_squared_times_V2 - A) - V_cubed * U2
    }

    function _ECTwistDoubleJacobian(
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy
    ) internal pure returns (
        uint256 pt2xx, uint256 pt2xy,
        uint256 pt2yx, uint256 pt2yy,
        uint256 pt2zx, uint256 pt2zy
    ) {
        (pt2xx, pt2xy) = _FQ2Muc(pt1xx, pt1xy, 3);            // 3 * x
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1xx, pt1xy); // W = 3 * x * x
        (pt1zx, pt1zy) = _FQ2Mul(pt1yx, pt1yy, pt1zx, pt1zy); // S = y * z
        (pt2yx, pt2yy) = _FQ2Mul(pt1xx, pt1xy, pt1yx, pt1yy); // x * y
        (pt2yx, pt2yy) = _FQ2Mul(pt2yx, pt2yy, pt1zx, pt1zy); // B = x * y * S
        (pt1xx, pt1xy) = _FQ2Mul(pt2xx, pt2xy, pt2xx, pt2xy); // W * W
        (pt2zx, pt2zy) = _FQ2Muc(pt2yx, pt2yy, 8);            // 8 * B
        (pt1xx, pt1xy) = _FQ2Sub(pt1xx, pt1xy, pt2zx, pt2zy); // H = W * W - 8 * B
        (pt2zx, pt2zy) = _FQ2Mul(pt1zx, pt1zy, pt1zx, pt1zy); // S_squared = S * S
        (pt2yx, pt2yy) = _FQ2Muc(pt2yx, pt2yy, 4);            // 4 * B
        (pt2yx, pt2yy) = _FQ2Sub(pt2yx, pt2yy, pt1xx, pt1xy); // 4 * B - H
        (pt2yx, pt2yy) = _FQ2Mul(pt2yx, pt2yy, pt2xx, pt2xy); // W * (4 * B - H)
        (pt2xx, pt2xy) = _FQ2Muc(pt1yx, pt1yy, 8);            // 8 * y
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1yx, pt1yy); // 8 * y * y
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt2zx, pt2zy); // 8 * y * y * S_squared
        (pt2yx, pt2yy) = _FQ2Sub(pt2yx, pt2yy, pt2xx, pt2xy); // newy = W * (4 * B - H) - 8 * y * y * S_squared
        (pt2xx, pt2xy) = _FQ2Muc(pt1xx, pt1xy, 2);            // 2 * H
        (pt2xx, pt2xy) = _FQ2Mul(pt2xx, pt2xy, pt1zx, pt1zy); // newx = 2 * H * S
        (pt2zx, pt2zy) = _FQ2Mul(pt1zx, pt1zy, pt2zx, pt2zy); // S * S_squared
        (pt2zx, pt2zy) = _FQ2Muc(pt2zx, pt2zy, 8);            // newz = 8 * S * S_squared
    }

    function _ECTwistMulJacobian(
        uint256 d,
        uint256 pt1xx, uint256 pt1xy,
        uint256 pt1yx, uint256 pt1yy,
        uint256 pt1zx, uint256 pt1zy
    ) internal pure returns (uint256[6] memory pt2) {
        while (d != 0) {
            if ((d & 1) != 0) {
                pt2 = _ECTwistAddJacobian(
                    pt2[PTXX], pt2[PTXY],
                    pt2[PTYX], pt2[PTYY],
                    pt2[PTZX], pt2[PTZY],
                    pt1xx, pt1xy,
                    pt1yx, pt1yy,
                    pt1zx, pt1zy);
            }
            (
                pt1xx, pt1xy,
                pt1yx, pt1yy,
                pt1zx, pt1zy
            ) = _ECTwistDoubleJacobian(
                pt1xx, pt1xy,
                pt1yx, pt1yy,
                pt1zx, pt1zy
            );

            d = d / 2;
        }
    }

	function equals(
			G1Point memory a, G1Point memory b			
	) view internal returns (bool) {		
		return a.X==b.X && a.Y==b.Y;
	}

	function equals2(
			G2Point memory a, G2Point memory b			
	) view internal returns (bool) {		
		return a.X[0]==b.X[0] && a.X[1]==b.X[1] && a.Y[0]==b.Y[0] && a.Y[1]==b.Y[1];
	}

	function HashToG1(string memory str) public payable returns (G1Point memory){
		
		return g1mul(P1(), uint256(keccak256(abi.encodePacked(str))));
	}

	function negate(G1Point memory p) public payable returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, FIELD_MODULUS - (p.Y % FIELD_MODULUS));
    }

    function checkkey_eq2(
		G2Point memory EK1Arr,
		G2Point memory EK1pArr,
		uint256 c,
		uint256 w3
	)  
	public payable
		returns (bool)
	{
		ECTwistPoint memory tmp1;

		(tmp1.xx,tmp1.xy,tmp1.yx,tmp1.yy)=ECTwistMul(c,EK1Arr.X[1],EK1Arr.X[0],EK1Arr.Y[1],EK1Arr.Y[0]);

		ECTwistPoint memory tmp2;
		(tmp2.xx,tmp2.xy,tmp2.yx,tmp2.yy)=ECTwistAdd(EK1pArr.X[1],EK1pArr.X[0],EK1pArr.Y[1],EK1pArr.Y[0],tmp1.xx,tmp1.xy,tmp1.yx,tmp1.yy);
		
		(tmp1.xx,tmp1.xy,tmp1.yx,tmp1.yy)=ECTwistMul(w3, G2.X[1], G2.X[0], G2.Y[1], G2.Y[0]);  //G2 generator

		require(tmp1.xx==tmp2.xx && tmp1.xy==tmp2.xy && tmp1.yx==tmp2.yx && tmp1.yy==tmp2.yy);
		return (true);
	}
    G1Point Checkkeyresult;
	function Checkkey(
		G1Point[][] memory p1,
		G2Point[][] memory p2, 
		uint256[][] memory tmp,
        string  memory gid, 
        string[]  memory attr,
        G1Point memory pk)
    public payable returns (G1Point memory Checkkeyresult)
	{
        for (uint256 i=0;i<p1.length;i++){
            require(equals(g1add(p1[i][1],g1mul(p1[i][0],tmp[i][0])),
                g1add(g1add(g1mul(pk, tmp[i][1]),g1mul(HashToG1(gid), tmp[i][2])), g1mul(HashToG1(attr[i]), tmp[i][3]))),"eq1");  //eq1 TODO not work
            require(checkkey_eq2(p2[i][0],p2[i][1],tmp[i][0],tmp[i][3]),"eq2");  //eq2

 			 require(pairingProd4(pk,p2[i][2],HashToG1(gid),p2[i][3],HashToG1(attr[i]),p2[i][0],negate(p1[i][1]), P2()),"eq3");  //eq3
		}
	    return Checkkeyresult;
	}

    function Checkkeyp(
        G1Point[][] memory p1,
        G2Point[][] memory p2,
        uint256[][] memory tmp,
        string  memory gid,
        string[]  memory attr,
        G1Point memory pk)
    public
    returns (bool)
    {
        G1Point memory hg1;
        G1Point memory hgid= HashToG1(gid);
        for (uint256 i=0;i<p1.length;i++){
            hg1= HashToG1(attr[i]);
            require(equals(g1add(p1[i][1],g1mul(p1[i][0],tmp[i][0])),
                g1add(g1add(g1mul(pk, tmp[i][1]),g1mul(hgid, tmp[i][2])), g1mul(hg1, tmp[i][3]))),"eq1");  //eq1 TODO not work
            require(equals(g1mul(G1,tmp[i][3]), g1add(p1[i][4],g1mul(p1[i][2],tmp[i][0]))));  //eq2
            G1Point[] memory p1Arr = new G1Point[](2);
		    G2Point[] memory p2Arr = new G2Point[](2);
            p1Arr[0] = negate(p1[i][2]);
            p1Arr[1] = G1;
            p2Arr[0] = G2;
            p2Arr[1] = p2[i][0];
            require(pairing(p1Arr, p2Arr));  //eq3
//            require(pairingProd2(negate(p1[i][2]), G2, G1, p2[i][0]));  //eq3
            G1Point[] memory pp1= new G1Point[](4);
            pp1[0]=pk;
            pp1[1]=hgid;
            pp1[2]=hg1;
            pp1[3]=negate(p1[i][1]);
            G2Point[] memory pp2= new G2Point[](4);
            pp2[0]=p2[i][2];
            pp2[1]=p2[i][3];
            pp2[2]=p2[i][0];
            pp2[3]=G2;
            require(pairing(pp1, pp2));
//            pairingProd4(pk,p2[i][2],hgid,p2[i][3],hg1,p2[i][0],negate(p1[i][1]), G2));  //eq4
        }
        return true;
    }


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
    // Node2[] path;
    Node public path;
    Prf prf;

    mapping(uint256 => Node) public nodes;

    // ===== Node =====
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


	bytes[] opstack;
	bytes[] valstack;

    mapping (string => uint256) public expects;
    mapping (address => mapping(string => uint256)) public pool;
    function Expect(string memory GID, uint256 ownerVal)
	    public payable
	    returns (bool)
	{
		expects[GID]=ownerVal;
	    return true;
	}
	function Deposit(string memory GID)
	    public payable
	    returns (bool)
	{
		pool[msg.sender][GID]=msg.value;
	    return true;
	}

	function Withdraw(string memory GID)
	    public payable
	    returns (bool)
	{
		require(pool[msg.sender][GID]>0, "NO deposits in pool");
		payable(msg.sender).transfer(pool[msg.sender][GID]);
		pool[msg.sender][GID]=0;
	    return true;
	}

	function Reward(address addrU, address addrO, address[] memory addrsAA, string memory GID)
	    public payable
	    returns (bool)
	{
		address payable addru = payable(addrU);
		address payable addro = payable(addrO);
		require(pool[addru][GID]>expects[GID],"NO deposits in pool");
		addro.transfer(expects[GID]);
		pool[addru][GID]=pool[addru][GID]-expects[GID];
		for(uint8 i=0;i<addrsAA.length;i++){
			address payable addraa = payable(addrsAA[i]);
			addraa.transfer(pool[addru][GID]/addrsAA.length);	
		}
		
	    return true;
	}

	function stringEqual(
		string memory a,
		string memory b
	) private pure returns (bool same) {
		return keccak256(bytes(a)) == keccak256(bytes(b));
	}

	function bytesEqual(
		bytes memory a,
		bytes memory b
	) private pure returns (bool same) {
		return keccak256(a) == keccak256(b);
	}

	function empty() public view {}
	
	struct ECTwistPoint {
    	uint256 xx;
    	uint256 xy;
    	uint256 yx;
    	uint256 yy;
	}


    //参考 https://github.com/Uniswap/v2-core/tree/master
    
    // 存储每种代币的余额
    mapping(address => uint256) public balances;

    // 事件，用于记录代币接收
    event TokensReceived(address indexed token, address indexed from, uint256 amount);

    // 接收 ERC20 代币的函数
    function receiveTokens(address token, uint256 amount) external {
        require(amount > 0, "Amount must be greater than 0");

        // 调用 transferFrom 将代币从调用者转移到合约
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        // 更新余额
        balances[token] += amount;

        // 触发事件
        emit TokensReceived(token, msg.sender, amount);
    }

    // 查询合约中存储的代币余额
    function getTokenBalance(address token) external view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }

    

}