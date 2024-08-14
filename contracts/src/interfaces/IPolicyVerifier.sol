// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../policy/Pairing.sol";

interface IPolicyVerifier {
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    function verifyTx(Proof memory proof, uint[20] memory input) external view returns (bool r);
}
