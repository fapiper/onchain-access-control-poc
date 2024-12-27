// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
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
}

contract Verifier {
    using Pairing for *;
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
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x222b1b504103b074ae1e56ed0b00a1c92002448833b7638e30deb08cdfe75e70), uint256(0x2e45eacc753a99f5525da9c0bbc845be4026a267e91356c5a346da8b007e2203));
        vk.beta = Pairing.G2Point([uint256(0x083620c3f6f3aa17a4725647d726ebf6ff7de57a81e0c8b1a91d5b9beeacdc2a), uint256(0x12f4a1cbe01e0221fa8da7f527061287881b2559054363449832f43bbb2ea579)], [uint256(0x14010d8675b966409db0a2e2f32d22ea1a59b2549da8cb379c30fe88366e29a1), uint256(0x1f908f3a5f80ab40c687673c3d80efe4090a1b7a1de77f1c1445bae8a662fc35)]);
        vk.gamma = Pairing.G2Point([uint256(0x2268f5092c7d9b2fe4f41e8e6a0c2dcadd031d3aad128280f86c33ef73e675b6), uint256(0x1bf3a98b6dd100e2b3661ef8e81cebabbcaa529bef9d30787d60d76577fb64fc)], [uint256(0x1c1a068c9aede86dfb3428afa8e6f65ed2b945398444488f4762f4c5b27bb74a), uint256(0x2c97fcdacc02b6b33be142a417fe8c681dad69f2e76b10b8dd147d445b430937)]);
        vk.delta = Pairing.G2Point([uint256(0x2b89a6a643b02a36bb77ffb88daf315c02ea1dace56cfe0928d41f11319a0642), uint256(0x16b0ddf110a8d3c202539fcddeb5835a080b0c91589bbd967c3bcbab972da943)], [uint256(0x2abba40d11b197b9a88ef69b0ef85840fee2886e968781d0e2403aac078682cf), uint256(0x02290193078d2f18be97edb422ea3b78d9d9536451584d329175af6df266195a)]);
        vk.gamma_abc = new Pairing.G1Point[](28);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1c14d7b099b85a46606145b1739170d6602f90dedf1d48c5f4a6418b0cec3ad4), uint256(0x1a1655da93bd2ad7b9759c37a8bee1f7c45a994b890231b8806060366560efb7));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0d7d8d0321f54ddf999581b2bfbbe4e8f6283b2511eb458d59d068275f8ec24a), uint256(0x099c6fa2434e3f11305b30fbbe02b20aec11d5a2fb25dd7fc1f6cab277b9a29f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x015776043230a087a30d9bf8dcbc0e531ea81cc0f3ffe5c787ad18147bbb8093), uint256(0x2891eb1d1251e2308a5f8fc00529059aa0afe6bc1b3c2e4cf21b944fbe9f5a44));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x15436a891a64ad5c46a4e967ad60fde221498183b4ae23257f5c58607efa8cef), uint256(0x12726be42401b84043bd339ca94d757d93a0eeaf62909d7b77b567c233c5da3f));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2977ee95140af087af60ada42a4fa59cd1adb86acbe4062246de5ace0f2c0db8), uint256(0x197f0e985a3c5d4289b18b89f8afc12e7c59d51502a757e5ae2229200a683ae6));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x09b55370c62df66d12ccd86c5e549f7e606e257c511993493603b01b8916b3a4), uint256(0x1d96904ade6363b74fa65f02978ccb3978cb5281383a3bb60e346bb85d30ba8d));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x21cc160532f54e9872bba4f6a88f2f5eb343beeccf36142174f9b920f3dfeb59), uint256(0x029678387c3239f278202efc7417b494181af2d05e16bcb102e3786edb202378));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2eb3d22e3584417c3abb2c5fa6c61e0ece017a105746b7c0b296f8959899c067), uint256(0x0ec0361150b1d1fde3f6426262e5f72bbff07af1195539bea60a602d0c57a27a));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x08e33e7db08d95c87462e5e94b207f425dd6c749a4e701da503a121aabf3c826), uint256(0x0a2cf2934d3a181f77c4e5f46a3c70aac409e91f6de66650008865e08da7cdf9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x07e1bef8407f5b25797d8baee64b0bd012976d4d5188ee9ec1185084b7b697d2), uint256(0x2431eb86ddaf9ceca740dc77dfa2032aa6a170640ec2d5af45e1ff7e83d0c034));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2e403683923dc8fed07a0a298c29d2b6c02eacf2ce54179ffbf98057fc30e84a), uint256(0x2a10405bdcef980b27f03f9933b2aa8308ff6336a1039840ef049a991c12330b));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x11c09d4a5746831e3c0ca4704bbaa0677ec2cfae9c9906c22b351168a5a5f3d7), uint256(0x2b6a0df19f3a90eee891d5d52110a47f52b7cf39ed8920fc0a88babc3cc3120c));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2c0a01ff63e1c038b5aefaa79f49f8ffc35bdab10f50da845384340ecd51fa7a), uint256(0x05c0dc0c80a9eb204d3b60aff7edda590eb0175e57788715ca737d8c5baa90b4));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1bbeb337d4d06ac479d02faad33f2cd552b971f21c94779d17f9e1a390b9ef7d), uint256(0x257d475e39ab433d77ed51f3d4effe0077515c0b39dec1644334a8786cad45b3));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x226cdca7bf973f4632985aa50652b0ce7d319da68c32b3a7a9257ad68c755d7c), uint256(0x0cf79aedd222b3ab7ec319ce6685789ba2e8e059c4f7cf0fb39dc72d3df2bb7c));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2f8789465fbdd811169dcb9a6b207277d8df6a77bdd271c1d942c00ccdeba9c4), uint256(0x233002126925e55ca102b8be36bf147e457b84ad04a3224b1eaf72f8b77da073));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2306a8273ac109555d4043478ca0da38d8af1177f2246f29487071a1af9f44ef), uint256(0x134116d1ec777cceac59a3d7c5569d71d4d76943faac4f0e8018e22b5b33bf1d));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x201c89a6f0642279b40de7331d699cb6d006bebc2f0c4fc328a3938cb79f6c84), uint256(0x02295bd3b56f2317733fb132ca0d38ee2238a88d6ea681d27788f4080e4ed1c1));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x294a20d80b6a96d10c9f24b16e6cf20747f82e3d926345cf2d9eaab36e3bd6f2), uint256(0x2e415769ace66c63484d94dc65d2c401ae73f57cff6547ab663c0715c2ca6623));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x26cd210f214f386694557ba1457351d4b0ae414b243ba7f30d167a2cfe51ae87), uint256(0x1aad00d6b6ba887f503ea079379e105b27caaf2ace34d0e6ed1accca6b57cdfd));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x009ff42e51eb87151fd6d73082bb406f07cf5838b5851ef35f217693e557bb89), uint256(0x24246c1751e2a28db5b8682eb1f85d6e8a8a0faf4b661b402772d8344185bb88));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x04bbb4902d9318edcd444e3f761fee5902f7a5ace47e633e31e7fd8b8935c979), uint256(0x2c3d5419f4f5ffa225558ebe6d253841daec5f5125985118d5dad44510c9704f));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x191e904608fdfc4bbf434b7e683cc36740a6cd68cb4ab681f48955492808bed7), uint256(0x221f96bfa5b73a83440b642a587dd32ffb234239214109d8e8cf69d454bc6f2a));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x161129e5d778819951c091d2c49d3de098cd59dcbaee31bd510472d2a17e9243), uint256(0x2759f269ec8e8a581f549060f2e9f2f534f2e4cf370c67f1ecbb02136c860e3d));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x06d4f8d877ecd88152fed8e7c91ba8bd45a801b59a2860efa7911d1111551834), uint256(0x16c6858400d4752a2291b4717f3849544a76fadb6ba41f4bb7d24c10b344ee86));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x21d31e7c2631ad92290ed1e087e05fa87990a2053239ffcc416f8f1287b17ac9), uint256(0x2ee15caace2764bb0afd09be5f29fb618fbf3b1da8074f1e41cff329ee929f1b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x115603d7af820a994222800acf8b24ee3b5fe18f0a039d9e61ff2d31b1986702), uint256(0x1c56b90d0678c56f9bfb0edd35acb8f66a9c91992f1787c16d93a996bd0cc580));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2067f25f1af60126c50dad9566e97b97d28d4995cb7572d245995c88339ec0e3), uint256(0x28c4aca28b97aa358af5bfd2b17c19358580267c3b2d8b2197e2f5138e46139d));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[27] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](27);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
