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
        vk.alpha = Pairing.G1Point(uint256(0x24528c8b14204de675f057b758dd18d817b9b691d9d4f43ff166b03b6cdcc427), uint256(0x015c05199008728e0b1fdf187b48f82dabee88db02ebd6b42a57eb061e9d8554));
        vk.beta = Pairing.G2Point([uint256(0x1886d1cfa2910fa1b0f7a054ceda084da9222f38c487adb850ad4d34557fd9f3), uint256(0x0d08777ef6da7cca97c798b2eec9e7b52f0bfe7e4c680cd9f8e311e49ca9dc91)], [uint256(0x16d0607df230a1b126fcc9413ea2710e26a2c4015519df67400f4e51c2553efb), uint256(0x29f092c6b9778e2cac39483b4f63bd3024a80878519d5939077b7467304f89f2)]);
        vk.gamma = Pairing.G2Point([uint256(0x12e6d4d6e880a0b52197467720065ef5ff383ab24f3ab33eb0fd4d2634f5f562), uint256(0x0a1fa32aad4b563e73a9d8cabfee6d185fcda1c80efc25975b40e8c376905935)], [uint256(0x131ac441c3eff8a50a15c8a9be5e4f5c3b1fa2822f5c1dd003eece2b00b64fee), uint256(0x23736568a45370daa7ec78cc8cddd06de3c0ed6c04685050640abb30569622f7)]);
        vk.delta = Pairing.G2Point([uint256(0x1c6bce60f571de6864da000ad7433367b429ad8641827d534e47467462984378), uint256(0x27c6c09a61c6ad716eba16b6a2ef8d882b8fb6bc371d6aef3d0c2f320425f2e9)], [uint256(0x29f67b86984be738fdadf944a7b9c80215ae814fb0c43dcf8aa8f8fb28e163af), uint256(0x1e8251ba1abbb18b89d68f07c0922774c2e8e67773205ae12db6d03b0e00a684)]);
        vk.gamma_abc = new Pairing.G1Point[](35);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1acc26e92b28dfadc4a2fea18b4f79f4f61e3ae58392f529c1bf05b46d5d57dd), uint256(0x02a4cea59d2434da76ade20ad5317e2242606f57a8d9383360bfbe6311edcf43));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x153377b84035723ae60f63d44f4d713ba48c106289cd66192ee4d6ac014e6c95), uint256(0x2ce5f5014bd4369e61ac78758cd2908afd30004dc56a3632d2f0fdae9f5c625b));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x27416d0b14c086d8613c6f98b44f918b4fa9f120e938655f36b62579b984fb7b), uint256(0x05956f0d8edafecb611571c9831caa1c45a747732588b0834bf76caa815f0fcc));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x021dbe46da1e5a38f33943edbb0bcb29060c690ced538776fe9629acb0a79395), uint256(0x2e870aabd62a712e5b972aa31303bfffd3651ed530e66c12f23a9fcbaebc5f0b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x25e58cbb2a3dc7d63616f0c07c3920a0aa30728414ee2609f47edc707dadacb7), uint256(0x0e2af04fbaf4c7c4924db9f782f318ba216c51e1b5becb8b979d9a86e5f2f9e8));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0e4df0e0c353bacc410fc18021c4f4b175fb0e4d74d6366dedc45f1fe08f2fa7), uint256(0x07403662c6e003e6c4899a7f99b7d88f399718d048959273ae9d1ef16e2bbf34));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x108a8e9830303c8d556e7b5db59e7194acf4e549bcef10012d9647c6d5f1f916), uint256(0x079749c4d147cf0ddcdadee61f3238fdec335c2226ae8f4407d1e08e78dc60b7));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x16ae848d32ae075f1bc81e00417f3cbe98828ab66f76b37273b4cea8d6d9983c), uint256(0x064247dc9e2d24d64c4e96d54fd37101fb911a0a0090f2a28e9422350cb64bb6));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1558f249580033a83c7245576b09f2ef2f613e664867f3be701369b4e39c919a), uint256(0x034628f28606c0c2e1cdca592d5ca7d93148f3dac6f7040eda2947c2b0914677));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0e4f194cbc5acf0f1ab6b200f2204e42e38dea995ad52b8d3d2d96f3e83061b6), uint256(0x0f0cf8723938e2750c496478fb0712b32aade29b54b6d030d469016fc14bd66a));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x03922573196ae9af84f54134f6e63b9d380bbd50adcb5df8aba01440a0bac4a3), uint256(0x164092271acc337234aa41ca8eda1f771d0a632f790555207172f92dfc86d432));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0ab9707303d09bb046f8f4a3840331b32c8efc40c016d8be0fb3285bd7fa24f7), uint256(0x004d01e1b321098de651cde4643b1bb64fac0297effa36287c3f5ae83851b589));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1d4baf9a42484c8ace886ab4ae1721d575cbec7f0e5f3f914a58cf1ac1975ffd), uint256(0x0c4dd73b3f825748a4fcaa7e6e0c5eda687c9dca9e50552a78d897acbfe0487a));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x144c08ff9a3d160f262741bb1726157f35b1256e26ba5e9073d371e62a40c817), uint256(0x2125e9bdf2ca432b46ffad29fa3566ce2dc19ae8fc2729cfda463c777b8c60fb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2d3725e3cb607aeb55d09eb3e42efb383bf08b6aad0eb6f520b530c0d0a18b9c), uint256(0x1db933dcc7b684b557a8bf33ae77dfb07a01a8119c02e7198b93ce80c76d5c61));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x2b79414cefef64324d745aeb379a4b9334f8618dba977f79f385eb6d0e915c92), uint256(0x10a700ab31b6eac5bd58e77ca260072e5d8cab8c34327a0c10111ff3acfc02d5));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0f58be1ff40804f21f01fe24351c0155ff659093560fb2df82807255452cf588), uint256(0x226a69b81926f336275c6a3c17dd70c830e4a5a609bc1a1c3ab221a0de1d77f3));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x173f1a63015d1325965c3851f7ffd296cbf4125e157e15c18a797332edba5faa), uint256(0x19924e3d50b9e810318206a4820b71a46b387481b45ee3257a061721f3693556));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x26cb6d89e0f6daefb42e75dad4d93cd03e44bc3cb0aca7c6b54581c2682535fe), uint256(0x216ed9d85589b928144332c81af875c92a2b6049e90cfa124b628e7430727687));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x215208ec38d2947ccc78e268355b581ec27b71bd24383b211b68d8eec6b3d7f5), uint256(0x1976dfa97e967c056964e1a22ffee6ff6588c5e43e8b31aa21ff888455bf2dbd));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2c5f22165a2e287736af8c7f4c2722f3271951c3cfbe3a0f7a8489d396e30df7), uint256(0x27523ffcfb0c1057a8e5503c6606e4e0b590a7316b96b5043dba971509a8a981));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x149276732021f7298bf3548ca8368e40de485b2a282f4de6df4f2345c139f8d9), uint256(0x01db1a4be5a488a330530caafdebd5acc6f3a247b29f57e69c39deb0b090f22c));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x18a597138db579cdbc4c5cb0a0b5750c16ddbd5883265cbd31df996f0dd49b89), uint256(0x15c3b9d7d290a323c7125d34cd6d0f65eb6f90ed1baab9a8dbfc8d5e4824faf2));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x21dc2d637c072564665dc14068fab06c533e3bbbcb3e122ca4ae505713c5ed5a), uint256(0x0cf21db0e35530fdc22379e1e2bb2143a69b2124f57e2875fb9a6552b3097285));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1e179937e5b849927dc03a14742f176d63c43903797822bdf366c2e112c18d94), uint256(0x2f73e8d1ae55e281866e100f2e0846a39b9b10aa6bc273a959436df451ab174c));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2b5284865b3971f1bfddedfd15fcf844ccaee515013cc196e3d5bbbfa86e2ca3), uint256(0x1241058019692111987d62bbe8a19e5185ac9deff918fbc30a3049935e511af7));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0cb4b4b982169ddc71ffb7c6495c851df42fcd1637071af25b3a710235bbc7d2), uint256(0x2ab0ffd1e80883efff606f9724bdebc293b780d4d1fe4fc5a404efa18dbe40f9));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0131d4b23707bdf9c95faa0dadaa24b87c43b2dbd1c338bb69e31626b92845cc), uint256(0x1ca02a870ca9616c3590d2b0a85a657f307b8cebfd904d0bab46644176b390ec));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x127fe994b42c3475f1b7e96c12193b89d24d52ca146b38b4121e48cc0ff0772c), uint256(0x02b713693c8b983b7d563c72e5c1250369e60ffcf12551aef4ac13599b2125c6));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x16f5739cdd8a20e00565da21fcf8204f1259c92ad58f306b060755b2156e15a6), uint256(0x0312f6dcbf3ad9faabb32e6e89f8bbff3bd91fce6b505132c3b30422a6892533));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x19b66c673649ae29984cdbc359624f88fe51d4c8330a3cc1ea2dc4b4c8d2f754), uint256(0x092f367a4e579e45473422ab5f180089a83536ef60ee4670d1e4e80b9f4d67d1));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x16210a9172715fcb003f82b35f6f0b173b140483de256b685f1bf2bfdbf89d8c), uint256(0x157056d9165c267fe8b28a1232d0e716b6ab2d5db59b3f46524f3fd95d867f86));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1d9d23251559c0347e7a9882ea98ea8999c694940b33607aaf3ed3d26a0c842d), uint256(0x00a4527eda00e93a1a5ea141cf9726d48560f78a1bbba19b7c8d9401260f1d9d));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1a7167a061c9165f6b74991d4a5a0a4ff0b4f100997bf80067e646de0975f1a3), uint256(0x133c54dcaddc15a598fe55a029b763e81c01da36b27b4ce8dc997904650c1cca));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x2b697de41d4e8bf55a0c9e742da6ba924234e718d3eea8d4c3b441dc86dbfef9), uint256(0x18fe3662425a4475b38e6b6d4d1e5e6c2169b1f6db8b137825f486f369b19c00));
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
            Proof memory proof, uint[34] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](34);
        
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
