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
        vk.alpha = Pairing.G1Point(uint256(0x1e1fd524528f445d59cdc6508797b0424935a19dbc537bac43a9a3d7e8be4a31), uint256(0x111fe18651f054db46e20323018b1f8009345427afda663132436e9b3a998e52));
        vk.beta = Pairing.G2Point([uint256(0x154ff97eb3c6ae6a35ea024be96e3fcf4cd4557873c738e25baf017f51564ba8), uint256(0x1e369122acf866b4018554e908acaa46f341a8c1a0358da1812df517299e2a29)], [uint256(0x2746b0f0d91feee5a9aaa78c26778d69b8032850c1c5c8177fbeb75cac3ea380), uint256(0x0ecb02f594f16754be14a55e15ab636016deda383af289b3e037b8e26ddcd54b)]);
        vk.gamma = Pairing.G2Point([uint256(0x1427b73832035076a23b6e211403ccff1ec0c3d3c905e85eef35b1fe32705339), uint256(0x23d25f611acd4f1b2cebceb51c6478e2ce24e965e7724b39b53103b3956591a6)], [uint256(0x2202f8f2c41334ad233231425eaa577dbabcf08a80012d80909b8766f361ae5e), uint256(0x104edf72e3fe6be1399d0d7590ef2534e4c1b1b6728e21965caf085c2a1fa29b)]);
        vk.delta = Pairing.G2Point([uint256(0x2acac24f7d6a6fb172dd1000e10ae93d2614a17098e3b8538e0280858ccef62f), uint256(0x0c6c48a14d5fb1db61caf9f686410eb9aa056444ddd8ee95c2618fd6e6ce3ee8)], [uint256(0x20585603d409cdb8bf1ed605edbb3bcb367ec2fd217e33425d871272c5d72a22), uint256(0x19bef50ea881bdd99722a69446894e7f99b60f45492acce78bc5f386b834ce18)]);
        vk.gamma_abc = new Pairing.G1Point[](30);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x250aca619cd98dd0eea27b18407911d7f0741e9cf90590f0071646040ed5d74f), uint256(0x02f9ecd9657505218b23df9f69e66e3f63966d929b2b61d7393dc6d361a54769));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2a582b57c31c8e133eedfd3f0d78e8791e1eb9cfa36f3196dc15c58334853956), uint256(0x24ba788e0d1ab055d293b6650864ad0a4c65c02b7245e6877646740f0fb18ddd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x11512ce6b50cfd9e4fd66ca42e5c0357696c58f449e5fe81480584b87c5b52d0), uint256(0x12648dfd070010aa661e68f4bc11b73da3790c913e1bdd43fe8c864d85d4569d));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x066298466f1acaa3d1b5500e4f271b7f1921d8c051719ac95ac28d4558b05ba1), uint256(0x2a011e53a59cb9ab4ab848569e20512fe800069e953cf33101f6ca30cedab8bf));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x08809241fdbe7d5dada3a6e5ece0485629be76623064b35fe2ab82e1d53b4ff0), uint256(0x1fc0dc63f175017be80d5cf224e4a6bed4bafdf5e76c3a0e263846d1110ca22f));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x07440ff631fa9dd4ba322adf2b25e41b44cf70e0a244d9c60296a16bf4b34f5f), uint256(0x0040bce6f5e39a966b0c9337b84636c23616e4766838b1e03440163fce38e55f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x29306834d0d3930173d706719b531afe4d64ec9a3bc8a7c6828c38eea66ae946), uint256(0x19ab677e2a0fa59b2b7f2dfacd9d52fd7af63241796ee21a9c780990341174ad));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x11d91278bc7b3d7c9c4709b0ab1553922e5e91489c41f98b35514d8a8c3fc46f), uint256(0x179daeefb5f3290455dbcee5b7b36f0bef72e884f642a2c7e7205e9bf8c23a22));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0861cc1971e41aa57b8aff3fe574209cd8c39649f805560fda6aea9255b1296b), uint256(0x07a417b7495d5c4714f50e43bf9b423d84f2e88d147b491e7d461bc8f89db847));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0bb08c482dbf7a9d3c582d0a4795583a4a83480250453d38bc65687d5e0e6ab5), uint256(0x00c87031982373496b96a204a9c05b672110f38580ce40ee94a05a8fc683f65b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2ff1df53c2c6a07462988526e92a70ab89171bcb22d37426e8c6cea46e4e268b), uint256(0x0342df609d753c18e36d822a377fc0069a4b3fc92eeb24461fb99289e2be8f25));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x213326ed220cb1fc180d9b3b8e8781c7dfb4713646f86e6bb1ec76342d69a179), uint256(0x24d154d81e30c2fd55d5ba40a5a12d32f206e761077a5caf95b01625d5fbea73));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x189ec3bbebfa554173c82d2e859bbe152c6c9f9663e92368f74ea81ea489d2a1), uint256(0x1d7c1bbe955a6402e9e4c7451bb923f4392dba8f5cdb34b198ef5417b73d7956));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2d6a93ebe89479e78327b4b1b3be3602bf50a71f53aacd5a0c24a22c082bc404), uint256(0x227bb49df71f0181402df16acb6758b9874faebdca2039f5918aedb42d1fe0c9));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x246567e0f47bf1be01bfe13cdabb8287b445ecab6a78876f13f0979d6e2d2532), uint256(0x193c64f0a0ba8c5145d5f24736ef3520747654aafbdd64be876f8938d9d91a3d));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0321b71d70ab921c8db8704e6ae8a46ad97fbe5d507f3fc3199ce809aff9a07f), uint256(0x0ee4511f3a8511a80dfe0d21ccca434595a2c948e15b1ecdad0382a49e2d28cc));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x031136137254d5db24017c4c8c2d3d0cfc15eab359dc365a46bca1dd8660f5dd), uint256(0x000fd52b4ef33e8a75e337cc232fffb0ae1f6c6846f28a867130d728ad0948e0));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0c203463ab810d08152558b608e6dbd008960f5d0f80385346491bba6c4c1b0e), uint256(0x0509101900f0e8fa11e28c0126593ede68dda3e9410efa9fafd51f6a42140712));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x020107c177d0102ca97a91413e89190046dd6479e6b00260316c5de59906e4ae), uint256(0x1e411aafe8db094013c0a3957030003de3722a6b0366e52ccb099484d91f36da));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x005f8e5648e359d25163fca80530b5e2b28ce81bd0d8e7da6bf08921bf66cddf), uint256(0x25a6e5fc9ec5598d37c527fde29eda1ee7dc5a05af4cd5429fffe1213374774a));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1017f5e93be67abc60638b1aff55c9d2035cba3e94b2819dd64a49b122debf1e), uint256(0x07b5724e9365b1db0cb56e3d4fb4b3ccd61275f9f22bee3e25080de6d413f836));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1240702dbfb3839499577de6996d99f2b988cab77ee40ded046a81cbf740130a), uint256(0x179ca85a3f65a7e707ee44d4917e25c0bf0ec9cc0a5a5fe71d7cdcc1582c2fa6));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2b476806375f01edd4bd53e92f9433ea8c51b2b78be76d2e6ed7410b37746757), uint256(0x1fd93e2fbbf7127a0bc9f75f8b6e18d26d994a3d8a0918cb4be4a423b81b7c9a));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x0e43e4f881a53fe59523322971d9d157e4a70d67c82709d5510cea3c87cde6e6), uint256(0x20a0956f9973cb2339ef63deb3795d5a252e8d1be39fee0c0b69ee642c5ef8bd));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x153c9a02f1655e342594479f0760c12b1a0bd8b32cf77d7c8a33d20bb87ba428), uint256(0x00189d141095e3e2b366a96979c5faeb642e0b964f7fa7f7ecf39f989b9428ee));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0bd67bba02367e0e34d8ece5addc39d2c2e3a2fadf9f08504a67a043198937ed), uint256(0x1655eae7567c99c04fdc2096979c8b9db54747f57f2e73ed03c211340912361c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x259fb52031d741a29a7cf90627e988e53e79346371819b994ee1bcea2b19df75), uint256(0x048b771e92f970a344982db8389f587466dd619706cc297b2dde24bf77603a59));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x16b9871ca6985f7b5166b6eabde94a1b6ade86505d553441cea3eaa9b7a48d03), uint256(0x0212e0e1df420410b670dac0b007b98bca1de38e6e8e0d456232671286442414));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x14ca6a42f1114e17caa34a06d641053fde6abe4111b4bbdcab5fe6d5ce1e55d1), uint256(0x1979d63437a5ea14e5953f17ece79188d80ab45fc0e9d8adff61ca5dcbc2e49a));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x046a9ae6c2a8a9762ba7959b6a940e50de7c593b995b4d94e2c7a39da8c93b09), uint256(0x0d1a3118db9aff5f75d7b11fb4b16ebae7820c6f55476a59636b90ac2504dd3f));
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
            Proof memory proof, uint[29] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](29);
        
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
