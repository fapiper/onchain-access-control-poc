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
        vk.alpha = Pairing.G1Point(uint256(0x20cb0f6f1cbeb38527858781ee752d4c22ccf1300bb55994a24fd936785a66ed), uint256(0x09d8f37713d734b1d0e70db010085f51999033b7aee4e6e8c56e79ad491c8067));
        vk.beta = Pairing.G2Point([uint256(0x26e961dcee998d9e3719a4bb77be08ab5b6db5a834b6ee98ce241772d5ef0650), uint256(0x285314d2ad94d62793545120129afbc6c024ed1a0db9c95df97904150891d28e)], [uint256(0x2fe74b4d0e0c30b0a9e1aeca787c4d588031583a6cc1bd42cac77b521d90bdee), uint256(0x0f9c13c1a9ace0261dd9ed14d0e71f132fd3fbd9a50b0dc8fbcdf3cf9322e5ab)]);
        vk.gamma = Pairing.G2Point([uint256(0x068e708b02560972afaec91eb3bd682868d82dc355dbc45e5c9119c585749fc4), uint256(0x100049345e72b8e7b368cb12aa023328f4ee694a713ddbf3938aaaeb1a92d706)], [uint256(0x057e1a61088c680828855cf76547e9f1c7a78021d6f270f8b2d860b46cacf85e), uint256(0x2d2594a5f5ef761e91a2c4e8a365176d6a96f4d389d23a968f26cd2d3681cb72)]);
        vk.delta = Pairing.G2Point([uint256(0x27cb6ae6f3f1d078906e0a087717a1e2da1fdf0b6dfd8f602e0da150a6cbaa4c), uint256(0x1052ff75706bec1622d44c3f966dd9d27c0b194712adf6b1c020ef3f4d73573b)], [uint256(0x149b0bd6fee4b72783cb913cf6e1c7211775086d42e1d65cbf654179cdfe5548), uint256(0x007a58b176793f9084dbead5545d86ee5ebbc9d48d47355839bfe8a296024028)]);
        vk.gamma_abc = new Pairing.G1Point[](119);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x260e886ffac6db4516d94892d11bae8a368af7826dad15fc3d51d3096ff28d6c), uint256(0x24422128072c6b877ba0ec48f7128f01267dd7c1d3e81d6c0df58efba2413416));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x11639b368a27112fdcbdb83f3d9c37737a3d10696703f1a6aaad744c13cf52f6), uint256(0x0857c8a373036a21878313d6152363565d0e4d6641fccd610b810326ced8d2bd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x12dbd8d84f41cc62c02f34774976626739819f1cbcb1e32a9c85c2943956dc04), uint256(0x2988372fa8904f7d614679ce3b6c25a57d6f8142efac6eec872cc5f08bebfb31));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x07292d3f206fc3fa71916e58d75edb06ecbf3cde04eb6993bc85cf5fbd2b8211), uint256(0x0b26e8e0bc67ab69a57ec7614f0e7c916b1e8e7ad2cc8c463415c787b8af4619));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x058cb15229a735e734992c0eb5580f9132cb7642fb1be26d67652ede848ffafa), uint256(0x1fef556c57cc5cb6d2a22d01f69fde3f1b2be505a2ea4245a1cf0d90cd8e0c87));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x090652cd2787409e5aa2e0bda37131c7fbc6e8425686bd8efd02ef2eda4a3e90), uint256(0x1606f72c0354af86c0c840d66c48667720a10a2d8ef8badbb96886035e957585));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x051b2d2ad342c0e99be65767e73db4782e31a2e8a10947df28ed1c55271d59eb), uint256(0x0dd2ed787da18938a117ab1d73d2003508e8e6f5adb2265599e57a827f876272));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0159e8c8ba16c5c198d01c18ccb7fdf013a2625c626136c0bd4ca7ee5f015aa8), uint256(0x22ed9d9b31fe637bb174accd5f3d06bca4f55d928379eb997886439f3f42fe80));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x199143e8d043d2be0215810e956206e1a47bd187a52504322905fea6654cecb5), uint256(0x0fafa1cca322911e476a4b201fccf79559189c5f3658bf3e919ee60639d15807));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x272b7b6790f236c7aa3ba5e44d2d1134c7d08e42d0b93824b5262b1ea5382d5a), uint256(0x02ddacfbe3131fc37895379b3fc1ae748a3ac68435ef4371034f635968bc8e01));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0f01cffdf79d9e35f96e6c7eeade9360dffce852b975ee7c2c51d9319a9c9bde), uint256(0x303ed87464d70c9062c309125b5a45d2385752dbbad431fb2c2f8c6666f74a99));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x1144de4794e01d60b3b8c103df162a5b06a2fbaa1e1c70f267821298be24af13), uint256(0x2a9bf47a113cdabfc99b8651e959f11d5cba7693d750fb799066ab8f2246dc26));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2462414659bfd491177af7c1be304106cce70cf6f277fed62636e3aefa6da6a0), uint256(0x12884c6df8d6a939c855f29468845e12cacf4e003852394979808c78d3836ec9));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1563469f97fb6b337655952422191bc22ee012e1cecc3b19326dd6e904610040), uint256(0x23bcf57dbc9b3f2195709a1037a299308081d60489e07ec3b37083595eb84e87));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x099aa41ee049751a95896ff992e29f43c8243924ed3e562704cc33f0d082c6e0), uint256(0x1baa9ea4461465ab14592c9d79de409a2de7ed672f31d903f3cf968c0a8b8bb5));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x014a446143e652ebf0d0893230546f4c8834b1010e933e29708a30ca6761fb37), uint256(0x23e1d451e543daffe54e1df42a93b4d68d1a87551a4ac33a78aa3797ca160640));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x23522ee99d3589300ea3c73b1fbf60d41372b5622e4d7ec991ab30f886122508), uint256(0x2d3c3cf2817626c6a0ca1d691db7fa5b45b0a6ade99a112674706135c5a2bb30));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x06b0eeb9f38bac470d10f1fa0fa4adbe32f2478de5d840443948a17ef33e3480), uint256(0x2e82ea608369d25d18b0daae7ea97cceb65316218f85d335e0a5685379985434));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0ad3032ab983913d95d9eeb975eabcf0946e468f92f7fcea48361bd0b63a862d), uint256(0x191a09d51e1e31adee7fc4d5611f2c577a45fe7d5ea47fa93cc3345f0cf27646));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x056b5757de53b7afb5f4f4f2046841f6cbe83fdbc13176da12ac78613de5cf17), uint256(0x08bc2a8bca0cd6d02ea288a446c3ca09ef9ddd2b3cb37d8ef628b606357876c8));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1a727990c2ed804df5d9cbde4d4bc895e5a38d716b561245f584b6aaf3cad786), uint256(0x0876ec1c164e15079d6b9b83015b5584d3347e10b56be986e618aa6662f05437));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x019a5f54355a59cbd127a8f2e934b6ec54e1b83b7824bfee9d27a0d2bd38f653), uint256(0x098e6bfd24a7f58f69a28b2b5e1826e04156bbf3f12ce44c194143b3bcb913bf));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x06c2fca52e46b6746d9bbb3c51bef79f9db330233765441cd887d5d13bd95970), uint256(0x2e5ffa62119ee4ae963bb672735f9a373e61424c0a3d32115cb2f98fa4a9b126));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2948e5434ee91c80ccded41608d874254978e6fce682e7bce4212bd6c6cda79f), uint256(0x2195318adf78e9be5750b302e47270df0226585ca0a87cf49c6d1999185de5dc));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2bf6d940c5c57730c96a32c31b9015a42465475d92a2d2e776fc6e3d61a752d7), uint256(0x04ac0a9faa314f069d727385f582b7bf95700db6d1b46c9c9ef2684bee11fd67));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x22200f2517de4f4809f54e6dd90af2aa65bbf99d0a3e2993b88b0294757ddf5b), uint256(0x0bbd5b064aa56b38b5a1c19b62c9bc3decd33d36d7d8537841a2342818cd739c));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x277b93342839cd199746471da2c139b75e8fcbc7846b9c32acec3ef021488ebf), uint256(0x03458c30b3d6e1f563b4bc5b9ce988e7d7935252768119b03fcbd101538edfb7));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x20f953645333bc3d85d032049f07b7d952238d6fe64f7cce4ef040510ba1bdef), uint256(0x14204ed3318f238bca1e6eaf114c3378ce8a6d639d7dd79d00726904670518f9));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x00b6baaf99eaed09084a3480e08d0cd18eeaca35e60e3f5b8fe2f1fa7772d7ff), uint256(0x1ee19ba9435f2a38cf290221290e3beffc5b84567ef6938a647a83a5d1534f5d));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x09832cfde7676fcd2a7e95a888b420c05786d8948c3d7f2268b0764ea522c985), uint256(0x23eb266de0e7cedf720d3905ae7d02daa073924ca172b31eba2a4faad211b8ce));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x30185355058595cb0712e2277cb97680cc0b709bfa80031085673ed90554804b), uint256(0x0f3fe60931c1d707790620c1bec41dad6e0b751742710a2615cafa00a8564b7a));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x20392bd5aa4aa95abc310ead00a294897cf0f128726fd3c9a9c414efbee70c46), uint256(0x12a0c5eb6be428cf8099409fa8a86d14376abced90dd1c5d1185b924f9eef541));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0958b0da9e102ed739971b7eef40d9ddc8fb90a6070333285c841223ab86fedd), uint256(0x2f0402f24f8eefa27f271dcda8aaa0ad55770afab757347052684f272c617b64));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x07215dc675cafb6f767ceac2a0d2dcb02cc7712e25e7b72ab7b24d72f740bd32), uint256(0x168cffc166b3b84418841b2c8f979d26afcb83dec3db1b2e5bd9221faaf6dae5));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x055d3124dcea8dc997097d7ba330af54cdad649f9262647612d755370817fd32), uint256(0x281721a8c96705c1058198cbdd5cdeb92ac732e8593cc42eda4b0535ffc66aa4));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x03ff5a747e1678964c4361da29ba370ee8a2a594920dad0a9681d91fb438a8d3), uint256(0x2d4abe5ef9bd2da095e716f7802e3b9ef0a08132dec82792b184bc3a6ea5dd6e));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x1f73178da59aff8b56a60958da644dfb9776fc9f126920f5680371cc1ec95abc), uint256(0x215af0eb6762bea7a0a05878aedba11496e5a3ce5ccba39182820282add86fdb));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2d6610fdc52d961cdda09db3c7b497a0ef2fe27f67077fcb5d89ae78281719d2), uint256(0x05618e5e2ebbb060719933195e9ed665367f540bc4b75c10e072dbdf154f7008));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x031f2af2f10ee224390c4aa795b88c14f3c33041c8c5a3588d13276f9398bd1f), uint256(0x25b033b04c2ce29067a7f78ebdbf6c3dcf467803e2828c3fcb59764a18dbf71d));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x259df85cc0f8ba8e7a72fee9059c722f45d1fb005250588c18de54ad3d35fd00), uint256(0x25db451e38d1a5ccf3f9844b57ae8baea112e53476d20cfdd62d4f6fea825572));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x20f5993a2837f86109da2c606bc9cf5daf4aaf47e0a06a3483bebe08b9757e57), uint256(0x06f1d88ddf15adbcf129d4ab2a2796241c5dd1bbc38210d939a06e3dd14af2fe));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x0e9f3833b7e17ab8e01a5b369854bcb572f9a13e382b3b79d9754d8b8d0b3e43), uint256(0x1ecf84b5235d7cb51f6f391f295f1722c737fa1e3fc0b84bcbb1fbe6876705da));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x004c55a41b085b736c0f5349227467d095bc219e4f8025a7ca5308b6390fa1ee), uint256(0x249f9b3698c6a49309243a1616c7b3fd11537345ff582c93c1fec76d078f8e67));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x0f675b71ed9161c3c32a1a6c04c872d93c9d235068846bc75fdb68857dd4488d), uint256(0x12f5b2fe1f4e0e9aa054f2cbf8d91b4f2bbd7c30c5ec3e23f26028a4aa734f69));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x275cc56bfd83e0a5a19a3f0e50a166dc90d085224dcac4891720d169bd6dc6d5), uint256(0x267ad62090dd8e56c038cb82e55e8ce8448e39bd0eacce8dc4a61748caf90b92));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x2adb6f36b36447632f83f49091cbb2de3f39a915463915986aac6ce533a051f5), uint256(0x2d71da23a109a8c588a6d7a4a3a61a0e82fdea808a4048fc871cfe36d15ff085));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2aabaf9830aded170b409ce18d41ed07a6f3d592587e50332ad15d6ed630c57e), uint256(0x16833fae78d0689c8649eeac07ddf8ae42d48afc0086d56574394836f20b39cb));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x21b7e4859aeb820f9571c9bd22296e289d8df378e16e96bda5547fc8869b0f14), uint256(0x2eafda541bacf63b5175b30f8cabf0cd927e53b3d077d5e50e5f631857cf224a));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x13836ac1b659a3c9ed5a60cf512fd8252a65b7bd17ba2d2c5828c0b6c75cdcf0), uint256(0x103d524ee1edd70eb3624b2c683c909b45a80ecacba784f0edfe40e5268eac5f));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x09d0b3ace2d3cf67cdb0a64654d32f01fa67a1d427e72f996eab191d1ea91cde), uint256(0x080630dbc096c8eb9f1028f355790bd6c2186612828b14d8c470166a6a4816b0));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1c4c12deb5e3065eb4bf89bc6d527cd16ef0530195acb1c937dce848a3864375), uint256(0x288952e314b773a1b7e64b47ab67ec73fe82c32cb37180c741853b35fc70f775));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x180d5694adc1faa397bc43ec615f6dff81b4e7fcf0eea92ca12433358cc5ffc3), uint256(0x072ea9f8737b696faacd5affa6efa8ff010a2cd527ba470a7923090144a61bb0));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2e8574683fa9664e032cc24ddb0d626f45768c5f5fc0b26622cbbc1d2e4ce254), uint256(0x18fbb86e8e83037fd033b6daaa082e9b8fa0a3fc0642990be1ae7d0c39f6e7af));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x11e73f386afb47a683d2e3f08abf763f63ae7955bf34120603c9905ccccf3e7a), uint256(0x0094261ebc0dc2a8c3f009291f742139aec025dcfcb5b83c7a7a9b95c65a8a21));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x2e007570a6b85a9e97fb93b8f96b47b8af9aa2d5a60c1a594f2a5aa396cedca1), uint256(0x29f64c55237cbd592abf21bde50938550e6ae164c3e14943ea11aea62645fa2f));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x2cea3e69f0a65c070caaa382793b49b48135cc61e0c182e36e6be981cfad12f7), uint256(0x08910999bad3e3d880f4df2894fa8c03a9ff577d6bc4f448d06d778f33cbea1e));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x12de07d2e95745cd6957071176eb202222cf6290600c90bccbc179896595297a), uint256(0x26cfd2be83762ec8c7f3595e08eb69d1b0605284d95e02cb78e2c0b0bd998aff));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x04290fedf861ac96cf0363954812b4c66d6443063308aa0859ba4647a2ff513a), uint256(0x0017c98b1832708f71cdd30923552f7f415d30cceff94fbbb415946f0720194b));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x264e7bc67a155c332d08464909726db5c6f9e8463862d558c69ec599bbfb1890), uint256(0x0e9efbc81f9d79a0c4f7fd15af988b63d5ac044d2bdb2ac1626be42e48ac2288));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x011961dc4810dd2994bb62642e732026fafa5265d0cc39d5202f0eb1b9d31983), uint256(0x1a5a230ea6c75a1fbb4249374f13c8865c54a4cb0cd23d7a69b4a4b16286889a));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x0515c5739887efa27670461e1c12e9780556885532c032c36430e9c7796030a5), uint256(0x0dbf3c189bc1b7928099b92aa8a4286c1cc5badfe4b740e4bc9c73a817c75459));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0f873b61bd39264182be1ff340b68b0a705ff332a21e384ca6072e9673751b47), uint256(0x1efe13a156acfaee0363c9d397cedfa7c32744c6dd915ac19ddb8324100c8a8d));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x128068c1126040e399a248d24a2ef9aaba05e967410bd1b37aa460065b26750b), uint256(0x1b22158973ff3f2af6eed61546a4f0be1e6bac501b7af569fc96fce420365393));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x228ccb265a0e8d56c65736eb5459c36065fa1819b31118727724b35a6268d98e), uint256(0x2dad184a494cb02d26e6101affba425daa7a8044e4cf7715c2bbd372d4d57b84));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x27ce8c5eea8c9c719f6e2ba507a1bfca9c43a40970dfbefc41f4375a13bb41ec), uint256(0x16916ccd2f60715e0360140dffef11b431f860eceefea948f017811bee603f14));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x04bf69f9baede5e13cbeefcdab653f33af1ebb2d2fc9e4bd94d80f59a3901221), uint256(0x1c5c45989e63187dedf5cd0431d31dafeb3878751131c921505778324e6f9f71));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2e7774b511e50cb1f86358530ad8b7df84e3bcf25346ecd39c8b9c13a72aa29a), uint256(0x135f34f13ef7b35bf0fa11cacdd984bc08f53a9755a5682917c7c97555501809));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x00c23c731865173fc396539ed5aa24ab2f730ada701bc5d1faabac17301fb504), uint256(0x2cc7e00f0f599829cd5d4d305398dddc392fd9a0335b7a764377802e299f9569));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1b6b01c92a57776eac6a69f78f0cb1629d32829d2fefde07a9b4c0cc99adc45f), uint256(0x2d644af3cf4124e2eb499c55b5de8b2ac7af4de880b948a96b4b65036a627ae0));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x1f3573be26b3727a7cfa24fcc95acdac42adbee71e937d0d8571506884c52683), uint256(0x1e39d63b341c4f39a99bebd2cab37148cf3647e2aafc26f0125d35fdf401375b));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x0468d52da6d6ecfa9f953654f5a4e0d24b768148a9aabfd9e04d5806efad8011), uint256(0x1a011941a385c4133734e395efb2546bf30aedf80b7d8c054d59492f9d7d047b));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x24057ccff3faf5a64b57026a5aca6bc417411c22a49c31281487647e84e9fa1c), uint256(0x16a7f3197aea232b1d599d16d6be5a1c246856d52b815d677363137c8e9c0d7c));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x23443940fd53b5b872cd781aeff0a3ead3810f5334a5069c62db19d88d066663), uint256(0x21720aafad07a627a0a57a6c4525d59ccfa84c508b91f2cea2cfe15e72857113));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0b1c2c7517c9d1877f16dbb9b0b6989be5fb9abde0951b37dd7bba1ff138842c), uint256(0x28474a88029e6ff85b3105a79e2e907a50fa56fe0db3f3b03d1320e95273a45c));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x26d61d3e1df1fe573e37337b03201c1c64b467d75ea649807d1cb64ad48df6c6), uint256(0x07254707ecbb2e1729fa6de4da2cecbee4990ad80c3a95bb33c2f877710988c8));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x099535c8c7a615ed634931c83de207499fcf1058e40bf6948c09778388bd0be4), uint256(0x016d733934ea36edbd3aeec3f83ce4c058f0626b59eab9b4092717c312b943fe));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x230439166e67c33a867188c5190b70390ecd81051e0e9150e2bd892ec966dc7c), uint256(0x153820ca11e278a1c394b671e9a91839611742e1fdc2894e59a3835b0bccab4e));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x04b7386f7ab2d4901040b090be5aab798479b348d900ff31bdab7bfc140a8cef), uint256(0x265bbfa35728a6e015f436ee29c7985ddfc7894c8d1ef048fef5cb62bcc58c56));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x285d2655f62440c9ffae9940f6c26d8a482545ce6b5053279a435806130278ec), uint256(0x2d7202c28eb3527ced2ef6870997176169bba049c520a274de14660fbb8c02b9));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2ed7e3ba96d1341f134600c19d7f794f47eb1b04ea6b99bd762cb5df77378d5e), uint256(0x158187d383debf0d1e182cf0fb5dacd8ca4ac1782df011c027cc884795bb7a11));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x16ee86e4306c97364ced2d6b437cf01d642d38c2bc71042923c2bf13a84ebf95), uint256(0x08245638b25aee94a0c95f24d4f51a6b64357cc7ce6d11b6b276209ee7d86d38));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x192fcc5975d49b8c188ddf7ed898a62db888e4d5c7aa27dd7d68d61fb5db7ce1), uint256(0x024669cc8fb3886c5d043505dd1518a8961d03aa795530da32a1c0bf6e4c5bcf));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x197741905f4adf14ed67fbf3abea4ce6576e7018829c50d766dca944b097be67), uint256(0x1e7d24fda58b14ead16eb4d4e552c29d00d713dee17404b1dc171aa4eecb4745));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1fe370decc67d0d5e1a70f52133c638a7f5aec266a02a996fb88088c280d73bf), uint256(0x170fe38f531da7c781ab5a20eb79c5865c91b12fef496cffb2c73489d18e3e0e));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x15457737b92f281f534f4089cb4376f0bf22d1056dac5d41934364f028671dea), uint256(0x176bb54a9a73ed682f8bbd51f91328d1eaa9b088d918179e9762703d0e006ce9));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2c607d62d1f894b7462d9899998bcd7129c46414e922bd9f811c83ab2f23c1dc), uint256(0x03e160e0c5f6299a8afd3e31c3f1843da0fb3308d0c8bf761aa94ca47d00a33e));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x1a42fd0c19dc4138ca79d0add860faa60c89b8d9160e32e240328bdaff4ad77f), uint256(0x04190529f5326b567c848ca0107e6dc32bb3b637ccfb585b764534735158179b));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0171a1c65e291b3b6f5f6a4f9d514ab2fa32a300313a37473ba84f89f88317d3), uint256(0x2e100e03692c2fecac0865fe3fc302e02d60b5355c403d06cde066d328ebb253));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x140abc46f6301845210853e9a63aafc7a5b426edbea2ede14f754a056db09f76), uint256(0x2690d26e9d08ac7a752cf9606d988b12198ad69c8c118fcef874a2d1d87beb62));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x1e869a230aa2d426261a2b81b9df8c413ff9badd2b352b52865a889fd685eb3a), uint256(0x084c44e3fca3d9b4da80714d976d6d91ba8496534c1ab8e598202905da1f957a));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x13070bd1fe310d588aa17240eabf4f43c48ea02062ca89b8a49c383a75ab02dd), uint256(0x2303d66feaad9556bbad094745eaf445ea11db751604d154874591b4551d36f3));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x2ad4beb470ab003fb82717dbff1c11cd457275345d84a5475484ef723a8d64b3), uint256(0x27d73eae15cfd465837f4cef3504b4b0e157b475aedd9e1890c195ccae1330a6));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x009ed118f3ad8c3c5a2589cac69bb9601ff5eb4c4db177933ae1d79104f29292), uint256(0x1c02c7c17d3ca28d5ada77254689fd7b97a2ccf14fb1e1e0754f63fb29f74408));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x19d4006d64166c928622e8e5646ccb02f0981c75ad3fd5ccb25dbb068112a2ed), uint256(0x041272e5806bcff5c8271b9ebf2439c6b666bfd1df4961a19eb7c04c615ab8ac));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x1aca0df32f62c85e4a0eebd2622d9b12c773c055b740daebcde0701e985bd985), uint256(0x04a7d493bbf5ca8142b7bb41f9c3f6b394681585f1471c590e175dafcb391c3d));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x01e10586949b25beecb42fd52be104898d696b10d165c7bf338b45f8043e14f2), uint256(0x0894c06ed1e9423a57b679631a298d02033bf7c2a7271508c22a96839bdb251b));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x13e1bc8bd3b381c69c9602473339952d119aa82c3da7224b2834906931587b0b), uint256(0x2d2e8a4ec4549a23d55419424018cbd759489b75f49f752ae396b1f4b4901825));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2ef2c530673612393d5880d0b14a1cd28a177c8c6d59face43d4e57c02d82bdb), uint256(0x2dfe2e426f85018de8b610789ccc0f9d0bdbb19ec60a61b14e412d03e2304d42));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x0f8f1fc6d5d0a2031374cf7d08cfcb274915a4ce803f42bed176aef9f9521d62), uint256(0x1b630c8364f85404ee2db729157315f5a05da85161a1236e3c489ec9cf0d8796));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x212f9d86ac4ff7391f428eb12cc41b6cbcae4efc681aae23309501da971b2bb8), uint256(0x08557d99ba189d96c4a63b85e9955739cb2bf6fa9e9c4e5ea6e5faf7d76733be));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x278f32bbe656e2fd8d6454da82cbc3f206cff888e9f1aa0aa52cdf4bfffb54b4), uint256(0x29e365f6990e39253d2fa0e76ab0f5144e7e4bb1d300b85d2d8ced0500c7bb1c));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x24b6fcb49e6b23b1a1f3048d436f7699ea25ae82704291771566dd5f5741123f), uint256(0x10ed9788c6e235926067dd5f39597d3542c8fdb326bfd57a035f91402f1d76a1));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2524a849c48f8dbf8a56f3df2af7395976f2fea8ec9190ef647527f1fb8a396d), uint256(0x165ef316f2ed1a77437c40a0c277687e0b2cd93e61bcfe32a86b52649aa20690));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x289e39b84a4a520b4da98b7d388617e112c26965703da66df774e104f6a22c39), uint256(0x1858fd0ae351bb3727d941a3e0f849e556cfafbffee4a9bc4e21b16db8216ce1));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x0ef49dfc7bccc1a6abd53c9b8b988c9503b99eb36ee101d1b1425e3df599f7cc), uint256(0x2c24d3cbcbfc0a58a7ff4f93ddb52bace6ea7cddaaf72bca555008f650e34938));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x0fe4f9615c7f04989714888a12998d666533a94085d1d6057ff1f7e0ef3c1a1b), uint256(0x2cd2c53def6300c26de212556b3486088ddc241b9854bf852c9576557e61b471));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x2b8026dc1dfd7fd8243eea0dc49157e11b6d5b36c0dc4b8321b2e8a11fee7ac5), uint256(0x12f577286c3bb69213c270bd1dc245dc459602f841f4e526eb9c586b01f77eac));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1d814558511434f23ccaeab3ab435e1beab4bc8b8f90b1b49b597f2ff357934c), uint256(0x04ab03c03c1c8ad76a06834197e1c2c87a7f4d518e6425fe2b897ad78857eb3d));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x2345a54744db27cdead61057d735813b3ab97e9140ff4b3f85d4c6754ecf2d2f), uint256(0x213c22356e516546ef891dfebedf33ac7e896e115a4f053c1d4eb4fbff4eef00));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1552b2ead13af172d06c25bf5ebd1f4a254775aa8df583cefd97c9992d7726e4), uint256(0x18df93d1dc34c21a8b5c51bdbbd516259cd2960b96605878ed32cefdefa44e7a));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x2404e7506251dcaec28b0f94f242f70d76b6a003482db8f9ec5e1a0431646ce5), uint256(0x08262e44f6ae39837dee1b07ab53e5dacfb4c06db109cad2654f3abe0fdf3783));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x096cac2de58e18dce859cfca3a4b609b50b78f777fb256d66f0ef52c44aac8ac), uint256(0x1a8c17064b67a857cd1ece5b2eb59b55de7d23c4a93038ff12e2dc24bef89b93));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0e010b562557792b9ed0a35517b4749326b7737095ebe1baf321fb5d8d563cb1), uint256(0x07d80266326a370568fdad8259adde43d531685c208d22ce1438ae928a073373));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1f888a627079b0344ac1a82ad3db086b3cbc0502f828f2999d5b0e68f4dcb2a2), uint256(0x12f25fe63e8ec0fe85a46fbcc7f1f88050142b6811a95e689a22464119130f3f));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2b0e8dbb161b5cefac24e897e5e49b63221269ea80cabb187287b5cb32b6ce24), uint256(0x0e3ac001255ec0681d54d4b4ced607b678a68f6145c47cb6db44c32673b50c63));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x0f45546a59958107898beacbfa9aed48399e08e90c76bcbbcb0aa492ebce50e9), uint256(0x2faa8756067a186997021c97585515483a348dfdd03ec47189621285a562950e));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x22a6f12f213aca0a69eb91eccd838221fef87459c6a3cce5269e1ab34bf417c5), uint256(0x27be90b030574efd80956a0233df44d191d91a5a46e238cc65bce6943aa0a302));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x29d2d585d2fa29900f576815ba3895742893eeaa9656664533eef09d21089884), uint256(0x19fa27bbf406d82ec6cc685cd0b6c5cf63131d950e25dd929967244f7fc31334));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x0d79abf1cfd970b46954f4fe67003819bd3ce6060c683da83ba3791a53ed6553), uint256(0x28c8153963b38c5af856c3d4ba2a49c72a37c99cd87b14b4017c4595b4c38e1b));
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
            Proof memory proof, uint[118] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](118);
        
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
