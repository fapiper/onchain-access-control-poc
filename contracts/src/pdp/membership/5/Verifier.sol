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
        vk.alpha = Pairing.G1Point(uint256(0x0e2a8cdece4784d44789438d1c2d34a240988c225153d8ffa74442578501b0cd), uint256(0x150bdf4ac421911bb664205d6cfe4d5e57c8e343188a0ddf3be5e0fad5e2e8c6));
        vk.beta = Pairing.G2Point([uint256(0x2adb43c66b0ae76643b39a294a9e1e1324df1edfbf785df0789c9902663e6e47), uint256(0x2bcb89106a206ba4c0fe86dd90c67911fae16b93f6111a2eb3fc0ddf2573c122)], [uint256(0x0922704441748708826bdc8dcb2c244f6e422949448a9d09b11d6b00e5813a19), uint256(0x15f82d1004cd6c0c4d099ddcf09133618d25dc016dd8aa8cd1e77b272ce6d660)]);
        vk.gamma = Pairing.G2Point([uint256(0x02751a96a94c3dd24e1bd5d8058a8493db0cd218c6a2c43015814458074509d3), uint256(0x2e64d47fe3063c732e6758837e53454898614f7120ec3c7b9dd96837644aea4e)], [uint256(0x0b971da194f0d936f57418de30be9da144cddef55172eb95209867298346cf5e), uint256(0x13379a60f8f245047a294b8e0b8e366a787381fc70d86223a8c5be5932fa55a2)]);
        vk.delta = Pairing.G2Point([uint256(0x1af8333a9bdb3135bcb727a30182b1a56514fd22fcc0e808822150d327230302), uint256(0x08b79fc34943fb840bbcccd4a089c55620bd1a8593db1b130270e192d281b310)], [uint256(0x1bc2a5f355bf535ae4b4ccde8d36ef908a1f42090a626c7a0c50767424c4f139), uint256(0x2ca65b7cd11c7fb1d222ee6b177439c26a2a9a86928cb60e353455c97410818d)]);
        vk.gamma_abc = new Pairing.G1Point[](132);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x018e7abd2a0e810679548a377aa697d5c56a0e729c128bc0f5128a7f04a35533), uint256(0x2d71c2cc6741f3cc0f03aa72bcd8599f98257415c9b132ba6c7f70bd50cc7bda));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x19ec98dc9b125c79c8e30ddc867019511a4df5695726038f2e18844e2bc55dc4), uint256(0x176bcd55aff221223d96fc9dd9d524d0b61a9862ba1e3fdf09e91d9520686981));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1530c37fdd6a34cbef9982e2300e43988960632c9234b6066cddca2a2754d732), uint256(0x01ba8c5e0cb499aa19922e594b772ed3766e404cfcb35b8ce66997794974cd49));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0bf4d411e216a43d9b811be71f7297c99315352e940cbb374f4165c7570b1740), uint256(0x10bf66418bb34151a466a258f344836cd5bd1a07dec34da58a6b7a0f9cc75ddb));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2b13266766ff508aabb52bd511832f3fdcb5406c47da9d2e5feef4457d7796ca), uint256(0x0f7760b4ff9e43162f257bcdf20cb5c943fdd05ad29588e63315a06a31409ed4));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x209a2d6068ce94b0a533e965c163aa7bc3a0e07c3727bc1c89e1cba6e1725f7b), uint256(0x094f6a4a1ff280d9bd089fd6f27a6cbd2a80853402416bf691fb5c869f843efa));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x20ef54127529c2777b9494cba6f28cc92beae8945320e2af50301bd6cc6ca63b), uint256(0x15070c74a979442eba3f6854f3a836d5b23a73cf2587a543f84b46702a120b53));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1b402961cad3b4ae19cccf7ce861dc548092acc377a3774e9031f7543dbd0070), uint256(0x2aff74ce331ff597cbfa6e87825300c351342c8eeb212b3c7a46b9f6425ef983));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0b040bf7a2bfd6007cffbbb4fc3760094c0329b38fc4309f58f5b59785e92685), uint256(0x0658ea99a48606e6346aef3eb41af47ddd28aadd9c1614bf477bbb5b6ff87599));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x128edcdf4319c5f79b566a7f4d1ab92ac3c15645cb57a8676b5e8d979d7da475), uint256(0x11b796470eb7a8b7c05336a3badf2a264d12fdfe6279a41236d8cb196bcf36af));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x276194ae997d066d48fa8ebd091af7c3441e9955f8f2c68888acb829cac84fe1), uint256(0x20c41c8f58559fc7311a21b9f77232524ac83093a8db15292c78a221383cce06));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2ba9e4f5370ab4f4ddb84b0b1d6ff463e1812f24e995ffd1fc4ed0e90a6a4596), uint256(0x062108b84bae714a40cebb7359729677c5719548c05a1c7ab6a0d2abebb33b95));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x038d59dbef515841adc58d0f36d66798617c0e1becb122ec5f431b0d055d4114), uint256(0x238ab1df9ce16b8f35e87e5c9bfaa8a4f3c5ae9023ebf08382009a9bee6d5401));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0c452cd8c9ff315e8a7d5cb30836e93b2e6d98e91f1d1e777135520c823cf0e8), uint256(0x15e6bacad3ca3f511f8e71fd12a6c683ceda6a240c966904cfeaa83223452558));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1f789b5654ce0ab79389614a6fca5464bbf3e7eb8db6d911eadbb34167ce0456), uint256(0x06bd9a6a5b9884525026296039bb621d65c2708ce1e3c0f19327da7ddd8e1116));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x051ba5ecae9d1dd45f70fdd89ccd040bd09c71f3a00bef0efcd01fd5e8d5972e), uint256(0x2aef7bfbdd48d72808525648c50f061b18629872a18feaba84b3ef6d9569f80a));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2606951108bc58091e733724bcbd483e48f5446ffe248721cd44b9bfc8b5af85), uint256(0x2432ea76c15bd523ab1b69dd03e702c75439b5096de057d43e6d3916a61cfcc2));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x04771c4b336fe30462205a48c0d5b1de3a201a778aa1cf29983fc972f8655f87), uint256(0x0ce281132dbda4c54f8a241d37a6e16326df8aa0edba300d48016ab658b8bd6f));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2e948483fa125ed9aa9243d7e24bbd606623946f64dc3590fcb63de7aa33c2d4), uint256(0x2e8bcbb4a25720a76dd46ebd2228183dfebb85639d9400a9d50f0a155e653faf));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x216900ce32f4ec0b7d6ebb1ba3392302789d7d34b85c203ea337c80a7292fcb9), uint256(0x1133ec1ec28f7d1a51a71d43db853df11316d59b8255f5f74ec58064ce4d0bae));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x175850ea4a49a060ee18e1e296cc8ae17e6a4d8ccf1b42852dc29ae6ab361026), uint256(0x287e611719b308c739725c00ac3bbc8ca23aa4069a8d502863ebc81aa9fee2c4));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1745ce46f3474645d0071210d98d5f89be2c625a04023dd690cf3da4286da82c), uint256(0x0c737370ffe8ae39b8c6ea905f999f600411943438e3e95e4eda5e2c1a3fa838));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x0141c248003a43964a5904a17ecf979f38be29d1ac10785e78a0773e84a82813), uint256(0x296b1b82fbafb0f371ab916b5a39dbdabe4d3b56f6d51bf57cf730ed02ae8cee));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x24e06cc94362dd24d2ea2d1db1db04c03db0a9ce2917f1abe18dc5b761b8ec44), uint256(0x2a9ae35706bf50f25e92ef5e4bbefa11d7ebeeb452f14ec5c03c68cbf52dbafd));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x0a09a6db934416c78407fac4f2b1678b53eed1fc23abd5c28d0ad0ff590ea7aa), uint256(0x026e879b1f8c1819b7db2621594f51f2db2e0452b3256863a7af478043d4213a));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x096a308bbd822d5c108104841dfe6821ae99aea86c2194c1922398e8a3753d3f), uint256(0x193095a681a80e4cac03a0f1ef09b771cf5034de1069124045843f9eafcdb51d));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0ba21ec7284f68f05cd03def44d9c7ed4550bb6690dcb92a4676fde24393ce77), uint256(0x15c3b800d646918f008df5737f8c7f7fbf65d3b8d70538919ae094f3d4c12c60));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x22ecf73db634afa8ce96ac5317a8d8053d61f90321d7148986994fd3ae2e64dd), uint256(0x2c2d91e8c54e52fa121510e85f6cc04b0d12ef52ad0fb7d7443299c945ec5e88));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0ad56c75047e2506decf1a0809982a95a719e173e33f4433d4ec3b9cde9caa6c), uint256(0x1d8f916a5a6b4dbdfd5f3459e150a919cac777c03530f21dcb51c30fc81d1fa5));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x0622135a929dbbd910c60e657aae85cd719042c5efb6be24d1fe053bbfed8dbe), uint256(0x0cd1e729a6bbf6597b0a20e30f649dd8bd5d724f4a64ce15afa180f3773b33f5));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1a66208795bd06ad3e114512859f3b5e94bc01629df1420cda52a1d3c6f287bf), uint256(0x18cbbc4a23fb3e12bc274b473a9866b7ccbbb96b6eede40a9a50a3552f70eb1c));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x1b3e1e972257afb603158db88fba3cded92f349d182f5e622a5914833d5cd0da), uint256(0x064ef65d60713687288da9356a16939e4c783e31b5a7687d8e68b2e03368e768));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x02f75bd5ec698012b7d52a8cdbce2e261f2c08818cfaff03ca69dd4cf158fe74), uint256(0x000cf98c7947d48a191b97e56c35e5192f5a31de51e90a45df19d73412cc31ca));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x2ed0b4db5330b2556475c539411ddae566add10ec6a2b417c5dcf80944a0b08f), uint256(0x02f3d698d3e3ebb994605dc2d09206a29d6c863bc7b082e9348c8570f4f4f9ba));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0456089d57d3b5abf2dfde5eef4dfa510c05353409cea6b689138ae8092650a9), uint256(0x0f68a51d853b3a5ac8e7421d90ba2707dc50e8482af21993eb260d93ec56faa0));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x2ef1b29b1ba7119b0e5d1ca79930fdd6dbdf60ca09d3e71adbb332175fa397ad), uint256(0x1ff77e34c2ce789c77b4f9ebe3f1d0d184882e6941d95a941e8b60cc848fc520));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0dd15f43331988938d7ea18cfb45fcd4dce1c58b911857c5fcc92bf7fa4038d9), uint256(0x2eef41b9c53a26200abc94d61647fd1c41e6e722f2bd26d34fe0734d9eed6333));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x02f04a078cc865808fe1b9d566cae5829d58b050f1e16bb4b7b7d7606ac6dab6), uint256(0x05736e0f80c5e5d21481e38284d9a9cb044d019766a72fa4b054dbca18e878a1));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x21fd47b3a0d53e509b3bbcefd5ed013e1f2feb328b1b817bbe05ea7335480209), uint256(0x130bd90caca4c3b9b185509a37eac62925c73d18d06e67098ac0015af2c45c86));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x13d4c3b1c3c5ce133f3308750d2579ea8b1f34aad9779c6519c49758ada7b612), uint256(0x2dd290ae694e77931897d9854e6f10e3a6f7452e8186c067b6511a957f493abd));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x22c6d6edfa2138d8c91494bd72ad266909b9aacecdfac8e561b744f4d1affbf4), uint256(0x138f9a3da1bca610aa44f3a86540a5b969fd0ec6c7df1e35612e0ac1c27308b6));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x2dd843e294f18ce9f4dc5ea1c32c6a6d747c7950ea41e9c653002a4bb36a5fdd), uint256(0x1910ed82984d8446b1264806ef40eaed7c3892740705e14990c4c809e4331392));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x065fc97ecabcea32c1005f27094b9db32f899146344eca7df1bff49eb588da7e), uint256(0x2d16276b2fe18cb22b8c0892dd10087d26869c73430184950332d38b2da03753));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x02336b375f4a03fb8b423e0d12e11d8b3de05a06e61c21785db66f3670f5a754), uint256(0x181769ac96b6236a24811aef85e8725000bc8209a1b3604e3c3b413d8b3fcbd1));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x14ac6fbe4ac1d19ab75d343cc85fcd58df29ff7f4471f9987c87c3cd640b55dc), uint256(0x0e11b31996dfb1af54bf6a469726f164648a999eed79bb0d97551616868333a0));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0cf13a50150b0afd36203aafbbb419f9746cb5c7fb7dc90385ad106b2d6764f4), uint256(0x27cfbd38367665ad6fc39e076b2b3eea9fc74d427aba431f93e2013d1fc0acfb));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x080fa371bd983be9edfc7cbb5ef8cfd2e63eadc4106f0ca9df677c148531d217), uint256(0x014beb0526660d641ef30b040cc86dd185138a3686ebe96a63f8334fcb0664fe));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x165922e12e8fe7742d1e2eaf814f9d191874ba4c04ae4797b214ea192f8ec479), uint256(0x026a85a0e36ed9187498f675baec44a3245228dc1d29c2e440039a68bf43db7b));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x1ad95bc9ff1844c1f453e537694a888ed8dbc0cd10c0d6e8bef50b2b65c234d8), uint256(0x22513dded61bd7d7fd3e851d08b7050476e3cd2c963dd6a8691728cd941dfcef));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2665f9bc67991a5c2216989c2e299cd96b5dd70c13524ca7770b62fa82c69815), uint256(0x22ff837b31f7b811f070d9dedac84a155318e4c2ee7c6f9ce8cff0ba1ae3f94e));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1e8b74286c58450cc939c22d4fe0256c30c94cf37b6599f71f336d12e5e4a891), uint256(0x14b0386b00fa860181ded7d2f6395565794eb266c38e30c265ed142c510f779d));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1b1a376fc95a005875d87b67d666dbcdb235b1ad420f6fea815e7ce13f68a352), uint256(0x1a8d24516ba43be53e33b68434a9e268ee31131c45bf97b1224e299d5627a017));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x151b82a59d939bbc230e6999207648244fb6c9a085a7097ce316c839ebfc3f6b), uint256(0x1f1f979f5e214c513d961859b9d866fa44d60b6cfd755d3f5aac58c2ddaa41fe));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x10b180d7439e678c1786df199db20a787f57a86a9f29bb352968f5726b13d318), uint256(0x1ccafd7bcad8100334f44223a23a25ab5fc8294b5790c9e132f89a3a29aad5dd));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x084ba03766ad329a929d3fd5aaf0d3479d752b3cba6fb350d0f2cfdc18c9ec7f), uint256(0x12969443189386f3c270f79614a410859d15b2bb2d9664578fcf2fd57021279c));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x15c1af135f3ae82833ed3a350db1ebd84a79dc28fba718750a0e8c4677dc4196), uint256(0x1409e71451097114e1cbcdfc3200a3d83f732b7bf1e3c5a76c900c2cb99072e1));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x10495cdc67d2eb7d143edb7eb7c720f108053275103da7ceb79082f9e6340ec0), uint256(0x210e53dfb8fd7391671cd7eddda1ef29b67f84685e2a3105dc083f53a3b83e92));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x0e8e7fb58b893b32d8758d09767c0315a6fff9cc27e234d16fd7b1466f713c37), uint256(0x02b3cc304575986d4f6a4dc1a79d11e3e947a89d8e656b898322659eecd99baf));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x18e1d492454984f709b9b91ebe75f9acc4f2bb9fde2dcecc6ee2b46dcbe8509f), uint256(0x1e63111971415d76512ec8acca28b9721f871654c6783d89b61e470cb60ae07c));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2d4afdcc965f218dd664f7b6fb85439beca49bf6b0d94ba8d5efff9ffc35be80), uint256(0x04c4165c4c48de9a44cb197081cf9e824bf2a3cbce712d88893c4b40c3ed2a4c));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x076832cbb121ba3ec01542c8ee2f330f8af8c4b9e6fa210cb6791259a8b5bd30), uint256(0x0dfcf72257fd8a59ea2956603ab93efaf1e538c9a439514a0321bde065bd6041));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0aaf955a746d7b6bacb5641821261db772d61245d363a8f571e89b6c83688b57), uint256(0x1401251d260fd13035d9151399380e799f1a2642e0d5c29bba2a046a1e7fe7b6));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2faa23e238358b77efca7cb15d68072f6da35970f2656bc32cb5509744aadc81), uint256(0x047eaa83da15a8019f3f1136968a96570c8c4ebcd8b23b8dafd12800cf1849aa));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x234463aedf0017581416b9a8394d981146f6a34f15221e2823c3edf288d28211), uint256(0x0259ff0b3208ae69823f08be0ed0effc03c97ba82b8260118ceb8bc688b9b4e0));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x086b7732b387457a18b8cd4e7d469070d5f06e2a04884f3b1102da29a2279a6c), uint256(0x18dd9f189ec6bf6d04a6b55649e94482df252e3739becc9e8e24fad69b1e39f1));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0bf7377a04f6d32fd476feff8de654c946b12c0cd9c6456103778971b7694bd1), uint256(0x285603a63649530bd434e062760c3d0a4fe4320fb316cecc0e3166f27e236c63));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1dda86588e3c3e36f1828baeda081c6af645ddc2f927cdc121e34edfb987fbd0), uint256(0x1e4c5d6f0b8acc8fb0ddfc147389b3f31db11c5b12de8291734d51df7e6b6e32));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1861dd274d2750f7d29da9515b5a2ec857f4c44bfd93ce82ec62717acb525632), uint256(0x2922d724ed23dd87ecc90eb9fac3784c9f79b5ad358c4c236118e5c7868bb20b));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x170e9c14085b0e6958cb2ef58ba14400af05acc6c03d3384354f2fd32ccabb39), uint256(0x26996a2d39ec54fa1df6bb6a5cc7d73d3b69ce49591da7d4712f61dbf004931c));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x06aad5d498157f7cf23f9c832892d5a0e3223d44731881109c509539d4c12626), uint256(0x06b8b2c36629b53beec0409019013c7269b393d56ebed86a0d87a991820e9128));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1226fe464b4a697e25cc33295a1e4fd39827f09dcb94fbe8ca38b1d3a2f44843), uint256(0x0d8ad68fc7b909e1a0a2ba5a16ed29ddee9c03aa02b0a92195bfe7f87aeb4d08));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x1dc6376fe6c9f84e6f6fcfabd47ce79edfdff1d9e5053756480324bd8b248399), uint256(0x2c87a672bd5f9cae92f1e81464bbaca6824c12966adfa5082625c18950833314));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1eb3550317324b1ece598d8691a5beb89d3d675d25f3bad015197d5aa24805e5), uint256(0x23ee80cb5d6e46cd5e5d95cb9fc2184f337556d2771c17f74b7ddb99450046c0));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x0bca934158ca7d455c6ab9d512535496401867f7074d40886060cddc7cf0f32a), uint256(0x0e4d55c2d4c7ccd477693d39d2bf968d4635b4757e13e79199b3e013cca45b16));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x02255c7ce02615da51e03c01cb52f9c9b2a4ac4e59515e9e79f079bdefe55494), uint256(0x054cbe7a6ccd37ddc5dd57cbe4b878f4772d6a1b2cfe70c2b09711ca12e47c14));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x2913cd53668994c570b30d03758d55c86f0e6b14bb82f5bab382a822df65e624), uint256(0x288d4615c977f5548614f4584793f999cd34a6bafdf99a9edc713a89453cb135));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x29d066e0f659f0b08fb1cd77892b00c32e549f57332c65ae2d09176608d5472d), uint256(0x2ce78f1c4ee5f498f90354037fb5b159c4456f84014d0d3dc3d28fec6af79184));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x133ad24381881d241f9e879516deb61f9fa77aa3eb384ee1d7a18fb8fb34e093), uint256(0x0cd5c88f8545b020d3d4fa47fdcc8ba9066d808d4cdca50b395a5c9adf8c9554));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2d558da1eda6df361eb7831b50c0768c0af51e70230e6e906da82f86683f5105), uint256(0x2d196c2d476d0de67efb4e24e81bb3d3c5b68ebaa9aace4da64ddbbe06c246c6));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x117e05a7d4b1d76dc0be114ce1c573a12b8783fc2dba7311917f8f20b7d4d9bc), uint256(0x24f44fdeccd1190368adab1690ad2fc31a4b5783b2bf717f5964cbd3afbb8521));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x244f4d579a727ae940a0f0785a0023eba9e2095cbef287663fa0b2494acd1b22), uint256(0x026250000f3cab0a18ffdc803c8ae6a2057bd8e5348424f2dd086b9aed0323a9));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x082a2c8fd96cacee7abd6d985492a76a156efeb32696b8e5d0b541e6d910305a), uint256(0x1a0235ab492dd01576f365f247140ff7c330c8a9d26d6721a9baef04fb4088bc));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x01ad7b2e0dfa813aa7bbf03a605fbdec6526cb399d12f05039833c07d727c29b), uint256(0x27dfcf78fe19079f3d9a274785ea20c73b8d780b7d670efb50b104dbcca57c4c));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1761f1bcfb8d3fa93484e13519c69e2d115f1a3abd694109a7e6481b345b6ee2), uint256(0x2bb89acec02a7b9efebe30d1321446c63f4fc464dfd873b27ad9d9204573f201));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x2d0a6fd297ddbf2ac4efaef4a786b820be8bdec7083089ca44d1253339f9ccb0), uint256(0x223b82f077d3c614f8258953073b7d0d3ae3068b9f63e9e2efee90101383cb06));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x03546e97013811deac35c9ad7e87a52433cff116d302f941b489c69df941d3f0), uint256(0x2531af028beaa2bf4c6e9f8c4261f8b97470c382c46441f3db4ca7ba3f4f19ec));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x29d8c942a4e2cb2ca8e3960c8b523a8ff4bd5c9ddf5f12d98f1bcd25da0354d3), uint256(0x0d06963ce6414687cc64d69d7855b0c5c82b7d4a083f6f66842454d6d60d6108));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x1537faea5fa4e910da3020f17da6ddb0bb4af8dd3bb65baac30190ba306458b7), uint256(0x27fdd17afd2240b53bd30b4fc12b7744efc70aac84ee01c83eb6b67c43745c8b));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x024ba342ca87542de351572afce4b5ae2f2b8919706d54c55a9e1da3463a2c8b), uint256(0x0fda71943abd39effb3d4faf3556647280e82119711ad6abc1a2533c61e4fbb5));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x21953ec69d72ad3096b2f3ecaf3bb2ea61d80668fb3451d9c80e1148488be1cc), uint256(0x297d268b62542824385a81a1eb8e30ad12cccd2d84a4637cea9e50c52be169e7));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x0eddafa1b77df965285b82a4841d7d31f243a7eef0e5a573a101fa4dcc65f758), uint256(0x2a41aadbea1cb2db041e62a886a213d4baeb417ade34bae77423bed2c15dbb54));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x0680b914256e49d5bce307de4eb47a00c772bea7e08e4a75922d168d99e76d43), uint256(0x1adc1edc232d4847568e7275ea8182a9ad72a48a977a65412f21a1aea28a47bc));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x04b5a1240497a763d1cb59d9dc6c029346d9c835736930041bba7ab9c34bee05), uint256(0x130cb4d6c2514f535160227dce36c73459434e6822b49c14fd0233e58eb4a20e));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x2f1129240f2b3845450d67d1d538054bcdfa142cbb4ad454b83d2c686519a0d3), uint256(0x0aa6dfea128645a90b9c179cfaa40be59400a9762ac17d495114c7afbc3c4904));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x053dcd4d494e9f9b57e6d5513e1d0ed6ceabc96b5db9efdef59c9846f801c318), uint256(0x281cb47df0c235b537eed0edb1829a992fab5369b326be270bb47bf2a4b125b8));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x23cf70446364714c0d1e805494a57755bcd6cd5abae07b5ba342d42c06c40d35), uint256(0x2cb3ff38fd234533bd70ee7d9aace045375825afa6ce7fb9d9bdbef423d2d1b6));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x1c9ad1a02a7d90751fe755ded206a108ea3fb55535dd7953e83240401149b590), uint256(0x18d89e620a953dd0f5bf80b137fb0c9c304e650b1e9b89d38474c80f657e0204));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x1358363fb8af4dd9f12578f1314f7e4aca4589be75811cd7913813a0b1417b83), uint256(0x1c9bd9ba115ac6bd32b0b88da30726445f11e116e286e37647954e61fa0aad94));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x1a7571ea66ab3a8082b7aa9634bd8cdd1a7a75a8fde4faef6d309fa2c5c97edd), uint256(0x04fa4eb69a322d3b25e773e5b788a241d7b945d39aa341caf83a136e4966ce63));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x2c2db0ae2c04694fce743ac4cef34edca0c9015809a123244d124ddb65471048), uint256(0x07e37b397f8edc007319e4effdcdece642938da8f7f0a966eba6beaf499a48c5));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x12ee4362e828e3dcc6a47b2174674054cb5190e44fbd642f19b88f62e79f7e35), uint256(0x143e8f91f08f5c6dc77e016238f16e999cc602eca297eb02b2d3bb81a6c97222));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x23a09b91022f59f340c16a73cefc66cb9d2c12e398ed524012317bc0413963f5), uint256(0x0974bbe3491ef908fc30d6477f8c7b190ff64d9c2e982620bd5a596ad303ebb2));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1e461525f021e504ffc4b8f21965dc21a4f662a1978811551157a585a1449c2c), uint256(0x1cfe82319c886c0d36aa6b8733e255e26b29cef530668268f9768331709f00b0));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x0ff777e363b41e84113bdf16ce0dcb55ae27891a08e7fb481ecb29ed4d2b60a6), uint256(0x0404e6f21c523475fbfc1279e7ddfc36f5ff2697bf23e8b15eba8952bdf57817));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x10d3b123dfc12a13f5c03c295f06a6213eb00b21b1c423c444a33f7b03eeea4b), uint256(0x2c4a3ee7aba0bbf3485ebb5d0494c507dc967a564f9f775fb8dd6d4e41fb6fa4));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x10140f9c50dfc1e881a44e2ea3a482991dc220e8f4e6cac3a605ac51d7057e77), uint256(0x0e1c64140906ecf805c261cbc4c805c1610a446e84a8a4a4c1580f9e822c574f));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x04ab2fa774699fdad3c3f50545ca3c52260a605fed8f42d71e8f504721a5e02d), uint256(0x12da422b55ba3444a7b78325bf935a369a453b66bf2915f69bde0e1b32a91cd8));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1a4f19e2b7f690772b0cca4b6c8ccaf496d4920b20980ec48c20ce29d5d4ceeb), uint256(0x2730ebc0ec690a26b234d190f27622b5cf6ceb0078a9c13360cdf49c64186892));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x26a10c9928a70ed08be35e21c3a691dad8a932b033da8c906f722489330bcc30), uint256(0x164014c250f8749a9c4778dc5fd9143c3860c6dac04a28b21451ba93e12ca398));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x0b386a306d143d09c434a157b989de4a853fb6950395829a228bfa40631d4dca), uint256(0x2182d7d6cdea39cc279da64b770c7fce37b77e37a7ecb1e13b132ec8e9977a4c));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x18d7fba8439b330832e5f4d4802e3795f2ab17820aa9702ebcfe00bde1c1e55c), uint256(0x1e1ec9abeacfdc7293296e89db18a4c31d94fbf16b7af6a4a665bd16ecf4ae41));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x2fdb236c7e6609f156bc229f939604e280f7f1caa3c8e05021c868a01af06e95), uint256(0x25e7edd526dccab2c70a8b09af2ade3c170551871ebdece06589c05f65466b58));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x0161848a4c59365b8a0e21fd2b0407de6d429332279a1dcc4efad7607fed3b6c), uint256(0x13638a7a72fc6931496fd5ba1049aa5585373ff6b96f0ef9df4f0e6a582a5868));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1a208d6ca4e079711e57b564b2efeb2b8707e64f01a8410bee87f1f8c4dc9bd6), uint256(0x04a80bebc95e206f5dcad5faf78b9f590a20978f8ce52c93c2304b0ae0ad987c));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x2ff7e99e614abb47553805b01fdfdf6d57f59fd6da968c72bc9ffad45e492cfc), uint256(0x1d8588966672f8c63f51f1209c3d71f4732dbcc45069a9fb71aeada72f7ef9c4));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x05802b89c287d521e04e9760f8a0fb2c8c2c585dd7505949c300e5b75314d23b), uint256(0x0e35093e1880e08cb19582ef26dadaa54a957bd4e9b6ea55e6bba87411a19577));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x01c73ee4348394eacc059db115d91d7799df310c0a2639ea27c4c567f150fae6), uint256(0x0b0178470ef0732460a253d37e11a226b8ebe1aaa67e59c9c09af1b8e73191ce));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x20157850ec178b89e5ec98a59538ce0a30a88675b90c4578039c09a384c924cb), uint256(0x08081b1e5562c8ee78c1b4ecfb21eb50c555d263f1670c27096763c305b9841a));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x03ac40da2e8fba4fe5b4e92d27ccc85bdf3c10532600e14cd21648a3d4986fe3), uint256(0x3021687e495d647cc369b24c217e0470d93e5248d5fc573e36db0c6ad34c3b43));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x0afb9b69469ea26dce55d965e5a399c2fddbb8361ef86316130d257d276dd825), uint256(0x292ec768ab47d63f9e0935628cc31782ef1b5f252244d460819301ad7ccb2544));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x246eb89dae6aefefabbbf4896f6247cd3d26f3862ddcca90165b615e9cb54016), uint256(0x16677caf4e66e87357e585a8acbea602dbe497cde0d5af09d30b2cf1ba4627b6));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x2105964bbfa90aa321853f3f85526b1f7f13d22493864972e3810526b7b5b2c9), uint256(0x19f1634527fc1edba332f1e2f62399182ca9f68b069abb6397861838db9f11ad));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0bcd7f9757c74948746c38558e4f06520eb2f8342250f4af505492d195ade70d), uint256(0x172b63b614c79740aaf735eff7a644e09c2162d3c280399de8aacef28c5b4417));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x1655132761ee42f77e42b65c0c74b288ebdd494bf5ad94aafe84bf6779ca76de), uint256(0x0c1006d756db88d9821768fdc301e3906d064a41e8e90b16cd328d6183842184));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x0862fc74f2a8b143cd663ece9cf53f7c1382638de35d3d53f0ff88fa10198247), uint256(0x0f742a4a11178688e4b705673ae26c10109aca1e79177ad1440c1d682711078b));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x034733f9e1192961fef47995acded0044aacbea464614d4c32f7cb1c5bd80fb0), uint256(0x2a3aeb69cacc59e5ba52888930cb5f4964efa565316d5f8a7479214efc2b2285));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x23a456e04ae25c969fa6d33706108dad2b09ae54357e0a43afb44aef16324260), uint256(0x11d8848f0545af0e174d99faf8d0c4cac68ce714e1be14d873730bbdf80c613c));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x1efae474b60d8f51b4ed4ee1e4b2fbdb7d128c9095d7a28dd10c7511e2972baf), uint256(0x2cc97e603740a93297e1e02326c29097e90115df03bc42c1883dcc11928fbed5));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x25f455b746735e7707519d7984fc07d0b5daa9defa1b7f830516b70bd9bf4dc9), uint256(0x2a43b5082d89487430a2eaf58a1f44ea68da475d91d3edd79c294fdcfd09404a));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x00decc0368486d3edd36c4aea17753937bd590842ffd9349c73248999bc59761), uint256(0x13c5f9a6e934f6e8d1b23c47608ff202571ef12547989f5fb9200d62c9e82b96));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x21b7f861738d2a0e6a7a3bff287cd981f644ec92510a6701fcb345fdcec4caad), uint256(0x25f100ce7e3f66c44038adcda8766ef255f12502dcbec6c18d55bf52ee1504c1));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x2d2744d3fb8c3d25ba6c82145804672bfdb7848255bbdcbe4ee080b1554b6c6d), uint256(0x17a7cc43bff1a66cc1387ec7ee7292b5de784fdac2425d0b7923d4995d18cef9));
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
            Proof memory proof, uint[131] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](131);
        
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
