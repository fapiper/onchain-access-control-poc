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
        vk.alpha = Pairing.G1Point(uint256(0x2cb9725ae0884cf3058b9e701db6b95e1d18ac0902f47754e56843fa8da31c9c), uint256(0x2b795e7f6ee19fa5b881452e613959dec2382b393c96162eae4079bcc6d0bc38));
        vk.beta = Pairing.G2Point([uint256(0x214512a1dd25c92c47af10ebdd373eb2034035d601047a334d00f906ec24f981), uint256(0x10366718e27302f6ce8d69d6c6bff9da6e6ef648125b170401d1816686e07cbe)], [uint256(0x0bdacec9d88fdb8c544e066c2995d1a6df9379ca648aa3a91c1553179cc206ce), uint256(0x06ddb88ec08946ca43b7e568cb924a8727b3062fbbce66a5b2221233fb72ac14)]);
        vk.gamma = Pairing.G2Point([uint256(0x10b73a3446e76568306479ec29799ef1bf6eaa2d343330e81170a00a56d1c6d3), uint256(0x11f27eb528daf584f70324ff975ad29f1d6fb32f0d9507f725232a0ab51487b7)], [uint256(0x2864487d522f470b52921674d0dac48d70e6ab419f230bec2488fbba66731e31), uint256(0x0ba421c667e3d429dd1220e47e838e94714eb1e77388ce345946684f9abf4627)]);
        vk.delta = Pairing.G2Point([uint256(0x0aa587e7a2027e77e2281075611c4183ed13d17ea9f83fdced34c679eb8464d0), uint256(0x285dbd6bbc9f6b6fb1b8024b05a49fcfd0c5acb5e8bc3f58bea4d9ac599aad57)], [uint256(0x1a6609c2ee69ac898fde88e8235c084105863863b5c622799f62b99ff02306a8), uint256(0x1bd39082a8eb6645ea17d8279dc6db55fa7117138f2934c5f235103caef43d99)]);
        vk.gamma_abc = new Pairing.G1Point[](49);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x28587db9232f9ee47442cdb6d5be0847ea970191e21527e6eda88adf35b43244), uint256(0x02b4ab67d8fb3ec00bf0ec7f333d1ceae1cf2ddb3a47fb5b727bcf2482ed0020));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0cbbda8739619d48d259f44143b950667e4e2e51bfc6bc1cf473f1068ac1d91f), uint256(0x18873c8cb53ad8b4e73eabfb2de7fffd2b7815bd66a33c3a903de63459b4242c));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x02c73daba7633aaa6d1174d2dd5d9fab8971b852325da0fe4e847078d7619772), uint256(0x03fb27e2a9c7935c05d2f1da923ec5997d71ee5ff4b2e1b4dae08029067e390b));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x07cb322411b075edb255226925c95de1d9cc7dcde8c64af8664ac4bfdad6e4da), uint256(0x141c803a7955ff3ab0edf40e8f728327afefa7e7f3c3b0d658613a50a6f1b30b));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0462379909ee3e44dc0cee76d26346fba0311be61627f15e9206016fd810dea1), uint256(0x09353b31c4c70f1cd57d8c9d79d933901a02a810f561376ae1052d7631ef1813));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x18bee3b6f7410a71337416accf0193dd9e0574ee97b32a63d71ccc43cff46e4d), uint256(0x1b3df4db1172f37bf2cea1cb7386a0d9b2832ca34cde2ad9a0c3b1cd89078426));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1757121fcb7b27bfb6d74af393c9863502fd881a4437bb9406a1b0cc0ea32014), uint256(0x1c94428ee7419be8da2254040004b05fd961df88b3ce87d5a8192a83d49fe79b));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0b7a3f905b37284283f4d79bcc77154a4d2b54e0fd73f30b6b959e8185971f12), uint256(0x079437c969abf056a7ba5f276ce383632a52eb0416155a30e82afafda56cd177));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x01b6eb699f5863dc48af66d157a8fbb3850c81fcd214f24e5f6cbcf2aa545980), uint256(0x0d19f7869225a0ecef9f13d87ff57833ac7cc9073d02559e4c428acbdc475af9));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2d1c79b73569ee0fa3b16493f559c55780b49a0ff16988c2e86ced5f3d574abf), uint256(0x1bb0a5e8ea319c409af1e6eb40e0ae0fd127b335f43c40452d31b44e3f108c1b));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1a4df7ae53e445113b33aa605b2e84480d0069a1c7da4d99dacce0307011e57e), uint256(0x0a130f616cefc41acf2aae7f34a3d68ba68260fdcb6de15ab4397293768a8b64));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x19d8eab6cfe8188686d3468f46801ae9c526524076c071f578c0a386f194b480), uint256(0x2b71b932cd45e86d38bbb850b4067d678ebeaa55a74d173d870646f8ea47c3a5));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x02925aad4f3d8aa90afbdebb9f21a782e22018edf08cc4b6645640b608d8e70b), uint256(0x042cb6057ea739dc8719742dbbc1489592a61505e0a0c5765c5109351a59d114));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1066d26ddd908cb5334dbddae44b1c375271439a7a752a93b29d36f380607e01), uint256(0x0e8a8c77cbeee954f6dea3692c3bc3e20a4cbabc05c59c7beb47f4aea6ca73ca));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1acec1411e070c5170f1344092e9523ba6f396588eeee54eb1bae01c8d5ebf11), uint256(0x15e4b481c83c276ec19c843a8c61dd14ab9db127d078719f8e6867ca2f6333ac));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0a8d852e3528d2042a0c91168e65c9a8ab98241c7302285abeeb9d94cd529558), uint256(0x23c75440ea36fbcf2490bf0a1cc493e2e6160dcd9b3e4a2e80c9fe5cb67bb147));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x302102c70f2a9ca8798cb8b7ed1ffd030f01471020da89369cd3d713e617f88e), uint256(0x0ad922d3fc2a9bdef621db01564d775cdf509717bfee6a1e036f87a7cc74a1bc));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0c044196e154fff3164865b0bde6433d27150a82bcfa55990e23b5684633f39c), uint256(0x064fead70aa828b5fc6926494884083815a3e66ac2d0bfeb41b5296290e7f7fa));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2b722ed032c2ca4a177422d534fae0e11246376e9b184f3f787aaf37c0807f20), uint256(0x07bcb836fc5888766e168e6a3f735c23986bcd318a104fc197627768d1c968b5));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x201965dbc37f25975145957ab88cbc69add74cd0c27e2dbf24956f91643b00b7), uint256(0x0f56c3bc0007f2c75913485ceb7008673eece9ea2520c434b3d6da1ad77424f6));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x262ab8fa28cb9942c77a00cea316be841caf2649bdcd297e1d245409abefcd4f), uint256(0x03f5c68ff56820b65698f372599cdac2fbcb47d90ccee3a11fa85643a0f9ad15));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x15b3c405f238b04634252b8d0eb13316dda5a0be5c421c54ee69627d55b03609), uint256(0x1c0092087b3d1fdc6c8a713a72ac90ab08614c52fd1c24e498e9c0be0e0eafa1));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x1dcef4fc2a2cb38efc35fa6f6019d6988ea4eb6cfcbc29147c10c12422a24ecc), uint256(0x0550fde0dd75401d0b7418f4c5cefe2ac2896ed535db3dafee7fa3186ecea70c));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x12e2457116633476f6966f17f20df0afb2721bc8c89bec862ec9852ad46b8800), uint256(0x02bb824a37fe46e520a1b984e882ae5d919535f93b2ddb819fefcca6a6467b31));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x066d9d24d9b61fa528f0e77cf100fbf48075614f65902e12e204cca7063e6f50), uint256(0x2e81263af88d2e4fa0b8a7a2cafd3f431dfbe922eec33ebbb219bff7a9ac622e));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x00672a1d7cd2f9e117669459e0ce6cee980a6711a9bef5809d9569b1fe9a44f3), uint256(0x0da448339c19abdb691bf28e831f3d392c40abec49c7cb33920c487d10112764));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x24c6882c5d27c9ac166bb2790af9a9c4fd427b403fc218b31e438d8b373abbba), uint256(0x2dfe59e12117cf7d22d0e24eb1fe4a15a2fac774c45b6eb8e693622f5beb4481));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0a4a40f9f81ba8ec73aabfaffa4d9acc72680755b786704270ce09ddc5f65c75), uint256(0x09e45351cef5a6185bd11f432c925228b9943f8c12e064edda914fcf3c274124));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x0256e19f3d6585e606d0985c8a05fd8980d1efd4145b72e5c8f77fafc526ba04), uint256(0x15be43d02272323e45f52c270aa1210a4898a1c38187f790fe63cb928d1e14e4));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1af4e378981353f824ecef3272d0b3a68573b9d9aeab3d32e5bc4c2b6b53f670), uint256(0x0a78bfeeb6435a03a5079308ce4a18f98cc5a80a034f2d9b8d9450a51438d631));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1daedb8c0412a617fcd18581292bf1cdf86afee5b0c5202db1d30a12b129d542), uint256(0x2c0eec13897455502d96390f190259fbbe6453bcc0923067fd0d0c3048002ba6));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x04b157cdc9cf2794864140eed6b10f2431cd839056b4199fbf191df026d13796), uint256(0x088c5213f0f7f6e8fa0de03896fe099a46800fe3b63a736058e53c717f49039c));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x0247c704fd4fa36acd0c412ec4e11ac469c03fd5a166f25f4b72d50ff09a31f5), uint256(0x03254b04320ac82073a9e14a48e014ab0670345e997249eb9d7e1f94e45d5616));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x19a6406f4e6dcc96c3a4010a61fdbf3b92bcf0896bd2851b5c048e3b2c2eb120), uint256(0x15af57da7931aef7497aba4379fa04c05811447084625ea617fa2b18df6c4bb3));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x10521b2d07705f6d17620d0d8d16c44ba61e1fc15f22c66e8cbd951e767dac9b), uint256(0x040a90679fba0d74efb15eb2950f005fcd5c75e69e085710f0117847acb10eef));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x040276a1ef50a3b2fa8f57a8ca9ad3132755b830b4efa2aa9637767177c7c8b4), uint256(0x1ec45eca6714cc36cd7c26d3362938659e92a7d777a35f688d4a3e66a41ce216));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0e09608508090cfe741113cceda1b1a1b4ea907356b424c2fa4427fc98956fc6), uint256(0x11fd5b900941af302718bba9b24664aa9709580d588d8ffdf818ddd4ce128bee));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x1526e10ed9f39f050357cd2cdfdca372f499463e50d168f50240b4c144517460), uint256(0x036cc48734c947d9cd9a65a5814e51f0f1fb8602fde3aaa399b1b2e965fa0b68));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x024d162cbabbb9b15a8931d1477e169b997fb371f4ea81b0197c6a410728d381), uint256(0x0f33b92334441ca4aaecae59e58c1527984b3da5e44300e76af9d4b2c8612121));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x29b4ec06cc86e5154542ae82d22c206357c018d559d573ba8e12deac6c4681aa), uint256(0x1b2fb40dc771eb4abdac66f12458dae6373ccae1ad3898932ff0969e38e1474d));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x017c8f15f2a90b0f7cf94fb940d9bf5867d9686b15037efd825c725cd7d79f99), uint256(0x2f46a68cf9c3fdd6f668eb2378cff32d4387284570507259665c725c525483ef));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x1e9d832449052e648efda5125f81afe7ead33dfbb078e91521f42354301b4f66), uint256(0x24b23a31cd0c26700e8756a334c4fdd260f3a7aa478c36e86224782eb8fd9dfe));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x079719b91f410194a9d0f24692e5b4b0d1851f2535516206fb8fe298596f6fa2), uint256(0x08e0733d9910b9fd2c2f1107eca3f74470eb8d6d4257f8bbc71fb7d0e72748d4));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x05ee190d84ceb1efbe8c1deaf61f9108723bcde7bbffb9aa26cce84df558369c), uint256(0x1e4f2f988ce49266a7b08befe1f006475f2f32bd4e26c36cc5ced7a5e0652f04));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1394f985e1104212418b49f890eeab23deb4b7478082b9127e5ba990092a1d22), uint256(0x213c22bf1e68d30770c3dbb0763d304c7a1f334713780618ad8bc5072126b599));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x01433d67e50171bbdea537e1476f99ef58e609c357d232db1dcf3deaaf6210e4), uint256(0x1eb8ad37b9a9afd44c85d57f2281eb4c24af4c02ab250dd87eb606e41d7b0a86));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1335133ba833b383b1ed61d4c1a284d59c790d26ce70ab0f70459961ee4d0ed3), uint256(0x2876fce637f2e6992c68ed18f0ab6debfe78e7101322af942c30fa916a0f840e));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0e5e134682d3706c4700b2f928af37b8ee6070448f704ed7ee587af7ea9c101a), uint256(0x1b408c4ded8f1aef7334438a91234b5a191ab8726da370c8a2d32998b6794431));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2d52dacf2cd0fddc526cdfe93d5c8e378a8aaf9928090de3186fbfb0b8546fb0), uint256(0x06a0387e692308d6421ba0714654fcc261af7f991bec306508f999e292d0fd2e));
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
            Proof memory proof, uint[48] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](48);
        
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
