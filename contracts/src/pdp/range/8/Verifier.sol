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
        vk.alpha = Pairing.G1Point(uint256(0x121cf8d716d59febb6e9072ce15431056e637b0ef470a343d96fbdb4722cc9e2), uint256(0x081269dd6c9a0b33cddda65666c1fa5e9f7d5eb547cf2a21d0b1337b3b688bd5));
        vk.beta = Pairing.G2Point([uint256(0x055d3a48895629c6264331049c48ab1f688935dafce17de1a8e4412a44ffef12), uint256(0x2016df64c52b2af338306a2e143e231174687af54337f39d8b2d0168821ab964)], [uint256(0x12b217af0bbe41cee7463b900b3ab1b228b17b3df4bd0911c1c1adca8e628057), uint256(0x2842b548f4a95606192c932e5275927273a56019b32249ad50f8e9b88094e005)]);
        vk.gamma = Pairing.G2Point([uint256(0x1bdae3c430ee2f838ee94d638f2b68a7964512a4661290dc5c88e0e5d6429543), uint256(0x0aaf09a89e5ce3bf8239d73cf534aabccb12b52290d9ff987bf6b82362e202d8)], [uint256(0x271358e8de19313a35ce762af675424288874ccd9335793e1910287f912d0baf), uint256(0x172a9acd3a57bcf6a2544d9bbe45eb9235854e998d3b6f100bd8c667e89b28f6)]);
        vk.delta = Pairing.G2Point([uint256(0x138fa6f9c06e84b8901768430a1a9811d2992e12a45513ea253020b79cf3dc22), uint256(0x2df41401ea566e524bde6b09cacd203cf0284ab6025759e9dadce72399f229b3)], [uint256(0x0c886150568db0fca62541d374deec50ea5a0f04dd225fc876233bf05357a350), uint256(0x1cce8dbb35d5b6edceb7447194a8e592bf6b49e2792838ef6aa87f9a5cbc83f4)]);
        vk.gamma_abc = new Pairing.G1Point[](161);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x15ad8c27810ebe2d34a299d4d5c7c245e2954b8651883e4faf54b0115fe85b8a), uint256(0x1c561fb9c75afbeb4e46b06d67ce6ef0015380ce9c0ebf70914257460cf06e89));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x24bb0faeaa62dcd74491c6a80962d3af3fac24c5dc67af2267b54f752aa4bfba), uint256(0x2517a6efdfa9b48c39fec51e03058721f70460946a1b57db740c570da6083d68));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0daa2fa4d50e446a007558aca3a5d23bdf911921307d1d4b9ad170cba2017e4e), uint256(0x2cc30cf963d5598cb558f758b015291462dbfb3ad4a75839c953c08f96de1e12));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x291ae6b0e988132f3d51489b93b708df3d97ce4728748affad10ddc2fbce2acc), uint256(0x1402aa7605cd0bc7e7978fbfb98f872f3a429932cc4b8ad14266a1897feea2ed));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0039ab0f47a35c7d9f948575a61cc159b21c9d36fc2c48a12d95e197c3d8dd0d), uint256(0x0a6f7a5526807b8c46cd92893fc698a1d8bc9383eb3b05912118b9b85ad1a716));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x08b2af922e64e8fe52ccb34dcde23c9fbca491b79b4976ca5668e62b4ca33486), uint256(0x25986bbb1a156b0a51d41e9ba24fb33b008925ca1dbe9565550e178775454321));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1dedec897a6d4c081836863b058b38154b41685ac7f7ada901d12c8cd611ef69), uint256(0x2649e53bf243f667b7c29e7b6b240beca9163ad939fe7ca4ea8eb3f721195490));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x04ec663584a89d33fe272e64e8d02fb4a91a49937cd009fc9fa63d99eab96980), uint256(0x1f58e586c47de4932aebac6273624aad028c13a303e6df0243a26112543d7fbb));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0d8446b1ddce1d24b8a23cdcbe43111f9ea15fc465862c75987620373e9d975a), uint256(0x2522d0223d8a0bfdd1a44e8af80e464d0e7a3cc002e971e7349e6e8b494db337));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x248ec5a0d7ad725402e8603f1262835f8455d833c1e771990767beac451723d9), uint256(0x26e7846f7436f1ca38852b844a0f6ed08f207f7c86d2c10d7673e781437abd7f));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x172255b1b62a5eef2977ce055d671080587d04d55dda79cafda67700b03b6597), uint256(0x1044f45bbb5f86965207643ee262d4e4686a767e18f72aeb1f3f7346c38027c2));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0c6c150dbd57be8a29624dc747acc847b0cb2e29f7023be42f33fdef20244d1f), uint256(0x2bf0cdc61df4ffe288b744054d223d68aaab9ed5593839756f8da67da9bde944));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1f67889091212828dafd8efcfb5f9901254e6a83f148b45630cae99fe24359d5), uint256(0x11bd8f7958dd894686ea1d19e391b15ab861422483b7b162ccc100960bc84680));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x0d8193e647dc12503380d43695e57ddf97aaebb7bc9111862d66a30bb42bfb75), uint256(0x0d84f148dfa234361f6922e2746543d91bb9abb4e27e8eaaab4c0d142dcc9589));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x29ff2192662251dc20849f5560a0b5408cec1d2ebb7ffb6cf3d8d2a1c968e7b2), uint256(0x17ec22dce36e6d3e106b57e67b538b596fafcc95c0e4f8cbd0a6027e029bf8a2));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1c218685fd7567616ec22e84cae35e750d3ebbf76cec0fba8d0ce301d4e46998), uint256(0x1efb24a1e2cf5968810821897b45c7aac164eda24b9d61eafdd0205446ffccaa));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x049df4d3295ec095ecbcaef3ead404c73db92575a6ae73b856e72f63132c2c95), uint256(0x0119ec06cb78e9bc241d639bb1476aa892e1b9baca7b788314edf170fd79a547));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x296466dd495b1dd21ca9cb8433f9a1ef468a6da915d6d8935f1d57600389c2e3), uint256(0x2fab6c3924443aea5f91fd2129d28bf4ccedae8837ace197c6fc32cc176b3694));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x292661c610ae879b5383e2c48cf1c34a5a3ba58190a1c7102e42bb141a9c60c8), uint256(0x0b9184dfbc0779573934dee6b8285e9d255295601ce1478e2caec99e780c958f));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x07615e80769ac0e5a937841d42e38282afb815a9aa4534e31f49676723fc2b9c), uint256(0x05557160125ce63ab49f47fda2799009b193aa6fcc3625b990a559064da88806));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x1f6865e1b7e773bc98db6df85e1432c009fd9ccfe84448c6b487293df529cfb3), uint256(0x08359e1891d2972c765a0f9092c5f36d7bf42f37f4e20b1e0a0ada4dd55dd0c4));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2993dfb8674eb3d3eff8994d9c7ea9bccb50a4618fa7e8bc90434de9a27077d8), uint256(0x2e17327ba7032f2c1c7e41388ca46e7beb4c55eaa97aa7a14df5f0f87209d3f6));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x048c2cf05cb30158a86c18148966ac12188b880152d019fe4824c4a821cf0925), uint256(0x23a0be112c9ba9b5e6dcfe479a94b9785599e8d6201313f2a280a22077a72d03));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x02c01bcd994d33db18b208dc69828ac8eb3188a91310573364e2588f8b354538), uint256(0x064727aee80f0d8ddc261448d0131ff1a34450371fb09ad03b33670680cc077d));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x07b0d33320ca8f16a18cfdd739d322950968361936d142144f3299721a96e830), uint256(0x236a989794fb2efccbf11db86f34fc7a26fd1fc2b46948d0af558529c9a0d451));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x1b838e97c0a70bad99e7132ecfb19715d393d376c398e7e77b142f24477f7cf9), uint256(0x19cb0d99b5a0ff5d676447b2973beec87a7cd76ea2bee2002a55e265aee21a86));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x07fa404387b85849ef03a423cebccedb8fbb88653207cef688f83956d2886ed1), uint256(0x297f63039781a856821e30988a2d96ef02e1429b1c20cdb39dc56779797ba4b3));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x26e73c44621d53d7a435de40a9ae4d941d54c59253bde1ff6de5ff6040f5103c), uint256(0x230066aba0308e74afd24d8aba5eae435ddc72c5a9a29d949059998be7d7cd3d));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x010d4429fc6011a10550c2de21353646b38154aa906b7709016003475066fd20), uint256(0x11704d266ad025cc19f0a273668f292d7579c388456e5e38a6c45da5b51b43e1));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x2749b115240be14bdcc0d2aa932c53e7d342b4af74f616f4cf933ce3c35fd76f), uint256(0x088e7b03630bfbce3072296878d5c00237a830a44c018111402afa09d2b136b9));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x25698710f98d70b1b347a9f6094dee6aff50c7454238a6c23120a9ac135ff830), uint256(0x1fc00bebdbe4343be67c1a298a70d3a080c62d0675b27ba44e1e8bd209560bfc));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0e67dffa7e32d4176b2d23366cfe1069800d7059a5a8f24f9734fa845e08e559), uint256(0x230c4ced0ec1c011ef5a111d14df1a53122ca125a0fd086569b029ee2760ec9f));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x17e02bb630423125327bc11526306fbb6f31f542dc9a1d27a3f3ff7aeb9f2a2c), uint256(0x08c577313ff4159af9ca3c8d4b4d5732598338a4489903fdd7bf2b443773843a));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x1d48e3365951e447a5b70377762b0705b4fa8d12011477062688d007346b3cc1), uint256(0x171ec8f251cd36441583fcc28cb5172804042807ab9daf74afd4dc9040145fcf));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x26038d8a4ab908703c3f31371de6117f25b35be9ca1597ec09cd69c95d388cec), uint256(0x066d558abfbc4c6e851bf66c6109ca80bbffb1c4859cdb53c6bbeabf3b581fc0));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x22def939dfe9526310694d65e53b6250d31181acb876918829a3e3b63067534a), uint256(0x1c5b7459c70ea1efa8cfe60d4fe12b26b285d26f5f950a0e0490c722555e7f03));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x0443b14863a37f36ffb2dff2551d14a2486b92361e6bcccad90d0ab388b156c5), uint256(0x30626190a9f5d0323a8c9e2de9b651bef69d3e2e2d89f117d2b037ebf7c10b9e));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2a5fd6f7a824cde9ec56832f3a906377a05fe873d29bd28f3a766c8c8b63497f), uint256(0x1ebb56618241cf482101e68a73710cd7da2d2f374298d2b75acd1c23a9ffde9c));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x18811fcf5670fc844c6933d66c454d9dc150cc78d4a993f406c00f9284f4f4b3), uint256(0x25cbaf24e7695b7c65e3c7c9db22abbdb76287070e4d95f549f7081934d4a07a));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x00cb9179e636071250d7af56954f56bd25ad9439e47e62fd0d028b1e49134bc3), uint256(0x0b2d74e66ec51eaa9235104fa1446a6b4894dd96bfb35d256b360225fa8c0847));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2098a18933861e474e7903baf48a3abf8ea7e1a31c4f88307b29d9adf60f2b36), uint256(0x07b1c894ed9c77ac2d9ff3c91d126d724c52b1708051ced03d5f2a78323c412b));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x087dd02ad2a32fa96f5afbe50561756be8f7232aaec2a61368222913fce0ae62), uint256(0x2f6282303115393debcdb22c22d52ae3c9fa3a22bef2c21d9a5b04cffe01b2d9));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1e06174abbb5b32ac03d164ac5599ab2619b1fcad51d80d461849c61f9dccd83), uint256(0x15072a1950fd4f6fbf33bed691b8f1de5a0e37567b70a3e4493e7ae7963bf650));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x13ea4e63b099326338c0f1a7948e6e8f34653891fd8cf66e8c0a694d2eeecc24), uint256(0x1b88590bec2df4c323016a7fd1156928038e32cefda977bd8dffb38b376343c5));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x138b27a12e131f87fa5e3cfef06d9b473a7a3bc83bde3d4b41de1a3f85e873e3), uint256(0x14997506cd00c58ea764d44331d74a20584e93566bcc963bf8c3893c984ac2af));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x246870e843b7cb7515bc5b83e2318c4910882c14a593ad6f34607d728b6ae3e2), uint256(0x17c01eb4923400fe086829a9ac0255a1fa21f701416154944749d49b38e2e04b));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x1673e465a5c5c6fb5c2bc736dcf15335f6691466079a3fbb9439a05d10e3d669), uint256(0x1f28571e4585535d078719c534d16e2652d83e1ecc8b9fd87eb5b4629382e6ba));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x0b86a31e479744d6a8dee0d1783e8b9dc7ffc91c5b2854794c1f6884e5dc4716), uint256(0x0b6a1c99c2f5e78ee499de30d345e284b822284a711b2016f5c2b123c7c2c5a6));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x0e3eabb26767e8960d4e928827020dcf65ce8dc8df46ca4810ee557f202deed2), uint256(0x1e075b4e80bb64af7d4f84462bf39e58774289855b1c3cbad351b66b51bf8f60));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x2e72e2456506806c359a03271e34a7c703247c35892c2daed96eca6aa64abbd0), uint256(0x065f04a78afaf3df4abb1602aca9eafdee71057a55a75cd3aa1b7b989578739e));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x28ca6b69de819c347dc505c740ebcf619dbd997bc13485768e736306494b055f), uint256(0x07950aa302362abf7f022828d86a6732f3f699713f92303280a1152f73b61ddc));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x11a129157726eb963f95b09598ed7112eae109ddabdd300fe0c04b1496b09429), uint256(0x2a2c1d6341514ba7aecc8fa93e48fef0a8dd3def221a690c3962beb092ef3981));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2d060d26ec004cc35313a5aacd94aea69c0cb02a7d603a04de105de4550d888d), uint256(0x2e47926fbffd9e3cd6d7e2ba95a8604982823e1c1d9b4d97f1007f1aaf9acb66));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x2c368d2f42ca83b95c88fa74e229beef859ac0d6c6fe7c35ccd100c721296726), uint256(0x19399162a5c4895f29e77b7c3e1460b7c1eecf52ec52f4a2797fac489f3aaa4b));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x19171fee1bbb162dcf55458cb9aaf5f4e3849ec11ac2e1d71e13e9146f870f25), uint256(0x300b7d28398219899cace9164179e6abbb23c65dbe525eef44add4e94ff05e32));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x123635e5c65c8f1f4ec203c9d45fdd1e56ce0e0481e1605170499a2bfb53ccce), uint256(0x1251142c9cc8923240e209594644bb41d9b8049acb3e5e4ea3df7d2d947ab736));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x304d3d6847560cc1c7036848014746890222b0f0267a3983a05393aa3a460cd1), uint256(0x121a0438b79a875feea17f2d5b73074bd871f7643c5d6a8763f12a36a521d7a3));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x12bccb28edb18433e4a791a754b48ecc0716a5e4d513ab84ce624dd8222e0f58), uint256(0x1e6cd80cc22d074e9b7afc3d97f83bf2ee0cd0dcb1c411e0215b7dfa068b62c8));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x183c6fc68db355609c2812b0ec49c0d3778fed0886bb2b0bfd4f9471f8f521b8), uint256(0x210e0191283ca0120c55d009a970d1e1d0062222a06963246e35081462cdda3b));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x25f2adf5e90eb66757c978e2e0538eb78da1bc00c009fc95a986f5727831afab), uint256(0x2b05488e26970145ec598d536fc16b3cc298dee86d04068fecc56a668ef178ab));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x19e8df89ffc9aaa7d6de60a04f37a1d85aa2087ddcec911cd5cded391716eb57), uint256(0x060e40024cc412dc63be9497de95c60ec604736a287a289e8f6281bae1cd8e61));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0b37107529681528bfbe42947d606eacb57214fb480a8e28cd702b6903abacca), uint256(0x1dbf4a98804a5070cd9c27709dee7d888da5b61305b67bc0c0967f382cfc235c));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x154681709af7fa9df395f9be0d9f5ff8669090d8735e33c560ce2a1f60a6c82e), uint256(0x2f1c9df745daf9a20ea83e68c0e2f09d9912d27867e179d6685c52bd01979507));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x244e6962e654e702c2445072970544551203271354ef281474c5d62af6c5ac07), uint256(0x04c106f4876e8119805a01f3f637b6d33998b9171fe0131b4e3def09b187fb62));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x1617e6d7e4c737a1d2dea355c0246393ce09b5a215c4335d779449b25c006e55), uint256(0x25eb318286219bdb422a49d0e4a5121d52d552f76484087a6b0894940c9efb73));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x0e091791dfa4ce347cb96a281f592252943e5eb0856b2e19f6cfb2e58afea554), uint256(0x08b2264860d8558a689fd0e131ff450c1420122e35545165934edfbca6279ea7));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x20f4217585d3e16461dc058be3d8628590d02cb60d54aafa1fb53c48c3b17da7), uint256(0x05a00dfe2d8dc06d7c3f818a0fa27ee3b6e237f491101e136978bda532312160));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x2b4a614f7c9b2d951805241e07fd0d8342eac66416cb87846fe05757bf696047), uint256(0x0e41be2bb6325686c937c253b4945e2256bca83ee674022a9276904a2ec82b57));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2342c8924a6475be082e38313c05174fc85a217b55a3cf867e3d17eee685eb4f), uint256(0x1b1868bb486405861427fb4f73508e09670a13c2dee4caaa650698fc1307500b));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x02ad391617daf3f8e67d865b3e26a8b95a6a4f3bef44b9ad0759b01026953a31), uint256(0x1095ef068cf974df26271ee784343c97e6fa9b9dbd65253d91a6d853d6147b82));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1f2dc47032e221edba4a0bd823d5ecb006a09b16ce8aa7c3b9f7f1f5691a219a), uint256(0x2999caa532cfae0edbef7bf80a7730660848782f83939454c42065eae58d51d1));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0cbe3698bd48cb79420017f33655d23b70b1793b9d456df45bfe631112874da8), uint256(0x2f2ddb8f98ecc0f53c9012a9fb82074e961640ace1eb7cc7003213858344694f));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0931b87b1acafeae995aee651be8c933cb39eaf836cf40400cdeb2e71ebf16bd), uint256(0x2c37c119ee01c17456b54c25d1076ed59ac5ea9708091a6da913660d2aeb821f));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x2c7da6cfa5e83f2291d9b515384accf1735b550e435428648b4a0ac99dc8e224), uint256(0x2e753a8e783ab7bdd74c3b650910d764636821a6b4ffb343987179a6442e0ff6));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1605f928b040025d9f524d7521925ec80472f8416f630e7f5025a46af77ab78d), uint256(0x0f5ca8e3d7607a7e0da1674a8426a44c579feee0e3c81b83a1ff8fafad9aa59d));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x12fff5409bb919e2f3b5c2eacf9f9e4b3ad8402f7c31d5c631f2159f0890a6f2), uint256(0x0fceec2f51a5fc49ae4f3ff8af0222a6e17be8d3f1554720af640a7e54ae21d9));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x2413b273c3198a07d114399904f83b26b0d3bb1cd3ee18867d244a1d186b7d71), uint256(0x18e37ab460fb63ad4192db7fc0622f956c1bd9a2ff4b56a61359d5cf603474c1));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2071def2c6fe90e14ef7584f9381cd3284e0f6dd966b387eac36a9dc5a510941), uint256(0x27c226acf24747bf1ede545d3b8c5683cc067d16be21665bf432a8d3e6eda9b2));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2b898df1dd5e805e8a1611411a2e9b09408ab498fcd96d9d8704848af9cf9853), uint256(0x20f5d7a5191176a6ac69bfbda3f83b0fdb5e15cfdb61352faa9246aefab6d6f8));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2abd8812fb9c6e93c5f9def1dedc855f4c4a9de04a5601eaa83b9b272725189d), uint256(0x1437badd3b47dd49341f8b1490e0ae0067873873577d91344dc507eb37cb2599));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x15c5bff1e3ff0b711b4007d82e3e4842edd0518d7e1f2d6e09831f1a0a3b7c44), uint256(0x2c223acea73786d7234f59ea2579e3329432aa096b5b1c894b58cd4e57447888));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x2bf399a8bdd093713c33c6d18547a1b6a316f11274baae7790635e7e255fc178), uint256(0x1ef61820cf7bbd953068229617b19203e49b17de8649d0f5299c04043268c4ca));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x15758ced4e9b4a56d7f6dc5afda9bc38ada3a3fa2f7397e126754d21155f4392), uint256(0x2fb8fc9ae462f4a0943b380d4e80b9bfcdbd23a4ddccbbb410d380ac3eb40a70));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x0b9e746b4bc5d561f48d1f05edf2904a57db29409e68d204a5839215b406b396), uint256(0x1132f805894fa361664d2fcdea8a9a2d758333fd48d9fd6838ad86a1e774f074));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1d7801e8bb2cb878d61eb1249172c89c37623176c072e84476ccf6f99a08abdc), uint256(0x06e5086e8e0d48dee6a084944664f27a7cdbeb2149d207f90e3976b767bf39bc));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x2830507de6f56ca47ee9f7aaa8033cc6f177b89d397fddfa544ed4a755c71a19), uint256(0x295ff07daede7a5e6b112c85c64534ef2b40bd2364bf18367fcf828aeb0ab3ef));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x1c07986c16bcf0f1056eda5022f7456ff46fca47e1a38f22c784d787f86e5284), uint256(0x1a30f7ea889e262113622804a27873feffa4b594bec49b341b0d4771d359b33b));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x18edadb62505b7c8fc8931f48f48cf3eb95d10e793a9b6c43f188deea08e6a90), uint256(0x11608ab4647e27483fcdb098e933d53c0096baa25b36c4829fe26f077acc22f6));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x23a4f728e4cd3bf79abfce91d6ecb4b21989468743414346f7c6fab6e5af6d76), uint256(0x09c363a12242168cc3579395172d6d0b43779a242e5f0777fed3aef25102a502));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x0bb3c25e4fff3357aa5e40b0f629ae4e82f1b1ff7a318ecd61447ba91c120404), uint256(0x05aab99a0ee09ee11c7b7ed8e157d04ec293bdefe98b081b01f1a805e74e0fa2));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x0666f297a215ff6c282a5b3b68e5c6e2ae442e0001d5d8a1aa07197e5888157f), uint256(0x04a8e243dc9897fdd3464c3b6510255b5c7cf3ea818dcb49f1bd82585aa71a9d));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x2118c8db9ddea268ab73f702404c010e71ab616d6abea31bd1bcdefcb9247a74), uint256(0x0429a1b25b72ea8864feaef19b718de72bd3b5e6a283546895a3bcfb9c305119));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x19b24b3d606c0b8996e060414a3716e8564311677a513cf722af80c90cc2f803), uint256(0x23965e13ef5a0927144036a968e9f073c3866b0171004023a0e013932e00ea50));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x1d973527ec59abc151b4e95ad423ba2246bf66cd8f49fd69bd9d9f0f0aba8ed5), uint256(0x2e6603133ce18dccd9a1f43a6fde8a3626717485f2294cfdad0b2e5eb74e5f27));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x16ce1d70d32d9054264e6afedf8ba7de0ffc1ea461112a4afd8adc162f959207), uint256(0x23bcebdf7e66b469c252d8d45ec63f172d558593710af7e8d53d64c5c2ad0471));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x1cc4d2222bdbfc0b5fa383ca4b2138455b7269f1e51189b44f854e0bfadfce48), uint256(0x1138376cdbf1cf6bc03e7bc24d6f22ed89bf611ab054bcf1d420ceb6eec8051d));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x086ebcd99aaafd28ab1c7c035a0b9c00cdf7ca63842b4f2d6294ba4c8c16f504), uint256(0x1bab34ada38cba44605631006f7549094d8cd1a58d21f4388bba31ff13551a83));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x1c7200c99de8fc5129b763671c49f476ccea5c3bd3cd2a28fcc798d0d48ada6f), uint256(0x046ceb201e65e1f98e90667cfec084ce96edcc335154884082b853582c5de6ee));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x2f8151abc39468494d9a4a0714dde7a6429cc7c0d2ca0b28b6de7693f2041a98), uint256(0x12c920ff5f7459ccec01081fd2c3b94e63e31d05e012f266fa574ec81e844dbf));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x214e9f8e0e08d902ae5e50b3e88f93b2803fa87b34f972249ff2e2615f70ff94), uint256(0x0351b01d5ea6390a7594169384cac7d3729f7331cf158c143326f1d8b98abb61));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0d249bf31186425b6007a8f4a9929cbe0e63aeb31b11a5825d674d34ecd2ec98), uint256(0x09565e4bd34a09505c6655d4e970390e641a1268a8fcc23d8ced5019c5ccccd2));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x09a36083b9f65b4578b6ad385cd0d72a72a304e5fd160a77513156a68bf1010a), uint256(0x09e6d1a7881d38f7297d8ca48ce8c9cecc49b2e883ea4e57d797675cb0f1ca23));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x2938062029809e179eaa101ebede7763fc444601a28be8d8dce3c1d955bc1821), uint256(0x2e7d9a9b3474158781eade329e2451bfef3cdedd0f911a32a1cd0b4a43391d40));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x173ffb2b5ef542fe7067eec2d3264af8affbddd62377b6064b6931e8fa19ddf5), uint256(0x2f5c41b9d68e8ac4a5fcdc9034f95f0d926b49014e8734ae9d48ef45ec6d6a1c));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x1bc7cdfad17b72eabf86b25ed1d231f8f1c012479cf4d5f8f582f9367452c130), uint256(0x19d7d045854a5a0e0f153a96161a9ec028090b60e8188340c37f730cdad37009));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x28ec4421d98cb33e41a20812376528cf4a75a9ae25e39eae8b9961f1da455518), uint256(0x1821ab5d4798d6d98a5fb95c8eae1b607e9ab2d93b0854304d98d1914e3f34e8));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x09aadabf02c4eb06eee90020a748fb73d9f27f8b24f7973e92797bf090a6f72a), uint256(0x08c1c34ccc5e11519d6def0ea84a6392c49ea05e2a0ce129e40d5b0dab0cfa9f));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x1df3cd38c1be4e01ca99a75564365bbb3378bb8608335a448fad8ad6e7d3879d), uint256(0x09c3f5e29094d0ecc49f3b3e651e638d4b89df5088294de89b86402b583b8f8f));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x1e56ab4150d4cae7bb77113a3242805bf3d46a2009b3faae10c7aecc4b622a08), uint256(0x05325f5dbe4e8be892cb9355d949c7b9b2ad25cd652c9cb34888eac88d0df093));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x0b8044f1312dab874ca134a3c692ee469a2140e0da1b87f66e4a893342c51a54), uint256(0x2e1ea61cf6a4c0fc54238762f5dadab3961fe06db0b4d222c90c24b18a3a86d4));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x1cd6fe37ecc19ffccd2ad640e9a1a3baee969b590aa0f912846e40338a90228c), uint256(0x04c1ca7e8506f2ca785a15ff16b94a9eee72016765531a0ccbd73d0b70682d3b));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x1c3c6f8b885b828405a4a96dfdf7666a25e99e1de7ee8ed30e0b263459003076), uint256(0x2b3a0380078ecbb5a66044301c60e30481bfa5f033666f795331815e7a6dca49));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1818568bf4f3a5db92acf27bfb55840cd93e4b0605c0a90af1af21a0f77553b3), uint256(0x20158be07b271e5e0b6c1d88a7ff4ec8d6f610fed23249a3baddf06e5b3f1143));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x2f02573f760f233468858893e173dccf9c5b564d99faa79c93b8c49600bc789c), uint256(0x228d72118822636f0c00977f9a3967e551538152ac739073d1decc1ac6686123));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x0d131495b1dd49944bdc5dba0028948cabc0487892e72a6965cd9d2093058a63), uint256(0x04faf676ee09b52b59340ad9f94bbc9909623a3ce15d53944b4fc9b0a4cb99cf));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x11e768112337b803daae69ca1ad0a6c3b01a81cf33c886465e2f334b2fb482e7), uint256(0x24505cb8e66aa0ca2f10a97e3647467fde925edec80bb34aec30150612643185));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x01d58b49382f220c3f68402a5e3b6e192e7ff29e73b0e9a1d538e01fb415bb05), uint256(0x00240c398fd35defc58431f7bae2ec26c8a7398626bd928b1d8fdc2b6af7403d));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x1dcc93537a872eb256fb79a74ce8fbe2efd6467eb89028d9e77ef54b79f08a75), uint256(0x128f5d6612b1098ea3905642c46b55e45d20c8d5d5bc7af4d0be7c1ea8bd78e7));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x21524576fc8b2e2d9b522a9775b9fda7847073b1d38850145f25d50c3640e479), uint256(0x2b9fff4feb077fd4888309ca0efc2d5ff4105e6892b05d3d048fc780a2579253));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x279299df2b3b3747ee6f7ae5382caf4b5cb3a81e8f48919be48c471608e307d4), uint256(0x2757c1dabc1b3a3bf3ab86ccc5ca209480a226233fd097aaff4b8b949446f7ca));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x16b50939668a33acba09c0de42585849ccca4fefe3553dfd70ec35ef22b3c5c8), uint256(0x06e2ae22b78cf2d9525c559c8cbf1bf7dbb23d94be3d594cec25c19daa140b3a));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x0d6af2291f238be0734e08a31e5d545c6f70da32f42871f15d8a2235005df13f), uint256(0x188fbfd6b36da0d98c75ee65d9c6f629f819f31cb5e28197adc6e7988a64b6e7));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x1ad0f609f1c73caeb00498caec99a3ef7d9682f6ae15d8b1ae09600704e91e55), uint256(0x1be6cc495ea6ce121d9f136cf64f81810936689de888c36a7297a37e3e59b44d));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x15a4520fe295031713e00dfa83ab4d6f2ce898160c2807b911a15fb86754d3d4), uint256(0x236ae8b148528ae8eccfeed1cad5c44c7344bd0813076ca85b002cdbce750dd2));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x00f52968a114082b4c9fc3d76b3df21caf1b1ccead263d85d0220b05eed10e10), uint256(0x0db3e92e720e85807f51da62158d1eab97570af9112d8d5ad9d5f3ddd8aac256));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x2455a0f179714a187f50bf1ee09aca3ecdb93f47471bef6594d77d36075bf9c9), uint256(0x2410d6b5563464b8e59e96375c91a6512b1d292c5f2f5186bd58fb774c85182a));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x0953bb83911d81f751062eb0597e37b51267469f142d15049c14804fe1f011df), uint256(0x14a976a2f8d16c7129eb72511f1d9c351a6da65457d2c09b9658b91a9c887a4b));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x04d440b9f203fb4dbd73fce1ca22c55bf3716bbff361dea3eed74d6903df11e6), uint256(0x2046d9bc90efc3d777de0f8530902dec557bdf540ff471bd21f2662e49aa0f71));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x098a51dd0e5ea288bed9f5f5284db509c204c14d3c7fef668c113d2d4df62fe8), uint256(0x11ed9878fd01d5074d20176d220d904529f1861d72d6475e9cf6c707c48f1628));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x23bca76da7888831548d6f733d2dc3f1cbd1be660e9af503d693535f232422dc), uint256(0x2bf7417a3f7a07f3ca617159ca4dce0346f8353c905834d615030247db875c46));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x00fab3165bfdad09b181c15673bb4c1530fe8638709537c04919aa40d92ae323), uint256(0x28868b2ffd73ce705063fee7a6f2ae3c09a6fa71164260925f6c7b22f7f17cd1));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x08dafaca727eb1bfd56318f5fb5f533dd97b4db847286f80ca95de95d364ae5b), uint256(0x03853ef15f7d615d495fbfbdb774ab1d83c130caf5b7dbac0b9dbe97c5fa572f));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x1dec355a12490b9421ebf18b08487acbbf547ed3530b036430c5ed1b83fb7204), uint256(0x17742c76f9df817fed436296faf5254c1ad44acfb39609f9eae54c72ed6e2cee));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x2e0160c4323edc7766e4236d60f5ae7b5e3275910591b60a82d55d331343c30e), uint256(0x0fa8f157d86d371b836b30ffd63402c334beb71a0081fdc7d9b31d70de36a442));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x09625d7d5bfaa2463fdd609029ef89087ea5693a3db92fe379a66e25b25d835d), uint256(0x0c5beee1ae642a1509fc62fbaf78377ffeb13c004044a9d418c62a2999a2d0bd));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x108e70f92afe8e1f30923ec7bc156e6bc41aca58a7409ac01e5b5f514e09283a), uint256(0x0919c76fe6425a7f393ebc39d85563a9eceb92942c692dd0db91b589bdb16751));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x1d58b9f6489baaaf06cd68d4f37328e16d128cb7af673b875e0fb2753740e63f), uint256(0x0d71fc4fda4f9c7efbe0c2ab7b4f4d27ac17f6842cdc9564532b0f4b12b9730c));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x0949e45a46e3634c6ea68485a93229f935ff29315c16ab682c9511193955a208), uint256(0x1a9132dbe5173ca8f34dfbec713db90e966e973d47b6a951f72015186202e5f1));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x19c801fdf02f61a8946a53880c2c77a37ab0c050c01ee1c43475085e1f7c0294), uint256(0x1983dbc4222ffb2a39585a108be3699966eab5875b396af6ecb5834143ee452c));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1f06ea70b78b882226e4239e63df2a87c16ab8ff94bbcd784e63ea49bd524ed8), uint256(0x2189c02f211b105b70df49879b73e7784bcb1c5113946b151ac456f41811fdbe));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x130d3e464ee78a1bd450f4e88ef74b324665b9c0c706ab9cb9a0435d4538b5ad), uint256(0x2b40baf773311036950784270f1aa49cc0acee3f44c18050ee9ce793ad3a5949));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x28a681574d163675e413fa8621e09300b4a94b1215f135a373b736f0bc759cf4), uint256(0x2f8aef9e419d5175a6312a3fb32d3a8097d6d3e777a3a4154ef50b21495d5f20));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x15801dce96dbf6c693dbba342012651fbdedc1adfa151defe0904e6a30665457), uint256(0x2586ed205305121549ef980c66578d2305b4caf4f35e73d79470201d86090f4a));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x09d638ceb067de52c0a8397e04100e1bb6194cd0222bd539500a6f94ca35aa69), uint256(0x0d86640ff3f752aff0d9ddeeb394f4d70063a0e93d8f8cd72573dd46d639c3d4));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x1faceed647b7d75b833f9ff2d2cac120a176123608a30efa9939e63740f4b65e), uint256(0x0178201b5e50cc878beebbe2e308d274d37fc217608d6505f5487018feab41c7));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x02dbe0bf5e46cb770905c9f48456ba1af97ee419115231c93f8e42b15fe9bd16), uint256(0x0b0b08d49314e8a6ce2920f1ca0af1ddcde209e6ff484e1bd4c4647c2991c35c));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x1b10bdecd0228c5b9f59498ef34f91b79de0bf22572e796e967a79664bc302d5), uint256(0x1efc50ac3c18055067670ca4c59e1b7991ee372072e999eeea50669c89a5f32c));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x207b1bf519e52753515569377df84717774afec47f5b2c1112011c49e1a7eecd), uint256(0x26fa88a1fb06390ad8ab3f2d00e7d627be1ca4538cf36638980919492029cbd6));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x25d6f8a3bcac249241c8b4f7202d55c40d3789c929fedc3832c6062ba812bc89), uint256(0x2b49f316223c9c75bfb1193f40598a03a2178d6c4f9cf0389170ac62ab085adc));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x1b38f445b8a354d15ce3096a28fd53c4dd8aec136afd34479b368eac8743a8f2), uint256(0x18346fc58e14692a787b2990586af88a774f9c8ea664d5519d44f7686682a941));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x049a6f2b8ccda76e794462ff2dd211724ee3d680bad07a70832db25103e7dc46), uint256(0x2bfd094ca5a4d648a51083963645e4d6bf9745b07aea64d62315f4d770b038cb));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x1c504c8007ae9e13fdff4587d3626f5a55068ff1e9fccaed9081173c1d16163e), uint256(0x229cf44a56cbb68ebb8ba5ef173f697af61b06ab5fb171a8d4ea6e40389cfd5d));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x2d67c6ef3865e978379e56e4f23cda26b95efcec9b5c12d9e9009c5514799563), uint256(0x2fbef785adbd38d4a1599197fcf32c405d3a1b1872207a4fd38747e947989d7d));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x17610f5f59023dbe877dbd575ec5fc383b2442ffb01bcbcafc8552b2e025c8d0), uint256(0x29796a111c2313183176d1d3ac0fbc4f80fd1103a8078424872e3ccd38a1e291));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x1cb01268a86ffdeffddfa8adbf780c02fc65f1faae16cef2ade464805ae9dbed), uint256(0x255a46094a36c367128e3b29e17012b7229c9562cf32f888e9e6a34786f78d1f));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0fd37a09be8624ed607ec4ab960ca7f758427d951bad347b07210d6802a247f0), uint256(0x1f14b6a7d95618758b492aaac4382cbfd963d5c53c2a1b4595a8d33c03972a5a));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x1264912fb3a3f25813a0354691061d0b2b2d1f260431820ee322e1a0187b0765), uint256(0x13e7b00b4062a2d0050a3916203fe79c5351195656e5253343ad9e96fba6aaa4));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x1cbcf42d188de8639c73ac95a8ff15fa66083c9605da64b5226e23db5434f8ad), uint256(0x1f0cf91fbf5949a49aff5f3dc3f6f99b1e8eb4b1a849342a5c8cc252698fa27f));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x08342a450d41a98c4bbc14d8ff7166d6fc7a9a633a27367cd9aa78fa5f72d1d6), uint256(0x0e59df7a4a10bb9690fc6d09d2d2d2542b1964639c90f0819f0d061d4b3af90f));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x2b8a2f4bab6ba4533a84075ea4a959540d0730b2b18871eca38b0773b0b01e37), uint256(0x064cd05f1349ee2ed01830d532279721e377689280a1522d3a8d2b7659430406));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x0ecd03412b3068293b92b4449fd24263f723d5e2234d516205846091f6d00d13), uint256(0x0475965d9578719db2f9bffe0d758e0477a5d488d1b73a9606b366f7c45a6b69));
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
            Proof memory proof, uint[160] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](160);
        
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
