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
        vk.alpha = Pairing.G1Point(uint256(0x2ccfa209e2cd7d70cf0db97d3da933eeaf6a31622b3dfa9634f0ec258b691299), uint256(0x041d16188d2fa2bbaf42d57f0210ec51d60dc4b9a2e34b0f90505592827b408e));
        vk.beta = Pairing.G2Point([uint256(0x1c72ff382ce58c46ab05d80621f5c6d70be8e44907e9782d0596938415d0d0f4), uint256(0x1a45588920b222ebc85aa308b40ac69f7afca9f8983d45687cf54f6c9b080ee8)], [uint256(0x0b0ebaa6eb2369b9ada506ec1c6ca2487ff2ba2e3104645b119308c289c94d3b), uint256(0x1cf34de684f8bd136529dc908d7849c85109d8a447fe556b5b4966e49a7ce428)]);
        vk.gamma = Pairing.G2Point([uint256(0x2ffc8ed7653584c7a6f2fec1c8a58f6b920cc92aff432147262e7821ca244156), uint256(0x1e3544a3260c1d95972846a1ca617c62f06dc5925c2119463887a78b5664b013)], [uint256(0x180118824f3218e51352c558e0cbb7ac2bbd40325aa080300b56ff1fe8a712f4), uint256(0x300eb128280d7fe58047cee2fb77201c20b670be0b0342f19a0f34facec6cad8)]);
        vk.delta = Pairing.G2Point([uint256(0x0de3c0e8805d18cf17682cf5be6738989149cf5eb1b03fa1ce3bf66247a25798), uint256(0x106124a71210c0e4c9c04e64b93b40551afa350c16ea95496954cc4b37f02506)], [uint256(0x0565b25f9bc8aef5ffb6a6db33db56847e38a0c67c46890869f4a0e94f101d7e), uint256(0x16c5f0c8cea4155577758e00b056d87d0b0458eb5dcad988fbda09f54a425fcb)]);
        vk.gamma_abc = new Pairing.G1Point[](425);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0ddd43921038e76d55a3b4b183394b7974473ce36914dba3d67ecb7f035bfc79), uint256(0x29135149d0b082bff3fea8b38f6863fe8394976366505e74a6fe7dc077eb9180));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2053a303057d6a01db06cfa6bec5f218042f873ef60f9e0921cc3b39f1983c6b), uint256(0x01b417195f623c1ff4a4c29dd7a6fe40f7e554a1d803214e4fe63dd1f02349e7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1d35026125cf4e29d15f7ac034046c270d647fc782bec85fccd9bfea1288041e), uint256(0x010caa3d8c10a4f07069d6200c690e99b18cead4de50d165698289c4001cf688));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x060c7a7981b7d7c243564989d7e2bda6657b6237e9e8cdf10c195efd78f37b28), uint256(0x1bffaf057799deb65d31a47a4e9c39f70ef2a45d249038047bc082e86a416bef));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x20238dd7c32a5cf8714d2cb38ec5409c38c2cf41fcd5d059f050bb39a5b0b2a4), uint256(0x2c4377878792c434e1833e1fcf83d090313e8c1fc946dfa9ff6fe0d78c9e6e07));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x057f593790cbcc82e2c513074da5dcf300fdd8ec054c527134b45abd386b8774), uint256(0x020317db0068d70ab4c668d27d32784082dc660a15688192c5151c24c205c101));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1d01dc995ae18b0e788c50f06f7f5af4db4b6912ffab7e2cee9ad6807a0e7ffd), uint256(0x165aabd2c2e2976e55cffb38e469a8cb964ec5fb4566a5cc3a02c9606454b20e));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x13a95fd68d29092fba665402718f3adb37a2ad1baa0dcb24900680d9e54503a2), uint256(0x00a1eae46383bb029d70c3df71ced625e045060320fdaf306f721ec5bd06456b));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x2480ca8eb7a73a29af5e5adbc354b39f3b80f3cd284541860cefac38f58582de), uint256(0x1d5fb6dea2c9821965f5a2e7fb0325d7d39dace6df2ba06ca1ab0ad7ff14872a));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x131eacfc4faa80de6f70bf9e27912a469e4bbc312bb43368b8de2e23d3513ce0), uint256(0x0603cd90b35f4043cd106c03f32e7cce4f55dbc7e7026d71198e84142c732a5e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x07c2838ee7161963b0cf409a8023cc119c27843191a03f922ce8b1144e0eee69), uint256(0x297bfd2bf5baad7d504a7223ab2a9fec59c7f57b426b1e199f6fb67e01cee09d));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2533ac6cddefdb149be52cdd0d07fa4158ecf391ca2323650b9db114d791340a), uint256(0x2f29e29f672f349ea843573c98b76d0a157be0c7ed3ca8977cf2ef04c6e836f9));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x1a568a6199c3f7786fea99d4f4a062668ae238b54358fcaae21e6763c571e9d4), uint256(0x0cf63a67deefb6bb521622709e11c0194eb9da39af9ebe8836476a06d262538f));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x22941d1ce320bd1bf3387a929649789264839ad32e15d9df59ad42936b178ca0), uint256(0x0d8a75d9269f77997f1cf8bbabcc58817de1873f094b028254b96ba8890be88b));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x1c33091841fbf0b0c6f52faefb8d392cf826b72ea203c2c3df863a40c3bd653f), uint256(0x12e4d5d69d3e4b12d309377651a7c18a8941013a50ac18f0a44a5bc4422a07e8));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x0f79aeecfb05c028d603b3c413d54f38537a7c5bc877d09de8913f2f7e764819), uint256(0x0420c9d2cbfd9dd4e826a5917bd013cc7245b0f013cfc7163dc65c1a2a243bb9));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x0186635e7f2cca4fcb0b5a7dce6f29b5c9ed8043636a86b5a4426f339880f75a), uint256(0x105cf1c9d9d606b2c7648b289c0149e0922ce03707b5328e12ca92ceda05c8ca));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x03d08bfb32415b881d9422f0d41bd0cc9601c0c954553b9cb0548858a3a90e1e), uint256(0x254aafff45ec42ab52aab66672a77ceb97d5ddd783643e7ddf82a0dbc5bc7711));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x0e7b29e0c5913040abb43b0f54f0962d27ddabb88fa312d9acd74ac3d940327b), uint256(0x2c986423b3f5d0f2a4e3a6cc0ccced52f58342e90bd04f783af237aeac0ea1fa));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x0b877b21a00a1f2b6e56c0a58abc2798c09dc49b55932a8e8d6cfa54feccd75a), uint256(0x02d9517589333af09d97d2fb58576e6414b55140d48c0449d26964cb03e5a968));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x19e89ad0f1e4d0aec5819cc1f1938d3d4caa600ee82939fe3268a204795a256b), uint256(0x1e23fe23f8e1d8459d600288b82b8d7198e735caf86d40ce29d2e1c74302b0c9));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x0aec1342dbb283d313f105fc24fe0bf68f520f521af6fc0a164cf4b78621b2b4), uint256(0x1a6f3dce691b7260515bf5104a55c45813afdaa655d3a6ed15db1707f32a5be1));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x2c5506e47136ac346afc1c5619ab4d58d28c29cf3efc4d31e91cf1962046fae6), uint256(0x0d0751b66559d255bde32a254ae102efec8c96711e6acbb4361d44a25b382086));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x190646d9c755e75034f40d2b603c20d81990e41da310f96e18799df9ea20c48a), uint256(0x0813dcc800ae5abd68252bf400f9b2739625c224c2a20aa2e4ba2439104ea72a));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x184697601a107c00e51a292dce36171a56d9df6aaccdfd5445ee72f5c7a36273), uint256(0x160df416ddfc05324a75c0555b3108c06ab45ccd386b34d6f9e2f3d53ff0fc05));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x2e485ad21f50ab0022b58eaf92acc3844ea33ee862042cdf7c837e80e721f078), uint256(0x2682b3b774cc44f99c90e322bc2d6d099bb487646cf152582bc1d1e16ebd819b));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x0ba77154f47b55e0b78227a9d2c523342878f50bcee5da8a9a2532b696d82786), uint256(0x127bc456d03dcf292ed61ce9bad77653d673a25c59f116c6cdaae9393ad4d568));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x1afbbfdba5ce7b13e2a26f1e02b89ff994d5d4887653be7a16e44af93cc2415e), uint256(0x12fc0bfbdd8f915f2440db31239d6287b1ab48e8c0ad2c65e130054785c9a74c));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1b4f529462c32741aa802b7e52799a35915ddab344c355903c12f65fdb353b3e), uint256(0x04174b397dfbe6f3a52c5861eeebf269632221a994f7756cfb58b6b8db8247c4));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x1a79ab0286401ca436f45dba8cd9b27b0d039a69d8f72dd4dcf8f41e83952094), uint256(0x0f5d3feffe558a8b5351b2e607f52cfd5b4e3ac14e03503909ac96930bb7acf3));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x0cafa9bacb9697f9fc44f1d9b87ea5b0a06285f7b95af0831d19392261d80402), uint256(0x0cc654d12b67a2d572a942e7c943908a53336b29f0985dcd4239f25e98f83130));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x2c9a0a5bea8bc954c673b613f3761dbcbc2c49748c41ab82091e9e54d4c293cf), uint256(0x2da3057f4f6e6796d343e11066f0272d600c6db43253f0574a3a6b3d32a9bb48));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1f01e988c7a093842ed10ab223b8fdb472d2c13bfcd592c9d7df2bbf83038d79), uint256(0x04fceedb428ff53a486e535a22374abed3e6d7f67407b66e6d690ff652ac5dce));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x01b938944c043251c3fecbc5d64ba3b0dfff83ca48b6de223f0c0812dece75e1), uint256(0x1403ee0f1e47ea8fdc36f882a7e7b6209fac240bb3a255c67097b6b6de6d11d8));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0df2f30c67296f1da3dc0e1229a2b336c726b45d1d18fcb11eba46e85713bd52), uint256(0x07f13862eeb98110f90ca569e0722394b9ff49dd1c6e65dd84ede790c7b3711b));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x28957fe6913ba49f7ce78e9931ea1bff4c31f4c69cb73219cb4a42bf4e68af8e), uint256(0x26d0da9fa45e9257bd72f8c336dc7a44ade3e4321e010175390c2c17a9cc421d));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x083418d51d354871edf80c593a4b2ece3035b162177bc94af91070ff3992f36c), uint256(0x051200f0fb0d421bfc36d9ad1a48737bb4f8018856d6d82e7f8cc3dfd0a1d2ba));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x29fceffa2d5cae0b159a3620367b1f092cff7cc2583811e4043c91fcf60ce894), uint256(0x2d9aac714bbb74191074c7039649e2f400b84f989d4909d73ce54d9f16edf3ed));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x239c355944c32c8fc2934c1da763cb479ae225b967711d175f6eda4518913da9), uint256(0x02f5477b1956cdeb9c5a21217b446ae3b5c14e74d82aefd37a87befcaa7e09f5));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x2884131763591968995f297eb31f9503e85dabe25754b25611db8c0c8e4462ac), uint256(0x12ba69e0f1e9e0d27615d2b1c048591ee2d5478ea2c23114e4eff6f5c750c41f));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1f6e04123946515ec48f578a1b4edd78395b758a256f7ef15191c9bd0d0b3317), uint256(0x0a7a4e56bbf38abd50f9c5c0335105de9a85519394f93f96f265bcb126adfa3c));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x233b0d2e7fe65e5a9e6d25ece7b985bceb80f874e86bcab7a9edeab8eaf2378d), uint256(0x1e53cf20a54aaea99c9fa5907bfff10bac45bef9aab8165f1a9ec7f4e0ff7b2c));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0c55d95803c39119730bba6e7fc544dd7d8b0077ae9d5d8654ff756b8abf8268), uint256(0x23015d99798b598d3f6a51b8b486a3f1a80175c64986705781b1832f6e35b3f4));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x08723ee8ab35aa7b0adbf083f9cf4fdaa18854d4ae66f0a2c88034e278ac5d40), uint256(0x251465575d6bab3951372cfc155eb8210b656b579c54c9b6946dcd071a08a86b));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x0f4c35e529b963c0e87efc0504c93cec37fd38d21965b7ba652974d3082596b4), uint256(0x20708a6414a4fa40d8c2651e3d6a70ce2a673aa83513710a057003ac29fe43e2));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x0f1e7ec3c9fcb5031afce773592253f40c0f50d85de42a7cc73efe352e54fec8), uint256(0x14bf8a8c131a52a0a0646af808cf567c64d29c043e9c91ff9346de6937e34d9d));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x18f895f1df58cf55cb8c3251c2ec33fdf88529d86d6c624f959e2a6c338e2ed5), uint256(0x178b499673931665993a04242ee919d8348e88e1afb4f55421d44cbf752c163d));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x193e7a28f2edb1756999363d2910da937a27a504d53182198e9ac03898ad5558), uint256(0x18d2b63441fa937fc59fef8a4137f503455d6ad0be39799f410f3969a3fa3d9e));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x185caa0c2f3ea1a157e5cf760f4e1d8dd034df41f434b55a85f7c9793d950edf), uint256(0x2decccfdf748ae30d1afd630eb8f2822719113d7b8a070b42ffdd41200bc94b3));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0703139d7d20ab8a101e85f4a6a45eb557a797da3392821d4455683d10aad39e), uint256(0x3041e60367e02c8cb19278adf3293b0fdba01f89e5e08f2f785a06497a5788ad));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1d340e9179c36cf566b3f5638827f499adf757d0f65cd6ea63103a2d0d408497), uint256(0x08aa6821d018a5a4510d1fbeaf569d0148a8e63f31dded1ec3f0b499113b4b3a));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1f36b969dc31fbdc212ebc107f7b20996d1990579e6959a16a173cbf06144872), uint256(0x042c412ea5976878c4a36f45453f6fb6689dc5c15242c89312f9b3a2f1f96992));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x2ee93d29fbc0e5827a4878e3b716d281bd0f887316369fe2fa424c1fe4f05473), uint256(0x0b3c6728164859b6e9eb8f568311f811900ce55d6e0686465c45db5f110c838a));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x0932e3b34e19d3f556ea49f3d1431354b55bfc2ff2cb69aae3d892f1a91fcab5), uint256(0x1bcab2849607172f187a3589b169a6a24c4fbf43568a31470a3e35dd3a53465d));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x18f1c84983ea3508f9ca9563915ff8b5aa4928363991eafade89d49b45a48f76), uint256(0x20fe79d90fc487e276e4a4c76b6819570f7c40f4abadc76a3fbf84d84c27a8ec));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x24dab68d75226aace326822ec191aef9646c922e8e8943ef1fcb4450c4c5f460), uint256(0x12cc49827d09a4b4996164e1140a58f11d777fbcd69ed3f46e68f43fe989df2b));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x1512f6479f76b846494df752529fe6de4d461f93f7e192bc88ec8a8d1cbcef4d), uint256(0x221c1c73443b3354aa4c6eec78694028cb88adb2d0595dd3b04cb8a06206fda0));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x105d7db58f0757b5ef218ca7c1ebdd3fb82bf50643b562147c7076397ef8ec9a), uint256(0x25a3871fea1e988e8bca7479f2f361be58e357e0ace7645ed6e78a1180996e72));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x298e3889275f61a75b3507f25f2f8be98d325b849a846130000ebf2880192038), uint256(0x03370698b7ea2105e1974f8c34a8364b678c606ccdbc42a39a6578789e3ccfba));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x273914429dee65ad7dbc31bd5565aa0d15f67f351d5056c184455ee5126d77f4), uint256(0x27c6852507b308e5b396f091a357244c202d9e352b9369c782c758e9169c0c5d));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x208677abda8434bc0267085725c1ddd4233f77c3f0e9eb979a24ba2eaf1ae4db), uint256(0x17cdffc6c5517f12a05fc117d904a4fbf50a113396b9c6a0fae8b9f38e5caa9f));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x1d083fd4b76a3387da48bcd75e285d7b92c6f8bb287b673af747c86f7cd2d45d), uint256(0x0a265923aaffc276e077e1ee8411195904208a5fa7c88c0e1510ced393ab908e));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x0a1cb77e8bb54e564afb02d11d0263527b9c42ce51212e7929961db90de9b508), uint256(0x087361f5932f996af14cc428370bf4cf1bb36a333c3c062b3bba208cc0a49f9c));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x2498fd455ff764e5c5dc2ac510acb23ae039b758eaa724e1cc8cd241963af011), uint256(0x28ddfb92e31598a9440bb747d7a4a2caf2153b4af8501b0411139c73b003ca02));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2a63184aeaea1fc5476a5a7385e7664c444b0888127c82e67f58c9878b77e3a0), uint256(0x237fcacd13f0a6b76feeee0a83f77e6d74329721962ee2e60ecc10871733affb));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x24fa6c407d5d8468161781e4e489f55577fc66faf0e6c25a6eff8380883d4f37), uint256(0x16b08b1c56e4b21acb952b4f6b383dc4e437a5701287db7ac4ee27dd996ddcdc));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x2013bea32426c7c11996ffbcac2a0e92a4de984a282cccc058076813bc815c6a), uint256(0x13888e11c746f61b6c7d88b821ea407e064590f6a592e859b09d53163821b365));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x078704abfdf7465071a0f97c915ae4477f0da19470aef3cae416a347c6692388), uint256(0x0cb894a9eec06fabd4929ea6376ac796e427cb32820715fa82d86c587ea0ea58));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x1bcd1a9829ee93b34f78aaecfaa6bd30729e3d93f46e64d2db8547cee1d70ceb), uint256(0x069140b34087be72df569f4729bb0783502e333a12350e0c81db481ea53c452f));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x11c4b03ded2fced50108a3c613b6c3f350b1f7d2b137ab01dc0ed32ae16d3ac2), uint256(0x29d5f7aacde8ad329e20fd84dc44f3e1a30b6a183d85c4aae38ab551ac704862));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x1c8ff58b3de06c68956988a8599333eff51a74a09f0797a77b4f1390c948f9c5), uint256(0x202b72ba689c602f04a40e9fe121fc36d8db95388a551de05ede276520b6b911));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x288beea20aa62a236f3d5a211757a598fd8237222a10cad54d68d45797442a10), uint256(0x157b6a56fe8ee83c3361080013fbb5723b65ea268d878e8e1287949402255ac0));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x0cf7d31c591549136ce47ad28a1dd03b87a71975a0e13156a77181a5af6f2857), uint256(0x01ef74b9d59ee68e4a5bd039c625733110284171cbba80225667512adeccf967));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x21dac100c12ea841cb0786b95bacf11f59062aa7bb309d5a7952decb16cc6400), uint256(0x23a26f13390cd2c0618501698fd0f3d5ded8ed87371c8727ee605f152ad3164e));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x0b4fd5c06609e22e7dfd38c9cbfbfaa5d5e8e8aad6318158acc2d5c87d447467), uint256(0x002ca7bcad29c90f3ad61fea73e93f663d23680c3b6b1b4920191274b3aa778e));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x1ff5fb720b07997149666c2f6bdd8ce93b82f3b2dd4ce8fe5af7a5ec8ce3d40d), uint256(0x0ed09c5c604728cee670fb7893e4dad29c74da134e21cb073837c8904b84e858));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x151ac0ac1697a9b63454362dc6514dee7022efddebd34217ca1c3b1fafb92f0a), uint256(0x1ac80b983b741958b1b94e7b1926115b6aca4ec6659cd0d3e971e2cefce6bd45));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x0a9f0c4687957dace612c408fccec89ff8c6d7f7f6e0e6db8246d84436d1dfde), uint256(0x170b3cb0a25412dd1888fa3f04bc8ca9669236cac04b9e21aa557b0d3c108c07));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x243a7a324ca2aca0ae656e19374f3665f5aae0aa7a14d2514414765e3bde3e72), uint256(0x16336deb83d5948ebf450221cc8615ff4afc1adf3e2074a3e43988b32b13a58f));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x0bc3b2498cba2c2f5fdeeb70063cd8f361617d5e5600ae47db3a97b3e6ffade1), uint256(0x2d1780fa93c66939c8451918cd5e14530d4f74a469bdb86f8b462140cc0ec8f7));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2a1196d6e46ccb4ac74b981d739d7102e548e91afc4687ed50ad621cc8e7f750), uint256(0x2efb495efe23909cccc5d3a519d8d17a20f76b5bfefe05bf7e3192fb17c32860));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x1193454eb6f79d1119484b2d262d144b585bc684af3f1e06e08b482eefab98d4), uint256(0x0236eafbc5333b13bca0e689e48e82e33ebd8358e6eab1e15ece205a699cb821));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x19f23693de5b29e4746b51a83145d741071d65e8fcbfc033fedc4ece77cfd5b8), uint256(0x0cd89fe2cce8731f3c9949117fe7e823b98c5becb4041f6a6b366349ea57f43a));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1c06582417697925c9b01c4f788d773ee6d3acc93fc3c10f9f6dcf475d82c31b), uint256(0x16d6e02bf0daee6b2890f6c07092dbe436bfe926d8ad7aeec877335a91bc0cc0));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1da2d2eee8aa80fbef5525aa5c115dd88ef58e9bc000ebf9b36654d149bcb302), uint256(0x28734b0b6f021a80a10e1db37f78311616c0b9a5a3f1d15ab13f9ce2c9030527));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x0cd18a74d3182395a065f29101aebebadec52c2e3ad3f918132c7446f4387617), uint256(0x2c680aac44812f7a71d287b021b7dbcbcbeb0a8366bcef31d8b7e1e88124bfb0));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2fb296fae8201e6bcfee141df70f13a087c4ce03b136854bbe81dd839f423bef), uint256(0x0d15b6edae4d53adad28e6a44697ba9b1c410ea239fb8ce41e2afd0eb7d1de05));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x0a4700c5c3f367ac80250de1a1b1f5cc193fd13c23244ccc598fd8af67abb25e), uint256(0x27534d7e8de7e4d2e4faaac2f5cb30ab9fbec4cd160ca25ca817b40676dbf4c0));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x1067692858ffd3b848a72dbe7e538c002899f5d3dce0b711345fc863dc56a841), uint256(0x2b1db5350832f9e15ee8cce2c360f16f84f6ba88fd69fa4ad46b26d4649d7fc7));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x17ec2185201d0e7c961b6e006f156ad6d65dde56ca372c3bcabbd1dde6e70248), uint256(0x16b2874cf7f5999ac5b91218857ff36cf2b6e98342cfcdad8f0d89d091ba42c2));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x15792ce66bdc6999fed92458a730f21c5d83f253d133ea5c2260ee3433a96a88), uint256(0x21fe8fa420234b0661c5edce378294af1bfb4e8f06e60d18ce295eb9866c9b4a));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x0cba0e170861d66320a59ab76451c6795dc3ee5eaf017f29c6f835075b1876d8), uint256(0x11993c2fcc502ec00300193954c8ef1ffc76ee348bdf7ad7d4834ad985d9ef41));
        vk.gamma_abc[92] = Pairing.G1Point(uint256(0x22c2c89348e2e3687d95383bcbffd8a53430b82066d446c4c875e73a596a37a7), uint256(0x171e87ceb6b99383d7facb09d3af423f6da8eee621f7a8c801f8f9d67009f5c1));
        vk.gamma_abc[93] = Pairing.G1Point(uint256(0x057614581734dbd48a0a6e89fc39e8e8fe88367ea2865d00a4a0186e209693da), uint256(0x03ece60a42da380d682ccb0834ff58399ef2c15e1d6d7187fbf444d757b4f97c));
        vk.gamma_abc[94] = Pairing.G1Point(uint256(0x0f210ad7b413ad360a1c45aeb0000d85f5f7fdbdd41e280010e5315fb448ae0c), uint256(0x242800896beec359d86e6b9f6c67db871f937623f3a3a64e058ab9d7a5b9590b));
        vk.gamma_abc[95] = Pairing.G1Point(uint256(0x15187afcfe6fee8836e863d9f03219255325d2c128bdc97d584e74aba5456a5c), uint256(0x2e9812d57cb59c3991931714c87321508a22df654da2a8533ff1af3410d9029d));
        vk.gamma_abc[96] = Pairing.G1Point(uint256(0x2537f500bf837792970b6f2e92354b28cb3e1f7c6655412639ef02efbaf64d4b), uint256(0x04fe49b1ff886ae038e91e0e63f7b1f5367059c58cb0ed87508273fd75fdd20d));
        vk.gamma_abc[97] = Pairing.G1Point(uint256(0x2d3e05e9c335560c5415a70fe1b5b828dcbe05fa7612e4539041d4ba6a76eba1), uint256(0x23986f1422e9485ef6cdac4644db376f0e1bb3f1d49fc344a4626f8ad06ae0f2));
        vk.gamma_abc[98] = Pairing.G1Point(uint256(0x27b3cf778b0a4f4cdec98e5d774225e35455c7e028494c96557a109583ec8132), uint256(0x22c185ac7ca1796e5047ac9536a0b8cfa62bf005822a930112cb1b3922004ff2));
        vk.gamma_abc[99] = Pairing.G1Point(uint256(0x1412e9a0ab666c3e1595c952d57ec26b713154691bd0941f8ec4a4be93bd6128), uint256(0x23ba9c9085a7f56cd47c2ade616cb19ca29b49e0fe01860c6c32e00ace51c8a7));
        vk.gamma_abc[100] = Pairing.G1Point(uint256(0x0e140544cf44308bf7f643d407f6a25cdfe0980654a5ba6bcac8ab0d186c6d96), uint256(0x12dc1dbe0f113fa0dd51d47372a2f539a78db9b28ef9f6e8b8cd96b97324157c));
        vk.gamma_abc[101] = Pairing.G1Point(uint256(0x2667e4d6cf75b28ad341ac4cdd415d9c6dec42db5cc4018d1d6854b29bcae21f), uint256(0x2c1f57a813b68681f23b4c9ea03ed7aa360f36dcc54ae82d52c01a6fea827260));
        vk.gamma_abc[102] = Pairing.G1Point(uint256(0x1ea615d4ff0c87739f1e28c14deb41fd2bf4b4300a8a3e1e451359688f78c580), uint256(0x213f17285cd712b75c0e3e2e1849cdee297ae22e9175899217d674992a611935));
        vk.gamma_abc[103] = Pairing.G1Point(uint256(0x05cd06285b7de8ab7f7ff3bbe53bb30a0e399a5f5960892b1fd51094092ce2a8), uint256(0x01d0b0ea852d709fdbf8070159727afc6afc3d51bb7ac1dc05fa1a50c1bcb77a));
        vk.gamma_abc[104] = Pairing.G1Point(uint256(0x00bcf12d3d508c19eec58e1d0bee69ac0c9eda3cf73c3e3d558030ce01d582f1), uint256(0x037aea89b3ae581b06257eb33ed676c9fa2618de7e8c0eb9aa49bdbc5d094e60));
        vk.gamma_abc[105] = Pairing.G1Point(uint256(0x15f5019ec75d44e6c9603fffd910f550ad9a2892c88b13c0538b3a82bb3c8414), uint256(0x134b67d4996e872c3a217dda2ef0adec8daeb66f0bea87fb7cc5086b91b0de38));
        vk.gamma_abc[106] = Pairing.G1Point(uint256(0x1b364b100c4a7223533eff7d0135c68e4dfc57dfa79e91411a0003693441956f), uint256(0x07fc55365f5db137ab9f04fc07b64e0ab4f738299803b12551e895cf54b68e44));
        vk.gamma_abc[107] = Pairing.G1Point(uint256(0x2d907d59f7514124783126efb7b468c30fdf5e273fe1ce549b2ac21534866e24), uint256(0x1f618f9eda7234d0e0f28f356980d961ee60091429bb6fd3cd703ec445ff7dae));
        vk.gamma_abc[108] = Pairing.G1Point(uint256(0x1a7a678844404ef7639e5d2b19accfec3a91fe1a479ff2d29e5d40deccd3805c), uint256(0x2b658790611f503b295c4c2b0b7bd77e725b6eaeb4f769834023d7bfb86606a6));
        vk.gamma_abc[109] = Pairing.G1Point(uint256(0x1801dc61a1467a497572f890403713b4d677a0079813d31e2c28119091352c01), uint256(0x09b49c20be664720f81d873f3e022a8ea8bc44019b0e880992c2af60cbfc5161));
        vk.gamma_abc[110] = Pairing.G1Point(uint256(0x062af659f37ec37e5c78de8bec8f115f0d372813a98bf8c5da92ddcb485bac5e), uint256(0x2d303fabc610379a87fa8ea9bb3bec075ace7061343896cef001d68193554712));
        vk.gamma_abc[111] = Pairing.G1Point(uint256(0x12a0e7d7d8c5333c78520fcc3ed377e87aa1e253aadf3bf1ea580e0b97d7ec52), uint256(0x0ce2dbd36b36f92413b85f12b52e167d9152a8b13aa8677e1d88d28fc5f21912));
        vk.gamma_abc[112] = Pairing.G1Point(uint256(0x1192f79ff47eb11f239a481c0e25ed3c1c4a952366947ae3234d17a0515e2d07), uint256(0x140b76ad9d9eaa7788b57e0a8bfec0b098ff6e2e8a3ef10b7e1533be0d4cfece));
        vk.gamma_abc[113] = Pairing.G1Point(uint256(0x1fcca143458e13cb103d1c7af8c79c67c3582776a2c4f5ab52b986b7d2e9f25b), uint256(0x1059fa9c1aa34a456bcf597e727dc067a864d53a37fff55ee5234fe5b0c20a46));
        vk.gamma_abc[114] = Pairing.G1Point(uint256(0x06ae962e5f1a8c2c41a28cd3ac6f5e942cc6b473131fde42899d23214f82ced6), uint256(0x203b17c8eb0aff10d5859c9c8f7ee1231dd0692449bd4cd1a925e7e791ffed0f));
        vk.gamma_abc[115] = Pairing.G1Point(uint256(0x1221b8353962d5b1d46739b9c321a63150852643a73ccfec476e0e930aae5b0d), uint256(0x1a814b89e2b7217cf504769622a9e36a0ed2978fe92a4064b503510214d9f97d));
        vk.gamma_abc[116] = Pairing.G1Point(uint256(0x1bd861c2db8f1c04b4629a2fab0116078d41be92fd4a80a2f0b01198415f35ba), uint256(0x1bfbd20038388eaf6d3f7b43bc481dc40a0fe472e2fc82e57deaa61a428191f6));
        vk.gamma_abc[117] = Pairing.G1Point(uint256(0x0ccd046d9f77eb55904d02cfb153c22de611d2f065c1b9838c46decb88ffd133), uint256(0x180fa98cc37af693e68fc02a99277963dea69013e11857dacf630e66e6c859e3));
        vk.gamma_abc[118] = Pairing.G1Point(uint256(0x2039cdb6fd903ae1573380e8624a305bf66ade5804b7b212ca600a6be43fa1fd), uint256(0x158b5414e33593abf9b2cf19f745e194336102404584c01f2b99c219529521ae));
        vk.gamma_abc[119] = Pairing.G1Point(uint256(0x0e0111b22bf07a02b10cfc84884f01bf78cb9764b7fc3c3c48fc4bbe54e2823f), uint256(0x2ea37fffcb52d4e0bbdf0025dd7c157b57c763fcf50e650ff3abdbfff15f84f0));
        vk.gamma_abc[120] = Pairing.G1Point(uint256(0x0e8d58bb76f5d0c2cd5f98770ae1b48750238e7546021e59d88a68949c1a14f7), uint256(0x29ef4e0f81db6c152f33bc14d3f631601f66a17de5018ea5ba253d6da0c137e5));
        vk.gamma_abc[121] = Pairing.G1Point(uint256(0x1929147b1a8468f0bdba2b893406abb2d9f36d053d518d4530f0fa03eb5c6fa4), uint256(0x29767bd68b4244acd55849d3f30b753bfadd657f4ffba24663986b54a91337eb));
        vk.gamma_abc[122] = Pairing.G1Point(uint256(0x0bbd9e37cd5bebea57c40d60b2f146670e9fd698a79bdb9654c202905c09433e), uint256(0x0c868c1530dad21ad0291dde85960f40b0bccbf30f9a3f9bf7280349534e7851));
        vk.gamma_abc[123] = Pairing.G1Point(uint256(0x218d14245807b4276a691f1a50c43e0bc759b5d4818eb11457195e410c2e6bb3), uint256(0x2f21d80ec0f7182d0a8d0bee5debde02dc084277d3325a6af942d7021f5f36b7));
        vk.gamma_abc[124] = Pairing.G1Point(uint256(0x18f3cecc0f16ff9e87f523ce2ca81f5eb964f49f46e7686f7b03c9d0d032bbc0), uint256(0x2bbc94af5669e8977b060c36df1332ab365a676da83200c6acde636da08ea982));
        vk.gamma_abc[125] = Pairing.G1Point(uint256(0x12228c9e249e8216ce8f04a35c9bd022ca273873e3ab2dcf56e742da32465924), uint256(0x087176a14a38ac1cde16f47970da481bd4f620a8b2720e2350a2bdacd7da5722));
        vk.gamma_abc[126] = Pairing.G1Point(uint256(0x1d62907ff7f50d4e37702304c755d877ecfb6186be746682209bb2687f8b19d8), uint256(0x2766c42bdf559f3519be94832598d47168b901794ce142a70187d1832d93ed0f));
        vk.gamma_abc[127] = Pairing.G1Point(uint256(0x188438e3f95c43dfed9c8b24f2e4df312c2ba061c5def9835a584821b271a619), uint256(0x2246c587634ca06faed07366a2080b5aca8cf6893834a39764e01dd86f51beaf));
        vk.gamma_abc[128] = Pairing.G1Point(uint256(0x27f3d81c4b7729a9c23029e82251e4e168544a88796bafa6b02d6747553953dd), uint256(0x0bab176f6ebd06bfa1002c5525c0313d9f22b0dd0bbdbfdc1e2bab99928edd95));
        vk.gamma_abc[129] = Pairing.G1Point(uint256(0x2e0974f68136a6a32822c6fbbf9cf392428f917f1eeb583356e26ea2546a6357), uint256(0x1f2a673ec0af49def63a026eedf4206f92201701177e867f123c8f4e6d740389));
        vk.gamma_abc[130] = Pairing.G1Point(uint256(0x2d1b8e1d4f7d8d049e5beb1cf6d1f84c370fc52e68d4b125ee747e05f0159bc0), uint256(0x1f0c4dd937b62e2c3ab9254104e7a2d36c120298e96720d01d1ab5e9dd9b1a8d));
        vk.gamma_abc[131] = Pairing.G1Point(uint256(0x1646ba01a3a92a487829d621d133292e3de4725ff469b0e7b5122a3399e0b55c), uint256(0x2aab429dcc9b5763a34ceabbe24bfebac87dd2d61134e70003e843a4c17db75f));
        vk.gamma_abc[132] = Pairing.G1Point(uint256(0x04c9e3a8f922ba8c2f837a7a5f4f903d50e8cdeb323634e533b551df1f59d3a5), uint256(0x059400c7b815726ca0a6a12c878d7b5454e3ce2bf45572ac1b2ba81c6cd77992));
        vk.gamma_abc[133] = Pairing.G1Point(uint256(0x27526f4e5ff4e701689da1809ed7b503102cb18950177397ec5585c0f25102d7), uint256(0x20d355718d222ce6740da03cb0603316f19e9cb110b728cf26003c268d413d5a));
        vk.gamma_abc[134] = Pairing.G1Point(uint256(0x174016a1130e3a2f221f73f6ce178c4ad9a758914dd3b7b4469e548eb865af18), uint256(0x1af7b9657a22ea5450140f35cce9c33a37177ba6ce5f1054a1eb2112cdd70b88));
        vk.gamma_abc[135] = Pairing.G1Point(uint256(0x0496695ff4fef76f23e0a25fb1c8813ac96d695328f3ba807c045f0e6c6b194f), uint256(0x115401d2c4452fc8e7fe5914d690f58c03d9b5398939bec2d8f9461223519cec));
        vk.gamma_abc[136] = Pairing.G1Point(uint256(0x29fc73cb334f47e458f47590b84259f1f2730d4f97e24531e50182bfc4cbc2dd), uint256(0x19008b22ff10f233d830ebbdefccf5e983de5ad8c69431db6c4eedde0e8975d3));
        vk.gamma_abc[137] = Pairing.G1Point(uint256(0x197d0a5d8bcfa3c21a07e50896c2f168a519682c082bb06921b309ca72b1f799), uint256(0x18b1932df561b6a082bb027d7296f5facbf6597f1d6f5afe10d5003c6337bc1a));
        vk.gamma_abc[138] = Pairing.G1Point(uint256(0x0828aefef577757ed4ea912f189ff120f846ed4bf09c08ba3ed7213f9d8e9a38), uint256(0x0d9fd19d6cb249dad0087ea14a64f586f8032a37ee5ef1693939de64a03ca25b));
        vk.gamma_abc[139] = Pairing.G1Point(uint256(0x1a4742d7c8a0a620053c774e2c979359a8a04fc18bea059ec7708f7b5114889a), uint256(0x070782633b3f2c01dae918b32ffdd3b079c6b26142dd8623feb1051a0448b196));
        vk.gamma_abc[140] = Pairing.G1Point(uint256(0x09336b389bc746d3e6dadcb07633202c2851361b258c44bf41cfc400072b0f11), uint256(0x111113375d029637732b9593bcaa66a39fb3a78c9082132f9f390dde4069a2c6));
        vk.gamma_abc[141] = Pairing.G1Point(uint256(0x2b6ef8cbbfa2b4014cb4b4ac1e4e57be47ed48aa287969a039b1ea12aab8724c), uint256(0x1292b1cb962741e6f859dff32e2e3ee7d810506af00ad451ce0607b944b628c8));
        vk.gamma_abc[142] = Pairing.G1Point(uint256(0x23a0413dc4d9c10db781ebd38261674be381ac713bfe4fd4ef6865dc63527215), uint256(0x1c90e6a4e58a05b0ca28e7ad84fbe9e3e36077ae735637e897134d5b8edad836));
        vk.gamma_abc[143] = Pairing.G1Point(uint256(0x2549573fd72f9a29fc64640ed04d3206e8dd4ec5f80773ac2b99d71b1c457f80), uint256(0x25def49b9ab472e81d50621099e00c2beba18a1c510477abbecaeb1850c6f8e4));
        vk.gamma_abc[144] = Pairing.G1Point(uint256(0x011dca42837268d79d56a794b0a1595c27884119772a7f1d8b98fc7a5d3b25ca), uint256(0x2adf2176ae494504e755165966fa9760264276b117f5908e65a1babc5dca0575));
        vk.gamma_abc[145] = Pairing.G1Point(uint256(0x10e5e045ca907270649fd5cfe2f047b75a34f0b87554765f2a2a0fb074f52824), uint256(0x1496e10104a0dbf2ab23158ede851729e7cef4f3553a0db54dec959192bfe561));
        vk.gamma_abc[146] = Pairing.G1Point(uint256(0x2a0f2fdfa7db6186a5991f53a89b88c91a1e0bf4340c7614da0c68d4439233e7), uint256(0x1b897227dc927585bf9297949e3dd13f6d758b67b7a79d04f6001baf59579dbf));
        vk.gamma_abc[147] = Pairing.G1Point(uint256(0x27207a8bce61e8b8b5b1bcc4d0d1dfd4847e0d8eacc83312f2210f4906d9cccc), uint256(0x13fb190930991d6813b58c5f28f63f31e153c5a084e8565fe7c759eb230c122b));
        vk.gamma_abc[148] = Pairing.G1Point(uint256(0x0211b2015eb0d89beee6992bd4c9fe5df125e0fe80a1994dd18fc03319be8474), uint256(0x18e11439f1d60e82cfebd254936d6a85f433aa471a82608b7a9df9f85220e388));
        vk.gamma_abc[149] = Pairing.G1Point(uint256(0x2bc6e6d2fe4fde287ba013d04e96b13809bcd0cfede5f3b137dfebed90726051), uint256(0x08a08dbd17a9dd73b2da203d8eb6cc64f1fff5f40b389e674cfdd8419699b4c4));
        vk.gamma_abc[150] = Pairing.G1Point(uint256(0x20e47261d6797d4bbd9d91cc0d90da161ebcc681f175cca9fe92754218aefb01), uint256(0x1079782427496a7e2032c0097ead26a04f4aa1503ffce70acd082af1afde8de0));
        vk.gamma_abc[151] = Pairing.G1Point(uint256(0x24fff77bd405906e2760f5f8c31e01f0fb750c3f89639d005edb9986422101bd), uint256(0x02b654c61a667d2b16389243a686d14505395bbb61bf90ba6e7890f8238cb2fc));
        vk.gamma_abc[152] = Pairing.G1Point(uint256(0x026e313b91822fd384e6ee326c00f87f22cb1a2cb4a24c25a60010f53ae5e900), uint256(0x2c8638967fc2244d1eb3beae2bcf6d546f3ff81e7156776870584f14c6eb2cd2));
        vk.gamma_abc[153] = Pairing.G1Point(uint256(0x10a9cbd2df36497110d8d48a2d79c135f7d1155b9ba39ecf41a8dd3aefde82a8), uint256(0x2f1887f7a0f48a1664f4ed740e4f7ba1f779ea8881393de001db65daa447cfe8));
        vk.gamma_abc[154] = Pairing.G1Point(uint256(0x252f01d6b4702867da4bd0e243a4078795f34b3efed40b449113c101e4c895ca), uint256(0x1eac8b2c7dfee5f635d2d449488f02c7992c4bed9f700019ed0862edc44b4b1a));
        vk.gamma_abc[155] = Pairing.G1Point(uint256(0x0fa7e659b178e6718dc29f57c9145945331ef79ed9f7afac1eca6e4dabb3ca4a), uint256(0x1b51643335598773e5ba79ecf68f6f9c544d8b8235c524440b4bcca073b450fa));
        vk.gamma_abc[156] = Pairing.G1Point(uint256(0x06339caf91a5bcafb6958bbef52834d8315d45bf50d12e841b35630b5a6802f7), uint256(0x18867190e21ced09cbc31fa1219780d2fac1b2ac304ebf704ed469777966136e));
        vk.gamma_abc[157] = Pairing.G1Point(uint256(0x0f2d9fe293a4c61ed9420b836696af443e9bc380642ac7cb923bc6a6a512761f), uint256(0x04e2306b3da4776e774518465d1dddca8f06524f0563bab032f6a96af6f77a69));
        vk.gamma_abc[158] = Pairing.G1Point(uint256(0x2e5f214925b1bb720d70a72225e3f45b0c7e5c71f1d15f5f150374b1c0acf390), uint256(0x0cdfe45b88d4507a8e0ff7a4bc0781ead5a8fe4ad916168adaad51026ff0ad7c));
        vk.gamma_abc[159] = Pairing.G1Point(uint256(0x21322ada3a776c7e699e7b87ad5ec371b33c4e494929dcddda2997d5f0d799da), uint256(0x0f97b53bb9e6a405e9363e3c775b40ad34e031ce7309d67742a0eeb2933a0145));
        vk.gamma_abc[160] = Pairing.G1Point(uint256(0x22894233a479543c06e275e17629cd48df828fcf9395a94b018e8d63cbe0c709), uint256(0x2d1e2eb335fb2ff2aebe22ad84ef4c7c7e8a344d0e57a4d971eb355ff46f306a));
        vk.gamma_abc[161] = Pairing.G1Point(uint256(0x27b6ae023e579276811eb31559753b0ab07323cfa7b6d591f1bbfdd5c606c8e4), uint256(0x08afd9d024545410f97702095d010eee767a59e77b637768efbdbcc6c418df59));
        vk.gamma_abc[162] = Pairing.G1Point(uint256(0x04f18c9ef295d61c26fa54f298110bee8224b6a071957eaaf2b2570d42d4ed34), uint256(0x2a3af75ae1031523a547d34139fed9e3146eefc6510b4bf1c5d3a978d4a89c9b));
        vk.gamma_abc[163] = Pairing.G1Point(uint256(0x05470b0851a71a6bcdf796c359877bb86d91766f3152749a4f67d68a22222907), uint256(0x14a6c84682de05058077a8a6d0a8c17e5796ad125e5950c7977248e74fb192ec));
        vk.gamma_abc[164] = Pairing.G1Point(uint256(0x0bf5597a1395ec5acdd3c129b712f5256ef8553c86787b6446b3c8e01084339c), uint256(0x06d8b155d2c56ff918ed8c25a59c639a13f55d313ebbd52d682a2e5886afdba3));
        vk.gamma_abc[165] = Pairing.G1Point(uint256(0x08563464cc3a6a1284fbb9e219a8c1b59473e3d4c74e05a4307f0e2136ad6979), uint256(0x261114741fae6f80ce4265c1f9ed9dd61a8841c0194e96b24a4fda661ccb973b));
        vk.gamma_abc[166] = Pairing.G1Point(uint256(0x25b2782b8030a5f45d1d94672a1325c61df2e6525865e38a8d89ab04917bbe6a), uint256(0x2b61815a84342a30654f2f4cb5316f90ef249ab2b44579c53cec581daa6536e1));
        vk.gamma_abc[167] = Pairing.G1Point(uint256(0x06ca26c763c7a493f82c142879a23512a2000c95ce49d774a3a264fd90c9e99b), uint256(0x2ce04eb04c82b6a0664e73504c1237a261767623990f245ba64d9abcd12add7f));
        vk.gamma_abc[168] = Pairing.G1Point(uint256(0x2a977010de9ed5664cb107e8f82791c377c06d9f98f7cbbd25cd677b0012b51a), uint256(0x0dfcf008f2e3322788903641dfbc779774d6e4a85c6360cf647e6be85bd16d11));
        vk.gamma_abc[169] = Pairing.G1Point(uint256(0x1919979e145a415e995438c4203347134b1bc75ede4f6cb59462e8d2f88ef7e3), uint256(0x18773fc31daf3c962b3360f13be6bac195362f48174505562c0d41f92610bb11));
        vk.gamma_abc[170] = Pairing.G1Point(uint256(0x1e90def65f37c6b6f0a8a8b00b94ed5d85ec68c9f295a234f3c14a8ae5ecb4fc), uint256(0x1b7010ec8a50dfb5fa3a9efa3cf6e7520e47b8593d276170eebb90e5e23d857d));
        vk.gamma_abc[171] = Pairing.G1Point(uint256(0x0d408582bb901b3f57b861a935d71ff6720bd4e5f5ff27ff976de32722820e05), uint256(0x23a260ad0602dd024583c4ff73c39ef695936827d512d98bd7d21440e69238c3));
        vk.gamma_abc[172] = Pairing.G1Point(uint256(0x00e438842377fa191b9aa23276b539dc7945210183968ccae370e4c90cdf0d40), uint256(0x01d8d1e13c1826f4f230fd9eab513cfcfff747b9ec937111d50e1f9605e3fcf4));
        vk.gamma_abc[173] = Pairing.G1Point(uint256(0x2d003c72b716c55e1ce5ae018a714051d20a2c764db0c789b047981b749f4e75), uint256(0x0a1d31ee3bf47bbe0681205b00c7c7fdd2a30b98e92e98a048a7d58045017b44));
        vk.gamma_abc[174] = Pairing.G1Point(uint256(0x1d6c37ec299dd6030722d0c0004df22325a24955dd6e31d08fab5f15478714c8), uint256(0x1af617407269b2ce20930e1ce9bdbada3e8e33e49522c74856b38de1a0f485e6));
        vk.gamma_abc[175] = Pairing.G1Point(uint256(0x08eb4939fe1f6f1776a2377e7d997d388d0d31c57d3f2171e41126695f40738d), uint256(0x14d81709c24ca4e7a0886499606b0a29015d79d1bb5ff05d8360231c7387722f));
        vk.gamma_abc[176] = Pairing.G1Point(uint256(0x22f80b0881c2e941023d0c0bb42821575ceea102cf2be08f6824d32b508bf6d3), uint256(0x0afea91d0e9d56dc6d1d512d26d8872bea2cdbb906a50f7ac7f87015e1ffe522));
        vk.gamma_abc[177] = Pairing.G1Point(uint256(0x1a08a1d036edd9debaf6c3cbf8a0dfa1395d9fe362d9b36d57e79ec7cb8f7860), uint256(0x29cf58e778761444fb9fe73832804b244d35fcf0a96ff4320d4fc286d1632096));
        vk.gamma_abc[178] = Pairing.G1Point(uint256(0x23fc41806eadf1a4d09302123e79a48c6a4a66b7ea5ce9e0424f9ae3e46962b0), uint256(0x2c19240558d38fba981c2f2d7a959e0c779e66b3b5602dc06fd60651934e1037));
        vk.gamma_abc[179] = Pairing.G1Point(uint256(0x172452ed367a214b5c7d9d4274e9d2b1be34e16c465a3a2e974f891aafc76d48), uint256(0x108485cd4fc271e720962259e20418f1aeaad81d4c6c26cb1a58787e9a7fd6a9));
        vk.gamma_abc[180] = Pairing.G1Point(uint256(0x155eaf35dc9f208a10ddc19584b44b5a9d63f7252304d4f684715001f125f206), uint256(0x0abf9043a8d74ea46d7983780cbe1ad6f6c121429ca0ae3f3e4edec7c4cc52d7));
        vk.gamma_abc[181] = Pairing.G1Point(uint256(0x105f5e0ef844f212b71c00d64b8f5805c44b9f1d1afeec2af2ce5512af3ae8ad), uint256(0x162a50e8935996764cc9d53b2171427c4011453d6d36a850b01f6024e204035a));
        vk.gamma_abc[182] = Pairing.G1Point(uint256(0x268a750b56cd6206ee5ac25ca0ef959391e2ca897a064d672d5093fb0f306c0a), uint256(0x146ccd788649e40758f07a9b18b2e564a922ff908afd4c046babb0f761929439));
        vk.gamma_abc[183] = Pairing.G1Point(uint256(0x05a0e452fde8fea78c2d6cd6e356cb34efaa722d4a7ccda493f4e4ab4b4e2b84), uint256(0x2f81e4cd1ddff9560f07517c3ce46c1c2694f84492a503df79f4bb586bb1de77));
        vk.gamma_abc[184] = Pairing.G1Point(uint256(0x2a5c48616053796d85a7a680201240e9c4382bc4e18122927734b126df61f3db), uint256(0x0259db66cfa150e4258c350ce7e41f72cd2f0882fd0405a70c20c5891a5b0f14));
        vk.gamma_abc[185] = Pairing.G1Point(uint256(0x15bdb16588f616c083474df8658b4fc9d414fac223ff8d3021143a23dee22544), uint256(0x1664e35175905043a6e3446882855ff6c8da8862438e6e58a3369c9891f37ffd));
        vk.gamma_abc[186] = Pairing.G1Point(uint256(0x2dca04d596a4528403a72aa89a78293734aa3c262084805909df0381003f178e), uint256(0x0850e14291ee0d7aa30f84c553ed15080571b7a62e2b373e43bea64ead05f537));
        vk.gamma_abc[187] = Pairing.G1Point(uint256(0x120069c5ab9d9a42b17ec98fbd3785ac9f2da9c60dd7ab8597f21ecfc1ec90ae), uint256(0x199a634d2b589060b4da5c4e4c5b8740c37dceb8d06d2615eef15dd6ba518322));
        vk.gamma_abc[188] = Pairing.G1Point(uint256(0x1b9ccd5451644449a0a0d011ee06f5f131531e8e69679f96a6ccaed2942c3add), uint256(0x16169db6e9757a04d6e2351fcbd34b82db610cb7e9a88dc1479443deecbbf84e));
        vk.gamma_abc[189] = Pairing.G1Point(uint256(0x06489767be0e9e7485faa014d33c5d049f8677495046166eee3057a671dd7978), uint256(0x1471857e487b31de0cbc7e655748e809f4e033f34d30ae4e6839a5a3966b1cff));
        vk.gamma_abc[190] = Pairing.G1Point(uint256(0x1b2fbfc1580d606ac873f3c4f4c44de2099509619b5f5d4355b9b98cb5bdc3f8), uint256(0x07c2b0722e39f4c0b97273323d82f0c26cf38ea37263ce6b6cfc083281e9f7fe));
        vk.gamma_abc[191] = Pairing.G1Point(uint256(0x02eef47c7a179ade1946f51570842aca454b87314969fc55ed2d34b6157ba7bb), uint256(0x0f09b3ad29c83c9b8d8bba917c8f9731f16699e659fc622b2656e4f48576b852));
        vk.gamma_abc[192] = Pairing.G1Point(uint256(0x0fc8470ca18f9c78411d015fde01fefff63121e6943bd737bd5942f128351518), uint256(0x2153accb67b90af4142ecce890fe0607a3912268865b5eb53099cf05fce92b8c));
        vk.gamma_abc[193] = Pairing.G1Point(uint256(0x132a01dabc7acb820c65110f5e0f45700d9a4f56bc83f09a9e9aa22ae124399b), uint256(0x16e4d24892741b32dd9d44fd287ae9eb2cc2fe923ea5ab0b5688a3e9b501390a));
        vk.gamma_abc[194] = Pairing.G1Point(uint256(0x14351207d47bdf26aaa9a7663beac9f739fd8767f404598174c8df1f50b55209), uint256(0x1a1d18db2e027da1f4bf13429b5c816aa3ac7f50ee494ffbf7f7dd3a64966d26));
        vk.gamma_abc[195] = Pairing.G1Point(uint256(0x081d3cfff143bbdc6a6f6ed16357c4592bfe7ecfa1a31f9bb2705c45a5700839), uint256(0x2100031cadf90d9e0828ef5f016f994d0b03c1c2cad3e5af1feb7e7e51e010fd));
        vk.gamma_abc[196] = Pairing.G1Point(uint256(0x1816e62210e35e6813ce3d9873300e3448072e26d16946064e0e3f3f73f176a8), uint256(0x236b63cd3d05455338a959b45de4198ffb6612e97e52c0c56354e16d206e437a));
        vk.gamma_abc[197] = Pairing.G1Point(uint256(0x085b32d2555f7f676857254db4934be5895899d44783b53a339fd93e4bcfe7fd), uint256(0x19df3d15df2eaba379d0c1e84efa218526a3485151630cd67f9029e0de391bc6));
        vk.gamma_abc[198] = Pairing.G1Point(uint256(0x2fd7f8d518b046884cdc35e4a0f523143c51b838a1add2733b2d8a6e1fa7380f), uint256(0x01a2ffda06815ce867d66e0f3c56f4e485d0933e320165d14530cdebb8ab9671));
        vk.gamma_abc[199] = Pairing.G1Point(uint256(0x20e3d74b1de4efb5a9f1268b73676ea7640376fd3e287554d82ce560deedf91c), uint256(0x2b442ceeab2aaa64ec201cb3c7384177231e9ca00a4e810fae40a455168bdb22));
        vk.gamma_abc[200] = Pairing.G1Point(uint256(0x0b0e0212abb3256eee2937d27c5f6f46b931698e22c8271a26f79622a640db26), uint256(0x2b557287710484638a54badb1d93fb73973e171352210060aefb6565779ffd7a));
        vk.gamma_abc[201] = Pairing.G1Point(uint256(0x0bd5ef25399b15560c904fb28438d4054edcf884d62a7eb0fdc3aa1a355e0af9), uint256(0x019b91a8551762bf022b5d01a83260aaa265f4e9ef7722e2f0eb1d389ab46450));
        vk.gamma_abc[202] = Pairing.G1Point(uint256(0x03fa5272e400b0a4c068204ffbf8bffb8d1bef4fe63db0607c658156e7831d44), uint256(0x0022b8432768c7a38bf1efb06293bbbe94d092a309817f6d7f5e373f5c748339));
        vk.gamma_abc[203] = Pairing.G1Point(uint256(0x1542983ac395f126c869152c899a37a0da5a901bd7aea68992c45ed317f58520), uint256(0x18c466e32e847bfbc9362c0bef341ee2bded78e6070fd6d16a1abd9601e165bc));
        vk.gamma_abc[204] = Pairing.G1Point(uint256(0x212eb8510cf42af8025534d0a6ceb59f539af824e43a6b8c36bda4df26d1eebf), uint256(0x21953f2d87b415c91bcce016607871181f8927e1975e68195e6141dab20b5507));
        vk.gamma_abc[205] = Pairing.G1Point(uint256(0x0163f35d1367d3b8f6a64f95d71b9e76fccb935f3c8862bd5eaa6fca6cfc64f7), uint256(0x2f18ab34fa74c84f65169bf664c3b4cfdc8e741329c6cd9d1cbb172da1e9cc95));
        vk.gamma_abc[206] = Pairing.G1Point(uint256(0x2a01331744c80c73e891c45057b4688eca2f3c3bb51da0607af46aae84974c7b), uint256(0x1c1abe2b66faab703c7ab672eca4cd050cc57160bf4e8a0c6009c0cbd13370e8));
        vk.gamma_abc[207] = Pairing.G1Point(uint256(0x0a59040e39d1c1b102b9829f65a601dfb7370a299727b61dcd563cdcf45177f0), uint256(0x1fcdeffcf36390304fb1facbd76500b4c909f395d07ca30e7909b5c1d8e7f440));
        vk.gamma_abc[208] = Pairing.G1Point(uint256(0x21446bdc17a6300f6737b6af0c096cb4b69ffd9355428a419ae8bd4e002bc43c), uint256(0x052040df146fb1c8193eb71ba0a0a9bb0b22fa5680d10830392d0a2312e91851));
        vk.gamma_abc[209] = Pairing.G1Point(uint256(0x162df55a81c798dfbff7a2660b902f4d9e2691bf18a8541337cb6f4cd77f414b), uint256(0x2245a8427579b3492b51a188b5b6ff29cf254d2a3aaec7cfc7e9cfce3904d66f));
        vk.gamma_abc[210] = Pairing.G1Point(uint256(0x2b201dc8da7fa5b0d802edec506b83562ba723577597c6786a2633f1e539d2e4), uint256(0x2af98048e94e07c1a87ae27a9f28eca2586bb0d9142a0e54725be67fc9adce06));
        vk.gamma_abc[211] = Pairing.G1Point(uint256(0x2f7c038af85ca2947d59e1e43e1180d8e41e8edc0b8283a9fc36de51ea4de83c), uint256(0x2f8f885d97b71f32e3cf628ec754c44e73c79fe25754573b8150d06879789d01));
        vk.gamma_abc[212] = Pairing.G1Point(uint256(0x2f610109b55487d05fc2c79ab709371cd81c2eff56b0c298d29c6f5576c8f01f), uint256(0x1d012b83056d6cae5e022ac0594fa34f781d7e22ae00af21d329493c30ac98ea));
        vk.gamma_abc[213] = Pairing.G1Point(uint256(0x2a6c9bffcf066f410318af0e78cecdb5c6ec495c272d91cc1e83a516234fd9e9), uint256(0x235e3b3efdfa70b903b9567e954c6204a17de9b6ba8d65c963a0de4bd35135e3));
        vk.gamma_abc[214] = Pairing.G1Point(uint256(0x293de3b0b586a14567396150932a370763c25bdae208ae406708fc6d5dde2a2a), uint256(0x26c3bdf4e1f76967a2bd7da75782361264ad6c86b7eb6fbdeee4b2a5ecb616c0));
        vk.gamma_abc[215] = Pairing.G1Point(uint256(0x2326e8de16e20728b7f4e3f6ffc9b8e3f297390f3a7faa0f853f4f6faec075c4), uint256(0x2b5d03e6ae6e118146c511126cf7e111a6425e3b981d874db6e0a57761b903f1));
        vk.gamma_abc[216] = Pairing.G1Point(uint256(0x078a287cf3fa1faa436182a3ede2c09d93b3ec6ca7eed0f83e8b8f945cb8e7c8), uint256(0x010d644c459dfae79cd1a7a9fad0d067e73ab7edee6beaeeabf9d830e177ddb0));
        vk.gamma_abc[217] = Pairing.G1Point(uint256(0x1ae60eadfc2a40c45e84259cb595f575b16307a5db6617920652b0b350a58a67), uint256(0x159295507890d84e63ac3ff697211335c9b76cce678ae77f8e318b9e4f02635c));
        vk.gamma_abc[218] = Pairing.G1Point(uint256(0x02cdd1eeac21662f823613a8b22cccc60afe9ed33eda907004a081e7182ba691), uint256(0x192c4f99da24e194c614e5ab74617abf3c7690242092ac92be11d41fdb9ec205));
        vk.gamma_abc[219] = Pairing.G1Point(uint256(0x0badbb93588367bf519455e784dec884761d2282e3944df420862a3ca2ed763b), uint256(0x0d7541a935ead05283be313307eacd46e229482b6aebe72e6e8199cc856dff41));
        vk.gamma_abc[220] = Pairing.G1Point(uint256(0x16132951fb140c34d2b49a3ee41eff5ad16d998be52ca4b91b7f05f90e73ae35), uint256(0x2b4aafd041018ded63c07be497b6327c7b07e45e5ae1c6003ace8352560bec5e));
        vk.gamma_abc[221] = Pairing.G1Point(uint256(0x1c730528a3db8df3b252baa49b3555d8e933152092bc60f4a7d8896a7773822e), uint256(0x1ab933f669b92b39a5491b1e47facc3f52348d874ccdc04a8549ab2574757bb5));
        vk.gamma_abc[222] = Pairing.G1Point(uint256(0x239e6a654110cce27e21051d9cdfc4dae1e98e095dbb1c7da0b1c3de01f8fc74), uint256(0x01d0968ced8523d216686f60dbcfe59d0f2f66ddb18a97f061151b3e3685d93d));
        vk.gamma_abc[223] = Pairing.G1Point(uint256(0x25ffb24238714740357cb0fc779cb8603791c608850c6a77a68ed3d72541f6ef), uint256(0x274a13a40466f57d909a617bf17dd3c381b0c687bc6f2486c402a472d6d6183e));
        vk.gamma_abc[224] = Pairing.G1Point(uint256(0x0846f81b8b08e0c3a4ea1d4ad84a97ecacd11e71290c9334405853bf0ffaa24f), uint256(0x2a46c6f28bed9e4d6cb47b60de247ef348049d9592ed94cd314b55cbb8efc17a));
        vk.gamma_abc[225] = Pairing.G1Point(uint256(0x18b38c6ae98770f19190605d772d78d2b2965d48bbdead72904413c7bed5d992), uint256(0x00507e4636357543d1aabfbebcbea91b87843a74d6f0cf22f96655ac105e14f9));
        vk.gamma_abc[226] = Pairing.G1Point(uint256(0x13f71bc5163ff1d1bea4f034d527523460a1497b6a731f497437003aef18157a), uint256(0x302f1518ca2d57c73b6042cf540ac0cbb9458b52b8cf6bab0c798ca38a48a3bf));
        vk.gamma_abc[227] = Pairing.G1Point(uint256(0x1c08c99aac105b0aa9f61762a0838a0b0312dda5598600aa39a4c64ae669b2ba), uint256(0x1aaa8a93fed70452326c3b04a99d583cb2b45a3463970182e34461f6e62f96ee));
        vk.gamma_abc[228] = Pairing.G1Point(uint256(0x124854915989522d50499c011331a2775aa60cf8e4ac653a429c4552c6a19ec9), uint256(0x2555a884b95aaa307056f0cb1d8d5412301a5b1ecf3f6b04516fbecd52684a58));
        vk.gamma_abc[229] = Pairing.G1Point(uint256(0x0c940ed04abf16f7b80b0a46cfb2d6a6e0de104684a1370aed107d14471b45f9), uint256(0x01e69a4c517596e32a70f541a07b5afc54f86108549b7693f6fe3cb5507ccf1a));
        vk.gamma_abc[230] = Pairing.G1Point(uint256(0x1c69127933f03f9c54a0841f4a8133bc6bc9389b2f3405eb98c7903d429afba6), uint256(0x26d592420a2568f61a01c700be9e870cb822d8f2f3b3936ae46ec998a194c40b));
        vk.gamma_abc[231] = Pairing.G1Point(uint256(0x071dbeda8995d01c9b89c97fd01ac77365e69ac853490792bef1083c0ec9382d), uint256(0x2efce065b9bb5584c2ae1de3b13e7bcf4ffb4908ecee29971a6fee96605ed924));
        vk.gamma_abc[232] = Pairing.G1Point(uint256(0x29de6b2259c4c0c764b3b2d14d4d67d59dbc0eb83985f0632330754ceca70707), uint256(0x1d72fbedc577d9445bb7612bfb6096184ea092cfd6656d6a07ed65436b7cceac));
        vk.gamma_abc[233] = Pairing.G1Point(uint256(0x007cd6e0c952a3e4e15c3f58b562bdca29cd1be0a280a7c35ba62a0872033cff), uint256(0x1c5e50d3ca25a7a27002bd9896c0f1f9955fad031d1fd5ed228f9e49d4819816));
        vk.gamma_abc[234] = Pairing.G1Point(uint256(0x2705b123d78b70c0c03794a234129cd94f6282fb047ed856ac8ccb3d58b3072a), uint256(0x1f7eba3f30a9c9661f68d6150fa0a4d6a733eb666ab95a9e62483cec2db288ae));
        vk.gamma_abc[235] = Pairing.G1Point(uint256(0x14dba9b77de38c576b4eab3c0bc26799b9027741ff876a1bfbad91373331bd6e), uint256(0x296fe95ef5bd55f6fd263abe151f3c197931c33a54546975fa599fa93710c231));
        vk.gamma_abc[236] = Pairing.G1Point(uint256(0x28f5bafacd3ebb3f4f2a985b9adbff358907f30ec64d5a9cce1ce3b20f5a1849), uint256(0x18b5ca697cc32d71cdadf87483c53c875697b105965e90f3263c969d5a1652bc));
        vk.gamma_abc[237] = Pairing.G1Point(uint256(0x04eb65bcf10fa0177b190771114f48bf97d3822a0e84a424722ed559c057401f), uint256(0x12c0c1679b9208ef49f69e1c6a772be4792be7cccdfa31bb6fcfa69c2e9e8f3e));
        vk.gamma_abc[238] = Pairing.G1Point(uint256(0x1a9d291c8f71010d23830440e17fe9d6510f77e7d56da07811b7728c42b73f21), uint256(0x1126ec76639e399b411a7c07d2f714c269649f76d215de057bb95c7c387d5cd1));
        vk.gamma_abc[239] = Pairing.G1Point(uint256(0x0d82512cc2cf2ec5f728a3002eff576ec04776de36b64abdc4f72fcdd772f0dc), uint256(0x2ba7ea7bf2cc3c31e8d2b139e5a6a50fe080cf336fdc38fc350fa7e11581e6a3));
        vk.gamma_abc[240] = Pairing.G1Point(uint256(0x1cbe5b34bcb01a86e5ee8866ecd95de674eacee25ca1f631d70340028d15b529), uint256(0x1652b83e5b29de4027a66f3afbfba6b63192d1780201baadcdd2c62304582faf));
        vk.gamma_abc[241] = Pairing.G1Point(uint256(0x2b0b67e0f623eb68322eaa27a133414ca10f0ca27f87d9818ffd9f73b65f2ac6), uint256(0x2a4b1b20a2d204c9ad82831eb75c366544fb24df08d905aafcecc0b48235469d));
        vk.gamma_abc[242] = Pairing.G1Point(uint256(0x0947fe0d542daa752f55f65731447ed3cad4f3afa64722d158bb314c60d3001e), uint256(0x1fa99c8c83ad3f7e5ec8e55245004924323a7e08d37978504bfd245ec60ee7f6));
        vk.gamma_abc[243] = Pairing.G1Point(uint256(0x2af6b2d76d8ca83d6edd8de856f5ede7f681fb410236b674121ed4da97823afa), uint256(0x18cb6f9b32389adffaa13215450b5afa9a42e68018e3186334d01667db0a51a5));
        vk.gamma_abc[244] = Pairing.G1Point(uint256(0x17ecd0bc8c0633e01c5a5b6688307eae2b7f9fbc14ecc2119617102e3895b711), uint256(0x08f849ef5992067c0bfd84c2ad8b12d9cecf47f4d9126b5685a3b3d21a0a2cad));
        vk.gamma_abc[245] = Pairing.G1Point(uint256(0x243ce933817e3b971c562dd780f05bfb3564f8130edd0148e942c1bcd4664273), uint256(0x0f54646586cf045d1a1b45ef689a5f38fad3d91bbcdf100124401f8d6b1665a4));
        vk.gamma_abc[246] = Pairing.G1Point(uint256(0x0775b1908fb02b4cec7ffc78d184901b2d307d6817c4c827d031be8919ae5fe1), uint256(0x02157d7695b87e501a04b7372cec61bab8e5174193ed59163a6469f98795caa4));
        vk.gamma_abc[247] = Pairing.G1Point(uint256(0x077bd31edf5007976259735aad5b0936d9ff80f50f903e93e7ab661747af8f0d), uint256(0x24081b3d84e40569c1c79595b9aa8f75f44323aaae4805dd250cabb2e0a4ce32));
        vk.gamma_abc[248] = Pairing.G1Point(uint256(0x1445bee2d7c8c9fcf50b305f2c6cd081df0a2a8dc2cfacc7174180988a4d1db4), uint256(0x221a6112a99aeb69ebd8977e111143cd34adea092bfd978090875fa367f1de42));
        vk.gamma_abc[249] = Pairing.G1Point(uint256(0x011eb75db76ecc3da48c4ac07392b687599ebf978051d33a088ff50c99d8dca1), uint256(0x186c09710a7e5b8057262e3076ccf788144329353c7a89846f497980677e432e));
        vk.gamma_abc[250] = Pairing.G1Point(uint256(0x0c98ead1934cfbc632f440564007ada0634dc61ee5b00c3abf126613257c6291), uint256(0x2a2c357cd2f67f9cc7dab469d8d72542cfd8b5ab519b60e6b76492a9cbc72654));
        vk.gamma_abc[251] = Pairing.G1Point(uint256(0x200775c8df859f471f874b282a422d34cc4e6de569f0687c67ada251373cc67c), uint256(0x2affa6174243a3664fbcb1ffce361ea9fe6362e890c1c08d6786128687b22ab7));
        vk.gamma_abc[252] = Pairing.G1Point(uint256(0x1a423ffc2fa26b827cb80299d1a7b7f4cf40a4e5f145945efe9162d63eb43f93), uint256(0x0c4e1512f31739c94355c1fe692802d7a63ae3957b4f2f678b4e115f7db29afe));
        vk.gamma_abc[253] = Pairing.G1Point(uint256(0x256e189c4eca1a273abadd589a579bd51ae7f0ad8fdf2fa85bc60314f6f6ef14), uint256(0x14352093e1f3a1b6cfa76d07f8bb185a75957e6ac70687907151b9e0e5665eb8));
        vk.gamma_abc[254] = Pairing.G1Point(uint256(0x2705a264a2e3a4d61da323a6664923ac2f57168637fd1cbc425a3c50007755ac), uint256(0x0ecdf05b5b8ad0f5a1a1537bf1fd98b2a117cb9c177eefabbe099cb8828c6240));
        vk.gamma_abc[255] = Pairing.G1Point(uint256(0x06b9e3c0856133f4f4ea87dc1efb52547314699bdc743adf474bc56840d520ed), uint256(0x169228cc9f52297533523d5fd982de9a95563b64c6ec83c9fa8f7bd13591c613));
        vk.gamma_abc[256] = Pairing.G1Point(uint256(0x22f33fc72e44b65e582abb996f203f3275ce44263275c3ddf5d56570c322cf4a), uint256(0x1b383666563838789d349a07edc325299480c25439c951ba5977849b8ad33fda));
        vk.gamma_abc[257] = Pairing.G1Point(uint256(0x1b16d6cc8be0a01f7b7adf224b6677080577fc49023a097c23d155ae58c02c8a), uint256(0x1f43309367afc4323106d14d01aa893b67a15c179488c6302af0f84144ff0daa));
        vk.gamma_abc[258] = Pairing.G1Point(uint256(0x1caafbdc962311e305c8505bf23b65e2d1b3601cd7f0a941f71fe8bd4498be4f), uint256(0x21e13905cbc78444ac8ea63fd7e11270f69f5d4fd6a2711945ffd6a95df88b63));
        vk.gamma_abc[259] = Pairing.G1Point(uint256(0x00973436a0febd35243a084bf84001654ad3942267e0cd544425f5cd2d9d29de), uint256(0x275ff71be56e48cf7f2215f4b9caf3bfafa166423926f17307a33a11ae0b449a));
        vk.gamma_abc[260] = Pairing.G1Point(uint256(0x1cd63c592e25eb1b5fceb56a620f6aff16595a44efb98c5ed5d66ff8832f7f66), uint256(0x2424151bba9979e22d72757802fd5c541a7969ac145683a6e9524451458c36ec));
        vk.gamma_abc[261] = Pairing.G1Point(uint256(0x1a349e1e2f7b9b5d9e93b2dd177703a6bcb360d853e394b8eab7ce90374e2d85), uint256(0x17623e90d3e2007747c0fff26c922856164c6d2324b4777a5068c24fbca359c4));
        vk.gamma_abc[262] = Pairing.G1Point(uint256(0x1b371379ee65941c13187e152054f56c72255e9d87284d798499eae517dc0bcc), uint256(0x2d1aa0a339112765ad58db25459b000c6400870227b7656c6edf4efb54c9a4fc));
        vk.gamma_abc[263] = Pairing.G1Point(uint256(0x19cf6da989df85731381426354a70c2507840b5f3fe355f8faa20cefb8994af1), uint256(0x2adb60b03681a9d96b4ef61f1b2125a2f3cfe6d226d1a64e707225c952b5f7e1));
        vk.gamma_abc[264] = Pairing.G1Point(uint256(0x21c8fc9735d6f9cf3955b5f6b7b92caccad30158168a30515b232e88481c4192), uint256(0x1956cc993799a40b04aa1e1ed3295304346165121caf2adf35cdf8ceeaf33085));
        vk.gamma_abc[265] = Pairing.G1Point(uint256(0x1446eae65483e5287cc94b786f363f548f7bf021ff8c47a06639e8d83eb2a344), uint256(0x06edd87550499539f15349c27817711243dba777b02e43330cf1afcd365ac119));
        vk.gamma_abc[266] = Pairing.G1Point(uint256(0x22f79614dd6c6430752f43b5193c8c7d0bcafb69984f499803a1b85d2b251201), uint256(0x10392b08153532fa4cd49408434b258f9cf689d38f089dcf5835fb7829349ec4));
        vk.gamma_abc[267] = Pairing.G1Point(uint256(0x1f864ae24eeaf2bd9b7d15f9a3be4bc675ce337be2166c6036febdf8bc70b293), uint256(0x26c4ecf0df7c2c6117dd655d118610f6b3c03309605be98b93705fc14d5b4005));
        vk.gamma_abc[268] = Pairing.G1Point(uint256(0x177337d4f3fe368c3eb87a8bf98f1f9024b7243a0a52c332d52fb36057507fb6), uint256(0x115195c1f76a9cadce0515425aae70a5f4558f6dd01c5940942dec1e45776b06));
        vk.gamma_abc[269] = Pairing.G1Point(uint256(0x195be20e29a48c61ae657b973dd9423334c26d43dd56f9d1dca0bcdfa93cdff2), uint256(0x23ee7c1d7bbada6a5f562b149cec194464cdca935697bc97d5172d6dd8fd8baf));
        vk.gamma_abc[270] = Pairing.G1Point(uint256(0x1a6d89026d6d4a32c90690eced9bdd6656cec4a23c26b131d70f19d97203fe7e), uint256(0x20cc241fa49306fc437788bc69d0ba22e2835842ab08ba67e2d81518eb629521));
        vk.gamma_abc[271] = Pairing.G1Point(uint256(0x2b38dd8fed4a8f88bd96c244a35c118ff2f2004de858b101a3b1b92830d453c7), uint256(0x0d78551c09fd2f08566100a921c7891a0dbabbc9865a740f460822a3d881bc64));
        vk.gamma_abc[272] = Pairing.G1Point(uint256(0x0ea2e2df4ba17a28777d4564e406e11602784438e8be93c262ccc7d589053a51), uint256(0x30505c8f15aa7a3bfb91b991156ddbd13774b2eb5190366d539d186593fa8372));
        vk.gamma_abc[273] = Pairing.G1Point(uint256(0x0e66ea620df605712e0d0010f0a86dde2aefd40ac30d74283a66eb42a24b855c), uint256(0x0294635dad95219eb3c5148853ce12740bcf74b60afa286842156a1a1b5aae60));
        vk.gamma_abc[274] = Pairing.G1Point(uint256(0x2731262a61d16ac481ada10e1cdc2719cc5f74b334c9750785a9cfc35f2f97f8), uint256(0x0b52a3df6f895d5ce38952f855cddc4544e77b4ba6ffa07eb2d1f88a0754c994));
        vk.gamma_abc[275] = Pairing.G1Point(uint256(0x1f2d5d0ee233833040eec21ff9aca7155907c4ed6db45ad24f82e3b3df4a39db), uint256(0x199e9270fdc8921b697175b3d813896ad29f2cb3ddb01904bd05daff3cb1e163));
        vk.gamma_abc[276] = Pairing.G1Point(uint256(0x1da233097d1cd8bddf1a33b1f855c3ea1799e758d1484183b1ce00c9befd2362), uint256(0x263fe334e38543ef7e0e86721ce8afb5cdd01c5f727df1df8004ec5b3cbad983));
        vk.gamma_abc[277] = Pairing.G1Point(uint256(0x0212649452ef04d150d5cf4524a40c7eff6bc85c3369ea1f348da4eec44fdc2f), uint256(0x022c81cf1b4aa071b5399914782fcc3bbb8892f7cb7083884dadc5b752c6cf51));
        vk.gamma_abc[278] = Pairing.G1Point(uint256(0x25bdbbbaa2cffe605efb4d02a3dcb4fbf9b9cf1ac01ea2e9804f57d34ed23509), uint256(0x228cd883b18cb37ddcaf0ce53824c2ae8d3bfde387592981ca32ba50be33e969));
        vk.gamma_abc[279] = Pairing.G1Point(uint256(0x24991392cbd29828b2475178d8fcf266aa5dd6f3a07d87c7924cb4fd52801474), uint256(0x29312896a3c6ca5db74ea7df27f88a2ed6602a9ca17c7055843e7af90ea6677c));
        vk.gamma_abc[280] = Pairing.G1Point(uint256(0x15297dfbd6b4155c0cf09c050573e0b0451b95c13499717666c07c2e43105b2d), uint256(0x2c1849543f511cb59dc6fbc4ba1506a1c694039e33b60a4becf19dc1e219720c));
        vk.gamma_abc[281] = Pairing.G1Point(uint256(0x265e28cb247aac16c077a1d0b7f1dacba5b0a8c63071bce41d070698ddac8f85), uint256(0x2fb3b7d4bdb07c8e0b9628213336fcc854329fcbc265304c3843628c1750787c));
        vk.gamma_abc[282] = Pairing.G1Point(uint256(0x2756dc3eff7eb29f8132f857c98c6d86a173851dd2f9f8820e8373dd1621d90d), uint256(0x251796b19bdb0d5980a2de982f5d6565e780c085dfdd2f83d1705cc6c90e6395));
        vk.gamma_abc[283] = Pairing.G1Point(uint256(0x0fb65b1df068cb5a6cf4e693784d0ae8cec9b3c659aa93e4a18ffebc171203f7), uint256(0x1167104de2b83bf7eb4db394b8bde3163ba19fc4e5fa82097fa31a06facc3a50));
        vk.gamma_abc[284] = Pairing.G1Point(uint256(0x2942f26fe8eca4bf606d1ad3de14c2ab1ed297c49934f485c8ccaedfbb8df81e), uint256(0x0e55db7ffef3cf8369980bbee43d6676cdcd012054ed8acf3531d8a29a6ff3fe));
        vk.gamma_abc[285] = Pairing.G1Point(uint256(0x1a3671ab44a5091a810639437b33e523fcddf86baeb9cd3a5b3f05bc83f3d868), uint256(0x0a6f51304bd4c272c002aa8ee89bf6dc9c11b22817e4396b4ecd5ecec39103c0));
        vk.gamma_abc[286] = Pairing.G1Point(uint256(0x1b6a76e2c4396d30048679c1b836e13a509e1025f2e673cdd5c23920550fe16a), uint256(0x134d5f72462a10ef3fb198d669cf35abdd942a46e378b0092a3c33a0ab0c7fbf));
        vk.gamma_abc[287] = Pairing.G1Point(uint256(0x1db38d675378d03136dd7566239aa270526c5e489226d2c97656e281127e9d37), uint256(0x2470a43759c1731c3c74fba96e43131f392ceb0f2109780a5c05e10f017b2bf2));
        vk.gamma_abc[288] = Pairing.G1Point(uint256(0x102876481ce0e7fc6f24229eef233c3bf188532c33bacbddc28bd35b20cd8846), uint256(0x097f03f58654caa3661a36661745c6fe120782881d1d116f6afe71e388a326d0));
        vk.gamma_abc[289] = Pairing.G1Point(uint256(0x1b86750954caa5a51a518835f33457ef54f56b093fd0dbbf12aad13ae869a389), uint256(0x24d817b5186e36cf7c1304f175d4de5edd8e5bd6f00aa06a1a0bf7cc9fabdf10));
        vk.gamma_abc[290] = Pairing.G1Point(uint256(0x030a1de3516da4d6e9d90eeae6d93f89d3cf4fd6a4cebd7c1c008b738432f076), uint256(0x0dfc916037339aed72229a269d7aef3b3f47bd531f9ca0d509d3530fdcc6ccb4));
        vk.gamma_abc[291] = Pairing.G1Point(uint256(0x15e77bea43318a9aa01001597300047b924604dbc6cb1088da8e9302d2dd8883), uint256(0x0c6585c496635486d378e8fe9065e9ac28395e0e7f56d45eb11c021c1d3e896b));
        vk.gamma_abc[292] = Pairing.G1Point(uint256(0x18f09299d77fefab81751e307dc1770ec98d1a47c50f6321a42e7a5cd914e35e), uint256(0x09e89b754c3e596ed9681697ceacc9b4ee91df8ee8eb9b8b28ab923020123ab7));
        vk.gamma_abc[293] = Pairing.G1Point(uint256(0x1e32ece68c437b3873fe0f0a6e64bc8cc0fa1472f17fb7e32ad8a8fcf3958a83), uint256(0x1f918a9f8a2851ec988726cefe7fae8abea5ddede702027f383bc82908dbf48e));
        vk.gamma_abc[294] = Pairing.G1Point(uint256(0x2ea8ae4cc8d0c979d35f7f642d17ac3c55f1a301749a787a467e37a1ebb74b82), uint256(0x26709107b4af920b1c951554f7f8c2b3986f6760e169b40096f513ad310cb79a));
        vk.gamma_abc[295] = Pairing.G1Point(uint256(0x181d5a6e81d658dc8b1254c695322146e70df7f0d6ad632be1989acd38a0a753), uint256(0x29b559593a25e9d5effd13c7aec0c78971256621de4fbb4adbd9ef159c4fd032));
        vk.gamma_abc[296] = Pairing.G1Point(uint256(0x2eeb96f25af275c973409791f38f957e37cb396d91d2ffae4068f60036dd6544), uint256(0x12bf652b3c5e99c99e025c8634d7f76468978e63c9fa9c6571e8b9430405c738));
        vk.gamma_abc[297] = Pairing.G1Point(uint256(0x20393cee2db1fe7a31e068412a7a4d0732d942b6c348475d043a91408cdd2575), uint256(0x11ad7f734e71c1cc73f257e5fcfdb5e27854717939abec634b6f585ac67dd77f));
        vk.gamma_abc[298] = Pairing.G1Point(uint256(0x11867d5fb64979eb40c9ec5845deb4306affb06f981e2df6b9fb3b6112f630ab), uint256(0x27eae6ca9aeac4a855a8e79c303c3437dd7c24dba5557f38b7be9a2a11b605ea));
        vk.gamma_abc[299] = Pairing.G1Point(uint256(0x1ff1896699ce6f33135d9798d7618cedc277f03f9e57852dda9676be76634bce), uint256(0x2ec42a6433d9ded0bbff1ce3008bcd699d8e8bce16d22b1fbad4a568aab6abe0));
        vk.gamma_abc[300] = Pairing.G1Point(uint256(0x2abf77f488a7a1e330580c99bd7677372baa39ff30b5d8a03e88a98cff09832c), uint256(0x0ec9e76456ec7d5359af347e5b08a7001860593004a30351a08351ee66d66ff2));
        vk.gamma_abc[301] = Pairing.G1Point(uint256(0x2f90e739b61fb1f33248556647b611a02e624f3179a2a4b16d2a9989c5d80443), uint256(0x1fb44335d57cd366761c5554aa80694b24134ec4aa1cb3849727131a0e1749b7));
        vk.gamma_abc[302] = Pairing.G1Point(uint256(0x0f7ca1a4b35769e598f7402a1f54c9e06e473ba25eee3d3abd4596e69d5c8316), uint256(0x303dbb27e6bee1972b229ddf118827113ed4751076f76c6c6e6c73b413ce4cf8));
        vk.gamma_abc[303] = Pairing.G1Point(uint256(0x27ae8366bf2cfd9d129735b1af9bbd1ddc20fb8f9330ab8855a1ffa3eeaca501), uint256(0x0c9fbf0299b8feb04af132c55a7eb77709835defeda0c034f32bc135b305d87f));
        vk.gamma_abc[304] = Pairing.G1Point(uint256(0x08ea3047c97df5ec64cd3f15f4e5bfaa7fee5b06b379ce492c37c5c8100ae123), uint256(0x285516b62a59d27108dc1e2a994a6100d4b11ee90b14a9905562fa107ddc9598));
        vk.gamma_abc[305] = Pairing.G1Point(uint256(0x297229864f62b5167b9b2591810ed778e939aee56330ed6d96cf5425f9e930d5), uint256(0x0dc7900f79052e12043761b765d4468ca8e1ac63476d8565e4574ca4c9fd9155));
        vk.gamma_abc[306] = Pairing.G1Point(uint256(0x1d739c3cb9d72693f0bab1b2e0c45acb1e6bbc111b40e098888638ef8ca58109), uint256(0x0cb85eaa89ef911d0932e35e5ba73fe709d2f201fa9593aad5a4212135db816d));
        vk.gamma_abc[307] = Pairing.G1Point(uint256(0x2f151863b46e3eab795b65007da06297cd4d31635cb297cc2eff255987e0cb03), uint256(0x2a5b3c8bbecf5f6e34298629e6783eeed02452237cdf3d4a11e7aec8c86eafd8));
        vk.gamma_abc[308] = Pairing.G1Point(uint256(0x177ebe92dc3ba54327d6b3404bdc8903f4849117aa54cf9eda5b0790635053f6), uint256(0x29cfd4f667de019291501b9dcef722e18387a2801e995d3f9d38213cf7e46fb4));
        vk.gamma_abc[309] = Pairing.G1Point(uint256(0x0ac8934ef170bd10f39948ff66f7870c49cf6fe5d036dbecdc58dc1ce805b15c), uint256(0x1fb334a433d8252cb9eaaef3adaa944ae9b4adbdcc7582dbb6541cd1f877c1d7));
        vk.gamma_abc[310] = Pairing.G1Point(uint256(0x2ef77ce1f99df7633ffba9d146f93f0814b3c387f46a4c792a5e807a4808b3e0), uint256(0x0234c45f9410e1eff0cc4a7b499fc95883d900e5514fdaaa9bb8720810838117));
        vk.gamma_abc[311] = Pairing.G1Point(uint256(0x2b1c6b83b5418b0f2a5bcc5f69e290e1f49c26872aa7509dd399df8eed5c0c56), uint256(0x267e1330413e88294b59b3f2240acfcc33ce641d9df05a4cafe5329b488baedd));
        vk.gamma_abc[312] = Pairing.G1Point(uint256(0x0e76790fb697fa9c44b8d90471891948c45557bcecb6b9eacbea80cc7c42e892), uint256(0x0c75283ccde708aae60802c406d46af18b67fb0604f0d58ff7d0367ffb45d285));
        vk.gamma_abc[313] = Pairing.G1Point(uint256(0x21c1f9cfadd4686c67ffb3e47dec4e88b5711f4905ec06f5e27f5c2af3260fdd), uint256(0x0c4c338670b73e726f9d909bc71aea6901a57e646f63fd6a1688d1a25177d046));
        vk.gamma_abc[314] = Pairing.G1Point(uint256(0x2c8a2d8290836e349d3b09e1441a8d5de890130159e59c39042b52e7e39547aa), uint256(0x04f0745914dd263d85dc77e8a77df34927944593cab54a705e6e2adff02c1c1c));
        vk.gamma_abc[315] = Pairing.G1Point(uint256(0x261d1c3da9a9248de054e2ed824431f6cba70f30ad0d1b85eef7468048b137ed), uint256(0x15ff6eb8199a90a3fce355bd365a96d865841db37eb516657b46e1ef9102574b));
        vk.gamma_abc[316] = Pairing.G1Point(uint256(0x02455be80442eeccb13ff9fa8b4f014760e7f77572d816a9d04e3e133c34c315), uint256(0x11ea7f4b14a914fff801373a5848e290d5cdbcc7a325018665a62044d7726658));
        vk.gamma_abc[317] = Pairing.G1Point(uint256(0x00e9f2de650785ae592f848d83f6513a0e29ad46e75b58ca9053c09aa4b9d844), uint256(0x20088079e9cbc73da1d30a2136ea382d1e5088e7deb32a5bc43e7e95b831f518));
        vk.gamma_abc[318] = Pairing.G1Point(uint256(0x0c2b2fd697f26f34e13a8efe1efff09a9106f2f8de48939a75f6fd624b0d72cb), uint256(0x1737ff293e35d57fb11984cdb63c6e314699fa1789a9c985deafc1ff41619051));
        vk.gamma_abc[319] = Pairing.G1Point(uint256(0x2550419868405d7812e7c5849dd6e54c6660a15bfdab0102b0a1b53cd7a459dd), uint256(0x105d7c6df4510db8058a25367f41ccfd68dba5f37d57a43192d8317dab8a7e06));
        vk.gamma_abc[320] = Pairing.G1Point(uint256(0x2be401689e8a4fd5d50223a6ea1ea2e64d5c662bc70f7c6c4ee00ca6fd083d84), uint256(0x11be2a84d9bfc9ba03151b4cf5f836777a2f65d4a9c76017abc3a3889b24c303));
        vk.gamma_abc[321] = Pairing.G1Point(uint256(0x08dd123ccc7fdb859a563a78ab650742c2bcb26cf78f4b39bbc3189f94fe9a35), uint256(0x0375ef7eabb35d4ea29aca0de04d258ef48c965e602e8ab74efeb5cbe1a8b58c));
        vk.gamma_abc[322] = Pairing.G1Point(uint256(0x1936abb512d7480f5e1e4d31126b0621fec0057db824650eb2946a6fcbc19946), uint256(0x0f09f94f1892958bcadbfefb9c6d820bfb878a52d3254172892acbd5667a8d37));
        vk.gamma_abc[323] = Pairing.G1Point(uint256(0x00f6d02eecf257448dbd2387b0e28abad837293fdf1e1ea24bbecce6357eb498), uint256(0x2adffe8646b034a9aaac1e7c7401e256a5285d6f7f7a4d7aa00e0a71848a5ad0));
        vk.gamma_abc[324] = Pairing.G1Point(uint256(0x11d2c620662ea7c07389fdf44b144c56ec46e593126c8b22c232c572b9fa29c7), uint256(0x131e3ab8e90a3a109c63fb2fd53354b9dc1d4f151100e6f8445e93aec679b4e9));
        vk.gamma_abc[325] = Pairing.G1Point(uint256(0x0475fb837f12ff7d614c743dbaf95395a8bc55bab405cfc05b1e3e762ffe7d4f), uint256(0x130b41e5ce82c6e48fbe265d245ff1653c0abd1d210ac84452bc7a4385724040));
        vk.gamma_abc[326] = Pairing.G1Point(uint256(0x195cc9a536b41bfe74d00c31d29847f21ea3f0b7a713b70ad6e7d8b67fa31123), uint256(0x22a4b1151b09a58f695cf12f264ac2167d9143986eb75147a2bcf4cee5f24181));
        vk.gamma_abc[327] = Pairing.G1Point(uint256(0x0153011b9f4ccd8daebdd4ca177d44fc651d4d9b13bc0d0ce34aaea4d97c71e4), uint256(0x0742abf6a6b933cd82be7847bc200778754ce5132e1f97f1b5ba811c7b4ded6d));
        vk.gamma_abc[328] = Pairing.G1Point(uint256(0x1132b7e19e48caa18fcf6de3de3b370f1e58ee872019df5c557e35a72cc1b7c0), uint256(0x1c118f1ab242ff30580749b4c8817d11daff3019820eea64bb9e2b41e28d1ce5));
        vk.gamma_abc[329] = Pairing.G1Point(uint256(0x19e5f8241b44cd59bc86b947b935f9341721d30d5051577f389c316add96508a), uint256(0x1cdbfabc9b7fc6914f8cdb6f2a70f90e77112e823470e66ca1d7cac68563d584));
        vk.gamma_abc[330] = Pairing.G1Point(uint256(0x16bd435637e1be6b47a4e56df3a5e775c981dbcb8fb74623d78d6d1dd89dc94e), uint256(0x0d978cf315b45964e1b7479fa1aff175585c17a0b429895beabb2d60474e7be9));
        vk.gamma_abc[331] = Pairing.G1Point(uint256(0x00061df3bda81fec905b360276f861ee59615a957f0f9d2156cad51bec3a1cb8), uint256(0x2e4c829c1fbeffd60dee6326b9cbef25eca1073b192490b1da4f560ced6d4714));
        vk.gamma_abc[332] = Pairing.G1Point(uint256(0x1a425bbabd1d562deee9f5e8b2fb038a64dc84e42920cb31843645ae897df9cc), uint256(0x024eef52e211fa5e044c4a30b380e0c0dd1626396149894ec39c3b7b6fb5a144));
        vk.gamma_abc[333] = Pairing.G1Point(uint256(0x0b32c1887c72c0e61750ceb0a908880a9c1bb6473b3188d98b209b39e53cc248), uint256(0x0ecc1478984a130aa361c828aa9df98b97496bd033922801dadd9ea9b1e6551f));
        vk.gamma_abc[334] = Pairing.G1Point(uint256(0x14a4c37c3dc57c17fa1d2508cc6dc4b08afcbfc357d2b25c12b8c338c8ded454), uint256(0x2d6986d958f70b4f0f7295b22361d3a0397ea79399ce1e5df9ddfd9883bc467b));
        vk.gamma_abc[335] = Pairing.G1Point(uint256(0x24bed75471446024582626221640d3c5819c2a92cb23b14ee74a941577f83442), uint256(0x2061e2d4765d8870ef17f638defb6fbc8b89e74d425f74983989a65a89eb2804));
        vk.gamma_abc[336] = Pairing.G1Point(uint256(0x2133eb786248258552cbc72b02187eb0bf5d65b7d047bd8d2bd936d2e09ee05a), uint256(0x0f4e65faed17f50a3aa4972a4ac05a652f8639e9c0ce524d95fe895e9c37acdc));
        vk.gamma_abc[337] = Pairing.G1Point(uint256(0x185b92ec4950f12f9284b03c8e98376dae00c0fcfd5fa09d91120e54d3506d18), uint256(0x132a66f7799d4881eb8ee553b0e13b9234763a1cd9160645748408aa7d584404));
        vk.gamma_abc[338] = Pairing.G1Point(uint256(0x129fb0d18f08b71306c06888981bbc157d85c09dbd0311faef583260a746a50f), uint256(0x0bb91dc7e74dbce41b6f700c35cd33d04c451de4f74f621a4d92df684e8acf61));
        vk.gamma_abc[339] = Pairing.G1Point(uint256(0x174783959e034eb8aaff3506ab740042ae2806b0417fc92be4bb9b48c1c5e92b), uint256(0x1b1b3449310ac2963d4730989c8a8f70f2a1b51cfa7151ad21508afbf896cacb));
        vk.gamma_abc[340] = Pairing.G1Point(uint256(0x0cce9b40f13fed0eec9aa3e2f8f258f64e6e8ba36c45b355304e3e0bfd4dc137), uint256(0x1d88132d36c28ffa186204c8633d676a9ddecdf03ff16525abcb9eca0bc78b19));
        vk.gamma_abc[341] = Pairing.G1Point(uint256(0x0d2555172ee7e4e1d1dc893b6661bd437f9b0597e48776f00a4431ca764ee84a), uint256(0x0a7ae3a68798d9ae53babc0e180ff2b2c25174c6e825003f229838aabe91e215));
        vk.gamma_abc[342] = Pairing.G1Point(uint256(0x1e8cad2a5ca2b77accc5fdf278f45e4e4af1762c161e3111734dcf0aad965824), uint256(0x01269032a5cc31a051b54a8967b0a239229cf2561c1122a762a29bef97b56683));
        vk.gamma_abc[343] = Pairing.G1Point(uint256(0x28bded16fd6b1d94a2297cb7e30db60230ec5db605d9c84ddd59b4322f905b1a), uint256(0x1982d7a557d472bf2a96176074cf073b2722ef7b9f023bba9b0692b4d9ad8350));
        vk.gamma_abc[344] = Pairing.G1Point(uint256(0x01efa153487f07e39acdd992c90c7b0be275088d158b9c7b6d19707559026d98), uint256(0x25736e6223d3898e94da2360f27ee43e8afb03ad2856a019ec3bc797da36584d));
        vk.gamma_abc[345] = Pairing.G1Point(uint256(0x0834855cc2c6c8815f2b056b9c9040cb212ac0c7de57dad1ab736205e08b3cda), uint256(0x0ce1b8b8dac54393251ea32339531bcf850f538cbb4e5a431b035eabd6893db7));
        vk.gamma_abc[346] = Pairing.G1Point(uint256(0x181a45196439941a7c2c4ea8f434287c32f72a22ba1e2857837ed3e0b019d2ac), uint256(0x218d733e276d5b2ae7c4cde67ad34b311b9a4d48a5624606f618f77b02f1b191));
        vk.gamma_abc[347] = Pairing.G1Point(uint256(0x02412a1f01d8d28703b7a34751c02e09f746faced4fea0d1e2a3e43ef891a585), uint256(0x0d38946f0c02467e0aab8ba73a0e05a47c39b00c97296e5a0d4b6c390c6cf57a));
        vk.gamma_abc[348] = Pairing.G1Point(uint256(0x05d2835ec478300605176d010cf63881e49a860b812072e744694a2381dceef3), uint256(0x26e4f474d3a2def6fc3ab24245c79285e54e2b8ee75bc4d6e04863bafb131cab));
        vk.gamma_abc[349] = Pairing.G1Point(uint256(0x04c34ced269c8090c1d6bfb8c1eadb3b0343ca05e3e1ab64e7eb67ba42d6a015), uint256(0x2a9c3b1d8aa176e24c5d702adc4b76f94883c16ce410fbe56fe934678ff8bf9a));
        vk.gamma_abc[350] = Pairing.G1Point(uint256(0x1d747c01afcdd2ed798e41a9ab6c546fa01c11df334ace326d13e65d2ffc6613), uint256(0x1980cd34480a6758804e1502341d489d849b6e061fd09d10bfeb6cc0be93496b));
        vk.gamma_abc[351] = Pairing.G1Point(uint256(0x2844dcb4b65146812379967cffdfca9bad97c20ac6afc4df44fc549fa1fadf1a), uint256(0x0cbdeb76fc63bb380e642a39325d238ccbfc32ca89349d2954916f2966c1ad2a));
        vk.gamma_abc[352] = Pairing.G1Point(uint256(0x165e0cd538ea42ac8c58c2868f33bcf31b88489e3e162d225ba8c7a386fbc89f), uint256(0x04ff1e4c02616a197569376452856c607e3b59f069e59acc400d57f7d14e9896));
        vk.gamma_abc[353] = Pairing.G1Point(uint256(0x2d3590ba40edc5eac026e9cb9b8d5cdceb4577d42ec0bac1fb296c44296ba4b7), uint256(0x1d33804f6a3023e89b7613aeb46e1e9df78b746b77447fa1210e2e70132c8827));
        vk.gamma_abc[354] = Pairing.G1Point(uint256(0x12c77e4756fec093803078dd672505fc87c073259f87f7ac2a97c3be0290b128), uint256(0x1bd7053ed8a7ad11f1252e31b0958c3546ae10d4b713b70b618260939b09d956));
        vk.gamma_abc[355] = Pairing.G1Point(uint256(0x14380b376bb0697b3de3587d45b43f905624aba5084dfaccd969b91301ad9933), uint256(0x09dd630cac9d28f6fd37577236246c10f799db9adaf7bb6709ce16b23163265a));
        vk.gamma_abc[356] = Pairing.G1Point(uint256(0x07be13c9e504250fcc4e92b9661fd15cbe880118ccce1027dfde0dad7c862b5d), uint256(0x169f4e41653492e14072d483bbc882caf529d1fd69f8d074eb0a841029661dd8));
        vk.gamma_abc[357] = Pairing.G1Point(uint256(0x220b8780c7488bfadb9252b7a4f972270314db9b2511f9f4fe27bb6b970faddb), uint256(0x16785c9f6fdf38f189bc3a2b2c345c76d4fccee76fbdb120657227f31477571a));
        vk.gamma_abc[358] = Pairing.G1Point(uint256(0x2ecf97ed5a589be88ebb09aeec3864920329f314b3e283abb35e9df22d83b96e), uint256(0x002fa0d78772989e95498d9c71744f458c57838af20bf79083998ad139c352d6));
        vk.gamma_abc[359] = Pairing.G1Point(uint256(0x1f1ff6206c285969c0b5b8c00d5b978561e58ff15d589a628eabf5e55705a7a5), uint256(0x2fd192e584e697be5d981005922cd9b02a813b1b6e27362d4129301fd4b58178));
        vk.gamma_abc[360] = Pairing.G1Point(uint256(0x27f81d5e182f8c8fc8fdbc1f354464718eb3ddc747925bc5028839dc9fb60976), uint256(0x009c382e4bdeb5fa3b3c24df87e44875d37d2ff1b22b2c89b4166fb77b215317));
        vk.gamma_abc[361] = Pairing.G1Point(uint256(0x07b18303902b21e9e6c0a499797b9b2c82d2b0497435dac70edf35f7ea04b7d3), uint256(0x08c1c42e8c68f11992cf1cc5f64e180daacde397005288d113bb1dec7f7debf5));
        vk.gamma_abc[362] = Pairing.G1Point(uint256(0x0e17d44410cbfd632f5459692f8b06123f0cf95df748731595a44c8c37f66c30), uint256(0x2e8e9691c20f889771d421643004026b290ec5272ba5923ef65e55f468530544));
        vk.gamma_abc[363] = Pairing.G1Point(uint256(0x11606047ed46b1af92ee000ba855c219e0ddaaf58d289f293aff5342d52cc2aa), uint256(0x046e966be4147ac40d65aa02606f9fabfcd98af2fe26c1401a5c9f86d24161c8));
        vk.gamma_abc[364] = Pairing.G1Point(uint256(0x153350c3a5273543696b1c2ac6cffd5044b5ea6df25d252ed0ebbb6bef5bc378), uint256(0x1fc33bc1178685c88cbb55e61cdf945e0afb3d784fc699eb9f7e1f7fcac581e8));
        vk.gamma_abc[365] = Pairing.G1Point(uint256(0x0d47c38d4a711cd5e29cdfc2156af908fc840648c84e272ff6a226fcfa858ae5), uint256(0x1d7ccb4d59dc91c73b4b096efc84edc7479c9a17e9312c322bd92250389a83ca));
        vk.gamma_abc[366] = Pairing.G1Point(uint256(0x0e8d9a80cc24443c08d9251934069d218829199cf47f59f29af0d1efd5c59ddf), uint256(0x2d729626f697ca912ac033d499cc9fba5ba3a268b562ba57491eacb23ad08dd0));
        vk.gamma_abc[367] = Pairing.G1Point(uint256(0x06b09404589f5e215214648cedb0135ca4013c09e75708aaf46e0b193120484e), uint256(0x0ba68a77e77fbf99b87902d148d29d952d843b01ef3a8b250846df8aa60a4b86));
        vk.gamma_abc[368] = Pairing.G1Point(uint256(0x0d7e7557166cb200c0d36947ae2231a87192b1b475e4cd60f96e48ca41a4ce65), uint256(0x22a398fa9a53b5963657a8f3b7d82c2dfbfe069a069b32534da4308cac4aa6d5));
        vk.gamma_abc[369] = Pairing.G1Point(uint256(0x152e9905c5c6c76e52e43c9463608bbe78ca1b69fbb5c2ff6afd2184b0a1f569), uint256(0x12555cb2aad55b176343655df853e54e9a2ed2478a178b9b26d90754807240d6));
        vk.gamma_abc[370] = Pairing.G1Point(uint256(0x053ea0d68440b16b3d3ac7fdf04c33a6376a4de77c918eb1e647b1ab6233626b), uint256(0x2d0974de56828af9123f3b7b397b8b287cf78faffa7d376297be31128bf17ed1));
        vk.gamma_abc[371] = Pairing.G1Point(uint256(0x00b0932f5dbf3c7a38f79ec93ca7f1c41455daddb7ef332d1364eb808dba7010), uint256(0x28bf461e38713e6f10d19d9a3ffd4de08c7f46368cab99677615324fe72ece95));
        vk.gamma_abc[372] = Pairing.G1Point(uint256(0x2c3555a9625849aa26df656feaddae4bbdced089818817ca47b0a1c1ea6c1684), uint256(0x0320020dfbff6c679dc23ede8d76b87846037ab41fc6383ae290c8347b16b34b));
        vk.gamma_abc[373] = Pairing.G1Point(uint256(0x2fe198645057e209d6180922c87ed15fd9132b602cb75a0cf7e07575e87bb0f7), uint256(0x0e9c2bc8ca69bd95789096a13867de14b64066b5a2f4e39752c26598e6972f93));
        vk.gamma_abc[374] = Pairing.G1Point(uint256(0x2334444ea4980aee682321f2c4789fed005e94b6c37fcef02ae7cf0c6f28e92e), uint256(0x160530fc4eeafd4f7e748857e16495a0424038e7c134bdad370ff50284428517));
        vk.gamma_abc[375] = Pairing.G1Point(uint256(0x1f271922da7f7e5762bf48db9a511d6c0e2d7b990d093b80b739e017a6468b12), uint256(0x0a171beac2fc75311d505177b6ca7ba1558c26089ba4624940d50a027ba9264d));
        vk.gamma_abc[376] = Pairing.G1Point(uint256(0x01005095be7d49f8adff61a26b98565771ba7230363170daf9f7f7ceb0dfbb38), uint256(0x235f3abdaec63234b6570cd3029b6ae8c0ef895f3e87354e4b8901098fda99d9));
        vk.gamma_abc[377] = Pairing.G1Point(uint256(0x12758a0d17a1b4c69505ecb3903e2e08c26b71235fa1fd2e7316420f45c8ae55), uint256(0x20a82ef199995cdbca5ebc861850b2866e0a275f4f1004699841f6dcd2bbab2e));
        vk.gamma_abc[378] = Pairing.G1Point(uint256(0x14912232319d7262bb55a7d4c35ceb9917298833f600504812d8703d9c7580fc), uint256(0x0ed067dd6969cb0546a449d58325654ad7ecdf49d7fc04a69c816981579e2636));
        vk.gamma_abc[379] = Pairing.G1Point(uint256(0x0062230c619456a2aedc9f70880460ed7e9f514d614485c35d0fa72d8a62bcb9), uint256(0x00a817d2e4ce7f9daf1f6a8e56283cbcfe63b2849421c6856e2eb5fa4725bdcc));
        vk.gamma_abc[380] = Pairing.G1Point(uint256(0x057eac88760e7236df77530a2a19af94936699557983255f08b9a13650aeff8a), uint256(0x211a5acc602ce8c8642786ee1a6fb9890aacb16607962e51bcf57e711d3d95a3));
        vk.gamma_abc[381] = Pairing.G1Point(uint256(0x1c811dcdbb4bc347d4cb6bf81fa6752702d4c9a78daca35c6ba694cbe66ba468), uint256(0x2270b7c060d4b71a914ea9224e99ee7791570d9e5494da64f0556c108ac9f7cd));
        vk.gamma_abc[382] = Pairing.G1Point(uint256(0x18af0649b2c612d02daae8b8c362a198a9c3a2d3883d34b8af0c49f199ca2f45), uint256(0x18aa2b5300c61d88f4206c5ae71c2da625148785ad8df4b118087fc8970208bb));
        vk.gamma_abc[383] = Pairing.G1Point(uint256(0x1b37b2836f483885e3187a984997a0a03192f75908463a134db51c9736dd3e7c), uint256(0x2530052c05a17fc42ebba076f5016a827b0214290868498380777dc8935781e7));
        vk.gamma_abc[384] = Pairing.G1Point(uint256(0x272b71363394f7a7d5ceecc14ed11f6919b670a97cb7b788b9a693b32bbe749f), uint256(0x180cae9fda1ca5fbca34df2fcf75d9ca8831832ac6c3b9f87535fd78a8b4d59c));
        vk.gamma_abc[385] = Pairing.G1Point(uint256(0x2347bfce684d2a65e81bd4bce75b193ecbf7f650b9bd58890894b06110129e7a), uint256(0x11fc24f5f0eb62fa75ff31e45d2168910134afd7dab56eb5bfa379e1373e5083));
        vk.gamma_abc[386] = Pairing.G1Point(uint256(0x1f72edb9780df2be8424bd284bc99e98e231961982e0a721b3e39169d9eba283), uint256(0x2a1929ad59f668932620ddb8a254fabdd3733a968ab4802afe2c081dfd4ad616));
        vk.gamma_abc[387] = Pairing.G1Point(uint256(0x053620047d6fb21ec5bb17a546e5f6388482d01c74b783cad10770950abfb20f), uint256(0x04f7181df09e417fd6bda9a00ddb8761f3b75905ae914352a610d1de0b9fcd59));
        vk.gamma_abc[388] = Pairing.G1Point(uint256(0x01e976ffd79c805144d6304492f152929de7ecd12c56ace108f192de57ed5048), uint256(0x27d9e2d5e320054f575c2c561e7ae69ea09689e453890132ac779060658ea0d8));
        vk.gamma_abc[389] = Pairing.G1Point(uint256(0x0b5ee8e2d5f43ac08e4e90f8e88a2bee6e4aff6c8df2b3892f65c889cce68429), uint256(0x04bab47afce7abcd134b36cc0d667e70deadded84202da6a9bd39030fcfaf518));
        vk.gamma_abc[390] = Pairing.G1Point(uint256(0x26cec6df6c5974dd0d65cf4bc9d9d4b5493de30d167b3759da0b35ced8725bc6), uint256(0x128be383652b4aa485842c5f5ab6b5eaaf50e7521a175e148055f24dd0d67fd9));
        vk.gamma_abc[391] = Pairing.G1Point(uint256(0x2d80fcf700872e1a137ad16e177e95572f2bff98d593cff55b69980bccaf801d), uint256(0x147054ac73032cc2ca0ed1d72a8a7e4f99cca1b50c3750845a64f249ba89f0af));
        vk.gamma_abc[392] = Pairing.G1Point(uint256(0x2200a54fc1bb915337a893fcaba1fb9f2a2d1c63c13a826a61944c3a5a3fe525), uint256(0x2375ab26bdcc52fd62cf91b48e198edc7d801ae1fa97113dab7815ca10d04a0c));
        vk.gamma_abc[393] = Pairing.G1Point(uint256(0x2f19f4d0708a25db5b6edf48d049f8169e1bbcffbd5819069690eee9ed62f91c), uint256(0x127b745185525290c610e6a5282aedb74a71f296676688c481d5b61ea66f2d70));
        vk.gamma_abc[394] = Pairing.G1Point(uint256(0x19378cab03e9a7073674f35988bef50c0694cfd47460c4f2196a9a8e288d2cdf), uint256(0x0d5962a1924e1b9c5783d3220683626b1d37410ff8e3ec77873a8bb34cae458a));
        vk.gamma_abc[395] = Pairing.G1Point(uint256(0x16fe2a01ddb678b76b86a5948f80b9a4edb124bf11806b3826d18e6ba3d42f80), uint256(0x2bd56de7b08bf796d96f27480559fd2fcf15920480427cd5209412d8db94a083));
        vk.gamma_abc[396] = Pairing.G1Point(uint256(0x11a220d7c71d21a05b4747d1838fa13906b4db5c3758dcc5a0b7d4f37d679ba6), uint256(0x28fe213911a0823066d15b7421c7115c6a90617dc73699cf222a60c9305452f8));
        vk.gamma_abc[397] = Pairing.G1Point(uint256(0x2a07b71a78286523fb3383a71d741dc7530e92c48fd7b9b8cab865e2f1937897), uint256(0x278372bf73c42629430222e68270687c6f37133ae4f50fafdc3770aed852b19e));
        vk.gamma_abc[398] = Pairing.G1Point(uint256(0x1dd2fd4cbd02569327c70a0718442f498cdc90e126798a2ab32d326ba6e0ee86), uint256(0x202f35ee7f252d2431631eb9aa28479ae1c47341ccd9b2444cbf29226b386ba9));
        vk.gamma_abc[399] = Pairing.G1Point(uint256(0x1190436a64536973da0db5512763e51057ddc7173988a67f0a38eff2a8932b7b), uint256(0x0ed55215da5a89b8988861f8dcc494e87b8a8bc8063baaff85cb817b15de8802));
        vk.gamma_abc[400] = Pairing.G1Point(uint256(0x2de907ccf4798dad952d0816f43a5de55a70e1509df1acfa3099d07ca8de1040), uint256(0x09154db2be84faa3c54b7ac53b87f02232b9d6eb87ab332d805093e6125e5435));
        vk.gamma_abc[401] = Pairing.G1Point(uint256(0x1ce0c69dc191677b48c3c18d27b3e711028980d34669e0f9abb373d767e2658b), uint256(0x02de50a20eed08d0078ab8c06bd5ee3869120b3877fa4b74b9145fed8872ba99));
        vk.gamma_abc[402] = Pairing.G1Point(uint256(0x1db690bd4b91b5d1ef2163e77be5f7c51bb2455612d200f2c2f35b3c6a633d74), uint256(0x113d07dc0e9555ba2e73a12e862695e57090d6b762a1b3db776bfe3daa48cff7));
        vk.gamma_abc[403] = Pairing.G1Point(uint256(0x27b23b13995a762f595d701e72412061d22aea9c86c54d88215bebc2a49f4944), uint256(0x138ff44bc3ebf4d75db3757084cad36de68a08345aaac968ed75806901a81604));
        vk.gamma_abc[404] = Pairing.G1Point(uint256(0x1013beb4c3b77c5680b1d25f67f3276e8c227fbc46b3acac909f1d0548f086cb), uint256(0x0678a227e497281570a0ef78375b8afa59fd20c39e7a06d562bdbe640860d529));
        vk.gamma_abc[405] = Pairing.G1Point(uint256(0x288c61d5d3e14366d992a1a201831645b83bb592ddd10e7d3eb1ec482376d209), uint256(0x275cc841232c218a2cfde1313152b6351c3d036b039a41ae57a3e353f7b15f41));
        vk.gamma_abc[406] = Pairing.G1Point(uint256(0x1e650c738049487f0274b072144f2b05e16dc20b1033a8684370e2a8ebd7a68f), uint256(0x154f0486b365ea5bd186a50df36fe769fb5c22f7c02c8dcfbed86ac0a4512732));
        vk.gamma_abc[407] = Pairing.G1Point(uint256(0x09abf8e809cdd2f19740cd482bd8c78a2f0e41eaed050d3b17c67da5a300aa94), uint256(0x2afac668e31818215d2e5c6677862c755492ba989d08b6d66998f79b97fc4dba));
        vk.gamma_abc[408] = Pairing.G1Point(uint256(0x0e62ff0b4d75e5529f1ddd205553c77713a8e278c3ee31dc5947b6369c02dfa8), uint256(0x14e3d94e6b7b0ce8eee09e02885f0cfc6e23da6d06a9acb3239ee7a00d5909c7));
        vk.gamma_abc[409] = Pairing.G1Point(uint256(0x2e055586bd31031bc5e44cab944917a7292095fd9d6a452546ad85987d643ffc), uint256(0x00e7c422a773902380490e97e1016b17b5a33eb27f04e467b0b8eafa35468593));
        vk.gamma_abc[410] = Pairing.G1Point(uint256(0x1b1fd79eb686d7e46518f42e7e9d0d71d3c75711489d333fe6ce5cb8d78e633c), uint256(0x0dfb32ec5c2cce58ed111ddaf9ce643581461fe63786d203ffbeac525348fc13));
        vk.gamma_abc[411] = Pairing.G1Point(uint256(0x26dd4819e3c6f242276a2fe974ecb454f479b5ab0265d4679f21c5961109cb77), uint256(0x1f8cdf968078cb3fd67fbffa7a1ade18ce6dd11ca992d4529cccd4b4b780b718));
        vk.gamma_abc[412] = Pairing.G1Point(uint256(0x1c3ef34b4cdacb96d9f24774642c6de022ac2a3244a33e1ff964445b5ce29fd6), uint256(0x0faabf148ffd429470367e9e1fdd1d644288a1b5217b3e93dd37f45cc4dfe0d8));
        vk.gamma_abc[413] = Pairing.G1Point(uint256(0x01cf836e713e842bbe7f4b6d43f4778e740625b29a499260037400833c4f2340), uint256(0x21213fbd0568f1bbd6fab70eb5266133b89829ac25a821e07e6f7a09157b5090));
        vk.gamma_abc[414] = Pairing.G1Point(uint256(0x2b056cdcd1280959ce013dc0a22866b1cffb66bd289d380818f9595c9cdea93f), uint256(0x2bba34c50439adff4ce003526a74b39c5967f390123e578864d4738f0ac2cd31));
        vk.gamma_abc[415] = Pairing.G1Point(uint256(0x18868fb47171262889363282ffee77195a19afd63b20b09ddbbe996f0063988e), uint256(0x0da9b65d161ae966358d4ead74367b5ab4740a04e6f9c0dd0a0702348095bf9b));
        vk.gamma_abc[416] = Pairing.G1Point(uint256(0x011bd6c98239f73446910d56ea61001a7deba14875565ba074bdfface44d0541), uint256(0x1fd77461f0d3584144417a8e67856028c8bd4f8d36616aa707798a63284f9bce));
        vk.gamma_abc[417] = Pairing.G1Point(uint256(0x2edfd0d5cb101c26a51ddaa8e97c4c5dd3db003bf134e9d0b5d3e2524b3ed7ce), uint256(0x0452ccc233d471b65973720728aabb53b2417983fa8784df4a5906c1f8c84e1f));
        vk.gamma_abc[418] = Pairing.G1Point(uint256(0x09964f3a67be1b1be605b36c7b9af8d9a30423837ffc38e5006024fb2d0241f3), uint256(0x08861382ec10337b8cc2d541974bfe6b50574d2107d5fbb0d7251c6af4643072));
        vk.gamma_abc[419] = Pairing.G1Point(uint256(0x0e59dab9b15fabef28b1bb05f9c269fbba89f6db3123560819ceda60ec65b1db), uint256(0x03d1279be2398cf61db51de3c82e86e63ef2050831a2d2b0e15d5bc03262aa53));
        vk.gamma_abc[420] = Pairing.G1Point(uint256(0x2f570fd89ee19c7fd472c898720e821f314283c2b67983a97745e393ec718e62), uint256(0x24157bed8418b114d3ee201eb028eb6cbd414db72c87b32295e3d0be91716df2));
        vk.gamma_abc[421] = Pairing.G1Point(uint256(0x1078928e8f3ad7d936c3684849b62880968fb400bfc6e8cef613152cfab47558), uint256(0x096e3ee0c4dea03ca433e4a1e5413262ab80d9afa410576c1c51d6178e0256bd));
        vk.gamma_abc[422] = Pairing.G1Point(uint256(0x008052b97e71e2df9cd571fdbe06744bbdececbfed12b42f89d90c4203acfa8a), uint256(0x13224a3743c5125648f129f1fac2830ea51e857179daa7a2b9ef7e11c188c3c6));
        vk.gamma_abc[423] = Pairing.G1Point(uint256(0x0dae795317f35a16fc3f484cc218db169a995c5be7a0c6868db293282fae9b7e), uint256(0x1a0f434a2743c2f67013234e1a560e31da3f09ae678e7f1fec79f11f2eab1399));
        vk.gamma_abc[424] = Pairing.G1Point(uint256(0x2758a1bcd116ce9a2e37b257165f5ae087c1c3c1ce46704bf87b99ce5b789dbe), uint256(0x031f61919abd731cd8dbcdc2bde0c5eaed4dd533af8a4eeca5022f786ca6f99b));
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
            Proof memory proof, uint[424] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](424);
        
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
