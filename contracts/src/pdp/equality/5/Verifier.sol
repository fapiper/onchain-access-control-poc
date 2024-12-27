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
        vk.alpha = Pairing.G1Point(uint256(0x0d43cf8a88e04ff60206bdc83ea5e3faf6d874731f2502639b98ce4181f016a1), uint256(0x17f7aee038e964cd807c71598bce92f092fc8b40fb6f572b6fdac92a05f70be9));
        vk.beta = Pairing.G2Point([uint256(0x069e47b51611cfdac201c46ea27e03a9085bee5d697cf016373435e83fdcf628), uint256(0x190eef681ed687e8ab0ec9280e0e09f5999cca1e49484ef932e753a4521ea188)], [uint256(0x0ca7b80390b10545253a3c211bff142dfa2508cd39d935ae5604aaa8a56f1613), uint256(0x14098a5f1bee65e8fc0f5d53fc2b844af99303234aa23acf2c93933b47cb5317)]);
        vk.gamma = Pairing.G2Point([uint256(0x1dd7349796714b78a58295bed1da3efe4941fbc2808923e9a27f8266f1ffe6f6), uint256(0x2160af42a95386ffca93f82067064008e0d5314c8cbef1e07d16735735339fd4)], [uint256(0x13c88ae1483e53166c12722e776254205a63b8cdb8e5b604dfb860509f60f7cc), uint256(0x1e56a14371e34edd0410a3c0060423253a02b08a0803e6b443d8acf118a072b2)]);
        vk.delta = Pairing.G2Point([uint256(0x084e5286bd5726b1f3d7a1c9adc16a2cde688e44a91a6ea12a9ef4ec9420817e), uint256(0x26ee15b537ff0f18fb58ad9fa16963c212f4a2d33704b162d0f8d7f1fe664d90)], [uint256(0x2d7607d92c9129f91c51cae5995d567d74f9ee2d18e8bad69a48672d60901688), uint256(0x225fcf28cc108826e82befba8ae25620c607d8046be13642d0f92b321c41e2cb)]);
        vk.gamma_abc = new Pairing.G1Point[](92);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x005ea14c8cdf272418e99757ab806d5c91ee4d5ed42f3bb3e2d2144fd5691e00), uint256(0x25f891a66598777bf6681389a8d63ee40550c2b132f5ce6cb9ade1c118e21e9b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x03fdd066b6ed30df6a251e18c8f02f7c6945d6847301bf49a0649910f00fc593), uint256(0x1eefcdaff03b8c52943c5489c8cb5064c81ca00775b3857c73630ba6759ee8c7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2e5b562a090503cbee0f32656bb29f363a405f718fabc18b203373c541ae75f6), uint256(0x19f53c3ce2888c60b63ccb5adce62c42d0625b259864a1bd3807432d2d6a3c3a));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x11069d95430015d4a226039144f101501255eed93ddee4c586a26f681924344f), uint256(0x2f537b1cff9e68e788e63ec35ce9930c3a431e8ee62f4f68b0d166127306b043));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0e3cb56cdbe20766ae009cee2d9b6e11bea243837c878815bc5be736e21b58cb), uint256(0x0df8304d2bcd06b8ac27bb2946aa5053ea78c08af29283930debb8468d5610fe));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0df6a3844adbe60048557052c1a681631c7a1caee4b764ffff87340b778102db), uint256(0x1b1153ad35370a3d293ee9a12e60e1871d1b7ea780d1584397847715edb91a10));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x1ebd4a042687ea467b555a95e53d4072af924dbc0821ac91fd3b75043f71ed47), uint256(0x16e00fdf6ec5c3933b3256fddec1f1b200910965f37eacb625f53d40b2397c4e));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x12b67c36e9a44d078c8e72fa12745a8c0fe5f802538950f29dbd340238a457aa), uint256(0x14b1d5868a68d2398d972c3f19dc3deafe98b633827e65a97db6bb2e09855af9));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0c0b9cfb3c8f125b60610d4b0478b6979482e5605347c6965a2e5abb7c60f015), uint256(0x2212678d0698757a0d4104d14785554c92e04c2898bf0eea8940a0d7468af7a6));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1b9412509058d580b027dee9711cbb7da19968e10785620268ef0261263205c8), uint256(0x22c086847e64eb852a410c18cdd9a9e24d675d5621c45425ec837d31a71d6187));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x2358a484a9eaddba30f200c9411799187aafc38e7beef4d0997e256a11f4fe9a), uint256(0x095ba9547f15e5f423549db5442f7b408aabd5710ba166ce0cbe4f68ad6c9600));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0b5e66e1dc22b4ddddd46a210e5e5e5454499ae39b8263f2921c1ace2398be9a), uint256(0x2845987373ba6cbe1ed45824b97e14cdc0b8a0f8f8f6ee49c040f02dac7b26c4));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x241cc20cea08a24da18c74375e4c168cc30ebf2c2e8150d1ec24f908436a4cda), uint256(0x24895e191d8f6f2d4be87ee0f257ec57662818db297b06be4a9b91bd1cacb524));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x03ee6c9a9b403e1242ae75f56fd4a0bb9a0271ae4cad576dd625b6264ffb0ce9), uint256(0x2c9b2d58415b286c93d02bd89758681c088f3495bc2a7991bbe2f3b47ffdfe76));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x26bf95378a087e8d5b981ba9ed3f2ef42e4bb5fbc666628cfade8afbcebb05d3), uint256(0x2f82a3aa8e7f3bb5b1e980d91fb0f3e97af642f64a903c89470900aea6e8e506));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x269d32fd2105109bff5193d2c4d12bcceeca0234ce44bac000314b755bc72196), uint256(0x170bf81288d0490b8c2d8d0899f2633ac3c5a21f31fa41cbc96f8cfbdc1658b8));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x1dc00e073b54b1346e5cf700c0444facec28749711e9de0eecb9a3754035849f), uint256(0x29eee6414371225aa09e36839c67be9846debd5141745ed9bd3048fec259dcc8));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2648d93b6a78b4b708fd96baf254648aa155a0f9e5a80e952e2bca51b7fa547f), uint256(0x1b32f55a61315202cf68f75027ec70c0dbdeba22ff624b2c924ab542312ea1da));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x104eafd22ce446b12c99aef7e321692098cecb8a5f722b750bf858565a977588), uint256(0x05518b1591a6800e5621abdd071aae1543c6ee7a82c2010033ec4bc3fe9d8fa8));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x172bd339696ed1a135e32223d34240ef0365bf0243530c486f7d7d0246e4e9b6), uint256(0x12bf7fb801211b7ed49c410eca4be580ba300f1193f85a9df6d548cbd1ec17ca));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x29edaa71e638c8f43874d9054bdaa23ab16ac7afcd5aa7362b79575b230f2f16), uint256(0x2d5b35619f14c37be3f39fbe203f9919a3d6a99fc169fada614f83c88c4a392a));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x17e3a3b10e928dd304ec8d95ec5144b45d2098a13ef34bae587d3a7af1cb7603), uint256(0x1c1e5a21f406402289434b9f4ee384cb46a2acb31790ceb7c456019fad6dce32));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x20a7dadba79b5f456d6a64e7ba0e120a152f08adbfae41ad6699d6b59a8e7fad), uint256(0x0809ec9af618f5a5c6864c751a06fe326d0da29f01ea78cea26788af36265ee3));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x1dc56959eff69826544a61f1adeb8b8ef4ecc4f917c8471f61add06461f48bc4), uint256(0x27b251828628f138c7cce833064d9e7e8d8d417007a87a5de4b24c9942e75f0f));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1fce1d27587afcfc91915ae0a26e717f063668d469416a80eef1f9bf2a7434f6), uint256(0x0c33bd4bfaa9377183b27237a7f7540445391bd88787cd658799cc41164bc3b1));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x0dc279d670c03127d561f419cdb2dab74952091023e68276ee19067058641a49), uint256(0x027b2cfd504e35c6817b8eedca24969a0819a0dfe65497aa01ee0dfc533473f8));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x08caebc5f1d2f5c98c377b446b123d5e9eda82e02bd61a7992b7eca584f90a88), uint256(0x19bd4147382c5fe795e297b6b0c527393327e06e8cfa0baec085453de10a4fbd));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x2a7da28fa3b7e2e393d011b540e922ccc9763f4c6dc7d9ffb13d9dd0a44598b5), uint256(0x28a33142816d3a699db260b6391987a3f4a45bfda9399f9998d0152cbaf31040));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x1475a45648c322bdd6e9a2578d23ebbdd092d3f809a5c76ece285827cd69148a), uint256(0x2322fa8c45c2deb37094d15b416baa05bf1e61f65084f09c72d91d2f19267394));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x20ada27d6334e157d1f0c7b2f6316f0c9a8471dbb103990743f43e4d2df98648), uint256(0x0049db2c2ccfa15059da305c1644fc717e92a6e9d73e3fe40e63d996aab2bbbb));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x1c16b78009a07160d05df4c02e9ba85b6219fb75e07890f586f0cde4c53ed146), uint256(0x1650a1a3fa41267d19caf39ed1330e1ca35ffd3569a37be0d3518fa712eb3e1e));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x0f35a42ee1429f76f3bbe84b31d85a979bc0ca7f78d4c4fb2e45821b85024785), uint256(0x1543e561e96f32f153c2091672dc1d091b17d7e818faef826a31ba0568159196));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1b6f2054fb40ad948b245f00192cbb9d2716d681ea334dfccd8cd2f7dc1387ca), uint256(0x07375b99ba821d7880a99999b10eafe37c6c42f9074c6d594d5a638fc0640c3d));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x23e609e61a3b1a324485423717113146228fdd984936e912396678c551f25373), uint256(0x15bad222949ffef21aac5920a710d5152b02168d82adc69873171c933426f9ce));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x04bdc9713c91a5a65e98ba58b0bf8a2b265f49d57c6e81d68848c0d25fdefeeb), uint256(0x028141ac870dda9501222edf7d15bf803fb5508aac0f822e58e237ddfc7031a4));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x096cfd993733db83d402ff53dcacac1ea92ea890ad364f0d6c5aa259a05f5f54), uint256(0x28ee0b384d028923370a2c7b1295c1320ea783e2fbea38b05bacd9f76e73b8c3));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x14580e206ce372bdfa83e2b67b7b128c0b4ad723894fc1b96b699458c8325215), uint256(0x15ca2f703f638cbfa3eb72e5d69e6febd56fa5d078c8ddfa4db6606d4975e3d8));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x2e90b137144c677ac54f0fc8859213d10ca32eed2218c7b5f61c52468c546f76), uint256(0x1364ac4a6b23e550f0650c8b89f20198d1e3a95a4b4fc40e9fb95664db3e3f97));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1e9ff86d422d8576534980065fa8f11c1fbb8bdce96ab9138bc44b0f29a14bde), uint256(0x07947ab36fb55d52496087bc02cfdc814993252bf8e2425db4ecc35523ee29f0));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x00d9802552192fd589fd96a3be2caadcae27b034150291795e0c217eec16cb2a), uint256(0x159f9473f3265ca592c3575a72a782d7b991570f35d389e044b213aa0aa8e1f8));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x2f6bbe61efe6840db9f00a56d2e5035d13ca4e54d52d050775863014f6d705cf), uint256(0x246918a5f9c0bbdf25bc10e12dd81b44af12a3f9e39e96a7ce6a7d0f2bec6ec2));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x20d43dbbdec8a62f3224b6b3557b7a9140946959ceaf10091e59a6c285aa26f2), uint256(0x0284d4b164580f01bd514dc130401e5b559002ea1db43d39be1deb290c17f70f));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x1b30717943cb4f771f1d0dfe7f6364c3b26a4d60a4df10f62e83449ee79e17d1), uint256(0x183563d269aa2977c0f7ec5ddfa13ba9573395242fcba86000d9a6f5dce8946b));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1314572515fcc995315464dc59193f6ae37213f631f76a04741732b633fd3cb6), uint256(0x202f544393c13d4d85782f818b343aee34117580117949657e8c78e18f41a743));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x131078b4ec1c89cc74126addf85bee0972f0e6e95473ece81be242e355e9af22), uint256(0x02d247c1f0653593e23fe4c20ab4873b29d209a087295360607838d4088fc73d));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x1350d6e41735aa5fbf421a7ef81eb0f4ccbb4262e7a22d1a56071581bd54df86), uint256(0x0ee1f2810982974d0f28de80c8bb63a6dc6d595a79acbdf25bccf09d761f8223));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x2cb790ede8701ce724ec472a12b2f7b420b62da0965d7cfc42bb60abd4e6910b), uint256(0x009b8b254ecac31b653210f1836ffd287a5b3f3c7ca117d8c9b53bed8a1e367a));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x2eb4ec4a0872c366c6c1563ba8c7347c0d400d266087067569703e0434eb24f0), uint256(0x11c79a81b5b58a7f5d55be4c36a679d85f8b26ad5a1caa74fdd47fbfedde8f2f));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x2d5b13866e5f74fa59bb585e01be9cc034d517d5eedac6304ef3e7ae049fd1d2), uint256(0x104922b9b34f641b359671a980345878775a83fc91136b42deac561c5f4b8e17));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x1efb5157a212fc55d98002061b1621ae9797e7615a47f90c560e7af562648cda), uint256(0x15e64bdf0b1c9d0464e408e0584605c3f77b39cddbd2143252d1235566506d59));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x293e2c592cde17baef3fb0e81d3b13da7eaf0dc0d2eb1817d5a663a8690df835), uint256(0x2ccf564a5917b04197f89cce0265f0e184da8d35bcb43a429a63af386b8c8dac));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x24a886d2fb59f1e7509b33be1eb5b64988cb0d8578df237695f6c93005eef1ec), uint256(0x2d01abbff82e9717f44aa0e14c28be9d050cbcfd2f72de487f654e7b875d5241));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x1cd90e1a6daf653451148f1a445f90d57231657f1dfbc26e1519beea97fedccd), uint256(0x04ebbc4f73a10f09244dd3079c70fc068d8d489990b78ca2ca64b69c7b2211b3));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x1b8dead14199ee44bdfb68ca5e2fec94403b7215ff64d9c1eab5bbce3fb8598d), uint256(0x0de6670e2728fa4afaf375f64daf8bc531a14fdfcb8d6abda117738cb0c545a5));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x11cbfd550371f72a3a0d662803132f8a995a42799c41a71bcae832aa7b80a4f9), uint256(0x2d2a86a87ac2209e8c36547aa82361fa472d345e74acb4bfd4a42f0aa7a2a690));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x14b220f9013b18b9ea17e626d13ab613642e9c33573b36a88814db67934fe593), uint256(0x2d1b6807cc9770a2cdfbc44d41ad8066898fa69b644268d8e88e7f59c8831048));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0f9024a1d7b9ff73a2885501bf47cdac140b4e0c05a4052640ade6151cb752f3), uint256(0x24e5441c5e33d1c8044c879ca02cd2e6d5b7d838dc0e1d6517863a4053f8e5ff));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x2ef5ee4174d833230f39b4ead378e8c672211081bada6994b1993391cd5b8181), uint256(0x2b78e3cc4035337237e17248b5e01c42c1e7c647841d40d13340c7715f97be61));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x2ef83d340b1beecf18641312992107c979c388d8d996b36d35b5330e47322bf9), uint256(0x282ab9687a4ea0ff032cf29614c7cd220c5ac9911104577e27495e3a64e9ef0e));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x2ab09370a643bb3e1c6796d1187193743c6a0a58ad0a7ea7ff3ebec52342b8a6), uint256(0x1809a0f6d65d3a4d92761358a22c332b06920526f7e539fa0d14e522e5dec89d));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x22671396ae5822b7d39085625ee68396aabd2d69d394870db7583939f7cd19ab), uint256(0x2bb486358216a123ffa9e9e8fdb48f8363a8267a70ae18cea38270391b591336));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x1e129baa6ad7c373cc182471477fb4d2c91e6e4dbc23fa1494736fdd3785b48d), uint256(0x244ac916e2363430b2ddd33ce4c1d03e3f85ce3e003437072852120f5690d447));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x139cdec91b60c71b91dd3e882b5aeb3cd55103d962315071c6ba5cc2318cbce3), uint256(0x197e88c7924a11902c0b62a1ab11178176fb2ff37bc45625713af76066724cb7));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x1657c39271e2e79280aa88e795cc046d71ea849554435fb2cc76b53f72f69271), uint256(0x1bcd4b657b54c0096910286fdfa191f9723049b04b852f2746653f22be7c2907));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2ab20763ba8ec5898589e4a44c1a4fe6b1cab6324ade06bd32a8d6bfa006e00b), uint256(0x062f3186416db5da6ca2d6598cdb26e9cde7cfd8dae9e7e999fb3feba50b3b69));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x04f4973c7fd2da79ca787d787b64e1b41b007f3e0b83652bab54d910d267ff18), uint256(0x2ff229d0a5692e10a4aca7e2c8d39e829a8bf79e91864b640f05d055c319971f));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x1057f318670d2bc3faca9fec5c7bd4f956ef91dc1ceece875f0aff4f92b226d4), uint256(0x03a4dbe70b431b601f44a1dbbeddfa496b023ca124f3162a1639b549cdfef4f9));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x217d4171a1cd5a259b6c65e5935b908870adc0f3d52a1c5039e55da51e76fbd5), uint256(0x0c90f39df65e472fbe2bedcaa9cbec9ff45a5427c4714fa3c0e52f9dc7b5f858));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x2d5a26274f016163427fefdfa523a41a5433e859bd2f85f9b76bcb25a9d79021), uint256(0x1c9ea6aa3da6f466b8c0efc51d48d9782180a2d1e75b2c01895448a029ef6ca1));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x0f8df9f932f118fa0896dc82cf27a75031b8bd22050d0b21ec9b0dcb8794ed2d), uint256(0x07f344c2fd9782fb39324e447c47ad71d83d09aadd2bdbc2089b5c1fdcbc226c));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x025b5f1fc79174358fb07bb27be7c42821253627699ec561ee470130beac1ddc), uint256(0x283798c610de703f69bcf1bd3b4bfec626635bb452100f64ab7d55f9f08331f3));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x01be24ef62f7ad5921a7e6fa655a5a60de6b0c5c277bc4981da04b4b837d3a36), uint256(0x15250ac604fc2af9dc99690f70947ab32cab0b91b24f2cd3a2ca715b790394b4));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x1ebaafd4a28881d7cf34eb2858357e529c012e9cad0f871190bbfa13d7bd4745), uint256(0x1ee96098ab5a42b05f2dc041d56ed3aa2481b3696053241c7b18cac3af9db8d8));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x22c184c0ea79d118e86e2bc7269957fa73dcc79dec302081993adc4810c91ad0), uint256(0x006e4a751fd78f6441e35acd12c94bf8dcfd0aac1f7ee78fbcc564f3411f7949));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1fc587eeb4b927d3177eb50b811a23fdcfd46762d4023306481f0a253e3cdbf3), uint256(0x033e1e5cd400c284651ca22e6acc08ca3defe8ed7d9c69771f6ba66fd90f7254));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x168a142b8b271f11e849f9dd42e28c09cd132628d8b1065e09212643cf36147a), uint256(0x2631715ec42bd6c83b9e5aa2b9b5191112f31a420b68d17fee512916a305b1d2));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x22ca46583b39a1b90b88797150e74e72fe8a2528023974b5bc07cb48f2263b3d), uint256(0x2569b5309717e13be95c8dbd76794165fba548910e4bb37371cfb150ba0a1f80));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x2f89a36f9d41778fb07e1008cbeecf1d5128cd49256193aa6cf5dcf7a53f73fd), uint256(0x0570748aa30c1ddc397412882a73417b5b4df1bdc48d0cb4fa989c97d215f460));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x2c1548d22c273889fe4378557b4c647e7cfb4cc1c47d3e0a9975e3333c292ce4), uint256(0x2b6c41c3ba085c45bc1d5166b86b1fad5bfb4e86299b208440cb6706ec9a4eb9));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x1d58407e7ab9cccaf8334037e383c74e4458266d8ac9f55bdc44f1612fb406b0), uint256(0x00be134817087714c07cb79733ed455e79b1238f195e2fbf57f78b7c27e3599b));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x0a63a993308f311fa846007ef037c037d684bbd355738b736cb83c1a4ca6338e), uint256(0x25f198a1706a22e9558e9f092e6d09fd2d036cea55bab2ccf3d70028321d423e));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x0c57fe2faefff923e9e4f916bd0bfa20036a334bcfb0d4bad574dbf1607f28b8), uint256(0x0ae31fe84bb40935c68343a7d1999cdd82bc56bda3046668914b304815c07587));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x129085f9174bf2c9ad327e58d0ffaacb9717c5f7af5d4e3c5268705aeaf0223f), uint256(0x2431a5da1f5f454dc5e41c599d395a3cdbe6f7dca18cb6700cb72df45ef76f01));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x1811d0bcc4747420674751d589cb021fbd10377b184d5eb658f81d863a304191), uint256(0x192b3b0b3092f4b0f16c0b3a6c5ac6bc1266ddda64930d9b65cc188d83c386d5));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x1dcc705b75ff3a0ec4979b248e2662bd020ae309f73445a326818ecfd355e16e), uint256(0x2f86b078d69d1c2497ef932f1bd224a81bae68d8ffa498efa1d5a13e635e7443));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x081bab23d2746863d0c8764119694cdf513aa1bc12b16125775ca8ea4d201763), uint256(0x18b6887798870ed10ccf288f80ec9904edc908e5c75e0250119774bf90d30b68));
        vk.gamma_abc[86] = Pairing.G1Point(uint256(0x2a04ade90f2fae245f33c06c589fed2393f3227c04a79bdcac307c0af40d98ce), uint256(0x1467e8ede815f03f7529d53bca7be9ca58237a9dae77b0203bb31f2cb23a2118));
        vk.gamma_abc[87] = Pairing.G1Point(uint256(0x1f260b72ac84db5d7e8a33b78d007792cf7ab4cc65c9b33e2018a1fc48fa7687), uint256(0x1acb473af4643b9cb06036f60e6babad9de492f13943fea62f2bbeae8e668969));
        vk.gamma_abc[88] = Pairing.G1Point(uint256(0x25c6ad217f078bfe435f44545a4c6b1cdc498645e5d275a7c2924f257ea9f92a), uint256(0x17f084dc886adf559b06ae0698a6db459583832a5cbdf535cbbf718068296f48));
        vk.gamma_abc[89] = Pairing.G1Point(uint256(0x19ac5424fe54ec4ecb614494e0e186529fb24f25c2a0a54652def5478fdbb638), uint256(0x0b9a8a558ee01b548801f54a2f40ec2c66aace632661c8478e96a69ddb4237ef));
        vk.gamma_abc[90] = Pairing.G1Point(uint256(0x276dde831688db21cf773de00c0797e1119c56e14b960164391804cf85cbead7), uint256(0x08c673c2224703826de5726acd1a0b6d9b8be94d25a5337f6d0c5fe6ac18234f));
        vk.gamma_abc[91] = Pairing.G1Point(uint256(0x13cdc138855a1d020b3ca17d6fcc263a260aa86b9e2bf32f9810bd407797159b), uint256(0x0666c669173e00b60b19e409576c1be89b93d4877cc4e1af5f2cd3ac46998429));
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
            Proof memory proof, uint[91] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](91);
        
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
