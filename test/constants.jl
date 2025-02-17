# Define some data we will run our tests on
lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
so_many_as_array = repeat([0x61], 1000000)
so_many_as_tuple = ntuple((i) -> 0x61, 1000000)

data = Any["", "test", lorem, IOBuffer(UInt8['\0']), so_many_as_array, so_many_as_tuple]

# Descriptions of the data, the SHA functions we'll run on the data, etc...
data_desc = ["the empty string", "the string \"test\"", "lorem ipsum",
             "0 file", "one million a's Array", "one million a's Tuple"]
sha_types = Dict(sha1 => SHA.SHA1_CTX,
            sha2_224 => SHA.SHA2_224_CTX, sha2_256 => SHA.SHA2_256_CTX, sha2_384 => SHA.SHA2_384_CTX, sha2_512 => SHA.SHA2_512_CTX,
            sha3_224 => SHA.SHA3_224_CTX, sha3_256 => SHA.SHA3_256_CTX, sha3_384 => SHA.SHA3_384_CTX, sha3_512 => SHA.SHA3_512_CTX)
sha_funcs = [sha1,
             sha2_224, sha2_256, sha2_384, sha2_512,
             sha3_224, sha3_256, sha3_256_keccak, sha3_384, sha3_512]
ctxs = [SHA1_CTX,
        SHA2_224_CTX, SHA2_256_CTX, SHA2_384_CTX, SHA2_512_CTX,
        SHA3_224_CTX, SHA3_256_CTX, SHA3_256_KECCAK_CTX, SHA3_384_CTX, SHA3_512_CTX]
shws = ["SHA1 hash state",
        "SHA2 224-bit hash state", "SHA2 256-bit hash state", "SHA2 384-bit hash state", "SHA2 512-bit hash state",
        "SHA3 224-bit hash state", "SHA3 256-bit hash state", "SHA3 256-bit Keccak hash state", "SHA3 384-bit hash state", "SHA3 512-bit hash state"]

answers = Dict(
    sha1 => [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "19afa2a4a37462c7b940a6c4c61363d49c3a35f4",
        "5ba93c9db0cff93f52b521d7420e43f6eda2784f",
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
        "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
    ],
    sha2_224 => [
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809",
        "6a0644abcf1e2cecbec2814443dab5f24b7ad8ebb66c75667ab67959",
        "fff9292b4201617bdc4d3053fce02734166a683d7d858a7f5f59b073",
        "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
        "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
    ],
    sha2_256 => [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "2c7c3d5f244f1a40069a32224215e0cf9b42485c99d80f357d76f006359c7a18",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    ],
    sha2_384 => [
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
        "63980fd0425cd2c3d8a400ee0f2671ef135db03b947ec1af21b6e28f19c16ca272036469541f4d8e336ac6d1da50580f",
        "bec021b4f368e3069134e012c2b4307083d3a9bdd206e24e5f0d86e13d6636655933ec2b413465966817a9c208a11717",
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
    ],
    sha2_512 => [
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
        "f41d92bc9fc1157a0d1387e67f3d0893b70f7039d3d46d8115b5079d45ad601159398c79c281681e2da09bf7d9f8c23b41d1a0a3c5b528a7f2735933a4353194",
        "b8244d028981d693af7b456af8efa4cad63d282e19ff14942c246e50d9351d22704a802a71c3580b6370de4ceb293c324a8423342557d4e5c38438f0e36910ee",
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    ],
    sha3_224 => [
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b",
        "ea5395370949ad8c7d2ca3e7c045ef3306fe3a3f4740de452ef87a28",
        "bdd5167212d2dc69665f5a8875ab87f23d5ce7849132f56371a19096",
        "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c",
        "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c"
    ],
    sha3_256 => [
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80",
        "8c8142d2ca964ab307ace567ddd5764f17ebb76eb8ff25543ab54c14fe2ab139",
        "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0",
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
        "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1",
    ],
    sha3_256_keccak => [
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658",
        "8be0cf2df33d17ca1e2d9ab02c8bfbb051f44e6abb80c3e06ab55aa3661b6efd",
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96",
        "fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96",
    ],
    sha3_384 => [
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
        "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd",
        "eb9fbba3eb916a4efe384b3125f5d03ceb9c5c1b94431ac30fa86c54408b92701ca5d2628cd7113aa5541177ec3ccd1d",
        "127677f8b66725bbcb7c3eae9698351ca41e0eb6d66c784bd28dcdb3b5fb12d0c8e840342db03ad1ae180b92e3504933",
        "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
        "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340",
    ],
    sha3_512 => [
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14",
        "3a4318353396a12dfd20442cfce1d8ad4d7e732e85cc56b01b4cf9057a41c8827c0a03c70812e76ace68d776759225c213b4f581aac0dba5dd43b785b1a33fe5",
        "7127aab211f82a18d06cf7578ff49d5089017944139aa60d8bee057811a15fb55a53887600a3eceba004de51105139f32506fe5b53e1913bfa6b32e716fe97da",
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
        "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87",
    ]
)

hmac_data = (
    ("", "", hmac_sha1, "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"),
    ("", "", hmac_sha256, "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"),
    ("key", "The quick brown fox jumps over the lazy dog", hmac_sha1, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"),
    ("key", "The quick brown fox jumps over the lazy dog", hmac_sha256, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"),
)