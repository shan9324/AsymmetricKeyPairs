# AsymmetricKeyPairs
A factory class that can create different key-pair objects and store its generated key objects in desired format.
One can switch from an existing format to another one as well.
Key types:
  1) RSA
  2) EC
  3) X25519
  4) EDDSA

Available formats : Native pointer (e.g., RSA*, EC* etc), EVP_PKEY*, std::string, std::vector<uint8_t
