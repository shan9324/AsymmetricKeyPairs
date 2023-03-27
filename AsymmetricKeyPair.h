#ifndef _ASYMMETRIC_KEY_PAIR_H_
#define _ASYMMETRIC_KEY_PAIR_H_
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
using EVP_MD_CTX_Ptr = std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free) >;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&::EC_KEY_free)>;

enum class eKEY_TYPES: std::uint32_t{
    eRSA,
    eEC,
    eX25519,
    eEDDSA
};

class KeyGen{
    public:
        virtual std::string getPublicKeyStr() = 0;
        virtual std::vector<uint8_t> getPublicKeyVec() = 0;
};

class RSA_KeyGen : public KeyGen{
    public:
        ~RSA_KeyGen() = default;
        explicit RSA_KeyGen(int size);
        std::string getPublicKeyStr() override;
        std::vector<uint8_t> getPublicKeyVec() override;
        std::vector<uint8_t> getPublicKeyVec_usingBN() const;
    private:
        EVP_PKEY_ptr epkey;
};

class EC_KeyGen : public KeyGen{
    public:
        explicit EC_KeyGen(int id);
        std::string getPublicKeyStr() override;
        std::vector<uint8_t> getPublicKeyVec() override;
        std::vector<uint8_t> getPublicKeyVec_usingRaw();
        virtual ~EC_KeyGen() = default;
		EC_KeyGen(const EC_KeyGen& ecdsaKeyGenObj) = delete;
		EC_KeyGen& operator=(const EC_KeyGen&) = delete;
		EC_KeyGen(EC_KeyGen&&) = delete;
		EC_KeyGen& operator=(EC_KeyGen&&) = delete;
    private:
        EVP_PKEY_CTX_ptr ctx;
        EVP_PKEY_ptr pkey;
        EC_KEY_ptr mECkey;
        int mNid_ECDSA;
};
/*
class X25519_KeyGen : public KeyGen{
    public:
        explicit X25519_KeyGen(int id);
        std::string getPublicKeyStr() override;
        std::vector<uint8_t> getPublicKeyVec() override;
};

class EdDSA_KeyGen : public KeyGen{
    public:
        explicit EdDSA_KeyGen(int id);
        std::string getPublicKeyStr() override;
        std::vector<uint8_t> getPublicKeyVec() override;
};
*/
//Factory Class
class AsymmetricKeyPair{
    public:

        AsymmetricKeyPair() = default;
        ~AsymmetricKeyPair() = default;

        /* Remember: The onus of deleting the newly created object is on the calling class/function.
           The ownership of the object created in factory is completely given to this calling  class/function.
        */
        static KeyGen* generate(eKEY_TYPES ekey, int id /* OR size in case of RSA*/){
            switch(ekey){
                case eKEY_TYPES::eEC:
                    return new EC_KeyGen(id);
                // case eKEY_TYPES::eEDDSA:
                //     return new EdDSA_KeyGen(id);;
                // case eKEY_TYPES::eX25519:
                //     return new X25519_KeyGen(id);;
                case eKEY_TYPES::eRSA:
                default:
                    return new RSA_KeyGen(id);;
            }
        }
};


#endif //_ASYMMETRIC_KEY_PAIR_H_