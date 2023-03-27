#include "AsymmetricKeyPair.h"
#include <openssl/bn.h>
#include <iomanip>

    
RSA_KeyGen::RSA_KeyGen(int _size):epkey(nullptr, ::EVP_PKEY_free){
    try{
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), ::EVP_PKEY_CTX_free);
        if(ctx.get() == nullptr){
            throw std::runtime_error("RSA_KeyGen: Context could not be initialized");
        }

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
            throw std::runtime_error("RSA_KeyGen: Pkey keygen initialization failed!!");
        }

        if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), _size) <= 0){
            throw std::runtime_error("RSA_KeyGen: Setting RSA bits failed!!");
        }

        auto pkey = this->epkey.release();
        if(EVP_PKEY_keygen(ctx.get(), &pkey) <=0){
            throw std::runtime_error("RSA_KeyGen: Keygen failed!!");
        }
        this->epkey.reset(pkey);
    }
    catch(std::exception& e){
        std::cerr<<e.what()<<std::endl;
    }
}
std::string RSA_KeyGen::getPublicKeyStr() {
    char* buffer_data = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());
    if(bio == nullptr){
        throw std::runtime_error("RSA_KeyGen::getPublicKeyStr - Bio ptr creation failed!!");
    }

    RSA* rsaptr = EVP_PKEY_get1_RSA(this->epkey.get());
    if(rsaptr == nullptr){
        throw std::runtime_error("RSA_KeyGen::getPublicKeyStr - rsaptr creation failed!!");
    }

    if(PEM_write_bio_RSA_PUBKEY(bio, rsaptr) <=0){
        throw std::runtime_error("RSA_KeyGen::getPublicKeyStr - Writing to bio object failed!!");
    }

    long buffer_size = BIO_get_mem_data(bio, &buffer_data);
    std::string strPublicKey(buffer_data, buffer_size);
    
    BIO_free(bio);

    return strPublicKey;
}
std::vector<uint8_t> RSA_KeyGen::getPublicKeyVec() {

    BIO* bio = BIO_new(BIO_s_mem());
    std::vector<uint8_t> result;
    RSA* rsaptr = EVP_PKEY_get1_RSA(this->epkey.get());
    if(rsaptr == nullptr){
        throw std::runtime_error("RSA_KeyGen::getPublicKeyStr - rsaptr creation failed!!");
    }
    int pub_key_len = i2d_RSA_PUBKEY(rsaptr, nullptr);
    result.resize(pub_key_len);
    uint8_t* pub_key_ptr = result.data();
    i2d_RSA_PUBKEY(rsaptr, &pub_key_ptr);
    
    RSA_free(rsaptr);
    BIO_free(bio);
    return result;
}
    
std::vector<uint8_t> RSA_KeyGen::getPublicKeyVec_usingBN() const{
    
    RSA* rsa = EVP_PKEY_get1_RSA(this->epkey.get());
    if (!rsa) {
        throw "!rsa error";
    }
    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);
    if (!n || !e) {
        throw "!n || !d error";
    }
    std::size_t n_size = BN_num_bytes(n);
    std::size_t e_size = BN_num_bytes(e);
    std::vector<uint8_t> pub_key(n_size + e_size);
    BN_bn2bin(n, &pub_key[0]);
    BN_bn2bin(e, &pub_key[n_size]);
    RSA_free(rsa);

    return pub_key;
}