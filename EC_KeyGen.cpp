#include "AsymmetricKeyPair.h"

EC_KeyGen::EC_KeyGen(int nid_ecdsa = NID_secp256k1):
                ctx(nullptr, ::EVP_PKEY_CTX_free),
                pkey(nullptr, ::EVP_PKEY_free),
                mECkey(nullptr, ::EC_KEY_free),
                mNid_ECDSA(nid_ecdsa)
{
    /** 
     * Reference: Curve Name and Key Lengths for ECDSA
     * NID ID	Curve Name	ECDH ECDSA NID-Name
     *                      key  key
     *                      size size
            415	secp112r1	112	112	NID_secp112r1
            706	secp112r2	112	112	NID_secp112r2
            409	secp128r1	128	128	NID_secp128r1
            710	secp128r2	128	128	NID_secp128r2
            715	secp160k1	160	160	NID_secp160k1
            711	secp160r1	160	160	NID_secp160r1
            712	secp160r2	160	160	NID_secp160r2
            413	secp192k1	192	-	NID_X9_62_prime192v1
            714	secp224k1	224	-	NID_secp224k1
            713	secp224r1	224	224	NID_secp224r1
            415	prime239v1	239	239	NID_secp239r1
            716	secp256k1	256	-	NID_secp256k1
            415	prime256v1 / secp256r1	256	256	NID_X9_62_prime256v1
            708	secp384r1	384	384	NID_secp384r1
            709	secp521r1	521	521	NID_secp521r1
            100	sect409k1	409	-	NID_sect409k1
            101	sect409r1	409	409	NID_sect409r1
            102	sect571k1	571	-	NID_sect571k1
            103	sect571r1	571	571	NID_sect571r1
    */
    this->ctx.reset( EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!this->ctx.get()) {
        throw "Context initialization failed!!";
    }

    if (EVP_PKEY_paramgen_init(this->ctx.get()) <= 0) {
        throw "Param initialization for ECDSA failed!!";
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(this->ctx.get(), this->mNid_ECDSA) <= 0) {
        throw "Setting the Nid for ECDSA failed!!";
    }

    if (EVP_PKEY_keygen_init(this->ctx.get()) <= 0) {
        throw "Keygen initialization for ECDSA failed";
    }

    auto pkey_raw = this->pkey.release();
    if (EVP_PKEY_keygen(this->ctx.get(), &pkey_raw) <= 0) {
        throw "Keygen for ECDSA failed";
    }
    this->pkey.reset(pkey_raw);

    this->mECkey.reset(EVP_PKEY_get1_EC_KEY(this->pkey.get()));
    if (!this->mECkey.get()) {
        throw "Key for ECDSA = nullptr";
    }
}
std::string EC_KeyGen::getPublicKeyStr() {
    char* buffer_data = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(bio, this->mECkey.get());
    long buffer_size = BIO_get_mem_data(bio, &buffer_data);
    std::string publicKeyStr(buffer_data, buffer_data + buffer_size);
    BIO_free(bio);
    return publicKeyStr;
}

std::vector<uint8_t> EC_KeyGen::getPublicKeyVec() {
    EVP_PKEY_ptr pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
    EVP_PKEY_set1_EC_KEY(pkey.get(), this->mECkey.get());
    BIO* bio = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PUBKEY(bio, pkey.get())) {
        // error handling
    }
    BUF_MEM* buffer;
    BIO_get_mem_ptr(bio, &buffer);
    std::vector<uint8_t> result(buffer->data, buffer->data + buffer->length);
    BIO_free(bio);
    return result;
}

/*
// Test below function
std::vector<uint8_t> EC_KeyGen::getPublicKeyVec_usingRaw() {
    size_t pub_len = 0;
    std::vector<uint8_t> pubKey_;
    if (EVP_PKEY_get_raw_public_key(this->pkey.get(), nullptr, &pub_len) <= 0 || pub_len <= 0) {
        throw std::runtime_error("Failed to get public key length");
    }

    pubKey_.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(this->pkey.get(), pubKey_.data(), &pub_len) <= 0) {
        throw std::runtime_error("Failed to get public key");
    }
    
    return pubKey_;
}
*/
// One can retrieve the private key as well, although in a production code it may not be desirable to 
// directly access the private without any authentication infrastructure

/*
std::string getPrivateKey() const override{
    char* buffer_data = nullptr;
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_ECPrivateKey(bio, this->mECkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
    long buffer_size = BIO_get_mem_data(bio, &buffer_data);
    std::string privateKeyStr(buffer_data, buffer_size);
    BIO_free(bio);
    return privateKeyStr;
}
*/