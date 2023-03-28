#include "AsymmetricKeyPair.h"
X25519_KeyGen::X25519_KeyGen():
ctx(nullptr, ::EVP_PKEY_CTX_free),
pkey(nullptr, ::EVP_PKEY_free)
{
    this->ctx.reset(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
    if (!ctx.get()) {
        // error handling
    }

    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        // error handling
    }

    EVP_PKEY *pkey_raw = this->pkey.release();
    if (EVP_PKEY_keygen(ctx.get(), &pkey_raw) <= 0) {
        // error handling
    }
    this->pkey.reset(pkey_raw);
}


std::string X25519_KeyGen::getPublicKeyStr() {
    BIO* bio = BIO_new(BIO_s_mem());
    char* buffer;

    if (PEM_write_bio_PUBKEY(bio, this->pkey.get()) != 1) {
        throw std::runtime_error("Failed to write public key from PEM format");
    }
    long length = BIO_get_mem_data(bio, &buffer);
    std::string publicKeyStr(buffer, length);
    BIO_free(bio);
    return publicKeyStr;
}

std::vector<unsigned char> X25519_KeyGen::getPublicKeyVec() {
    int len = i2d_PUBKEY(this->pkey.get(), nullptr); // get the length of the encoded public key
    if (len < 0) {
        // handle error
    }
    std::vector<uint8_t> pubkey(len);
    auto ptr = pubkey.data();
    i2d_PUBKEY(this->pkey.get(), &ptr); // encode the public key and store it in the vector
    // now the encoded public key is stored in the 'encoded' vector
    return pubkey;
}
