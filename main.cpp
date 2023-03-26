#include <iostream>
#include <iomanip>
#include "AsymmetricKeyPair.h"

int main(){
    AsymmetricKeyPair* obj = new AsymmetricKeyPair(eKEY_TYPES::eRSA);

    auto rsaObj = dynamic_cast<RSA_KeyGen*>(obj->generate(2048));
    std::cout<<"PEM Formmatted Public Key:\n";
    std::cout<< rsaObj->getPublicKeyStr()<< std::endl;

    std::cout<<"DER Encoded Public Key:\n";
    auto vec1 = rsaObj->getPublicKeyVec();
    for(int i = 0 ; i < vec1.size(); i++ ){
        std::cout<<std::setfill('0')<<std::setw(2)<<std::hex<<static_cast<unsigned int>(vec1.at(i));
    }
    std::cout<<std::endl<<std::endl;
    
    std::cout<<"Raw Public Key:\n";
    auto vec2 = rsaObj->getPublicKeyVec_usingBN();
    for(int i = 0 ; i < vec2.size(); i++ ){
        std::cout<<std::setfill('0')<<std::setw(2)<<std::hex<<static_cast<unsigned int>(vec2.at(i));
    }
    std::cout<<std::endl;

    return 0;
}