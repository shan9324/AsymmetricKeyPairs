#include <iostream>
#include <iomanip>
#include "AsymmetricKeyPair.h"

int main(){
    auto rsaKeygenObj = AsymmetricKeyPair::generate(eKEY_TYPES::eRSA, 2048);
    auto ecKeygenObj = AsymmetricKeyPair::generate(eKEY_TYPES::eEC, NID_secp521r1);
    auto rsaObj = dynamic_cast<RSA_KeyGen*>(rsaKeygenObj);
    auto ecObj = dynamic_cast<EC_KeyGen*>(ecKeygenObj);

    if(!rsaObj)
        throw std::runtime_error("rsaobj = Nullptr");
    
    if(!ecObj)
        throw std::runtime_error("ecObj = Nullptr");

    // Print RSA Object Details
    std::cout<<"PEM Formmatted RSA-Public Key:\n";
    std::cout<< rsaObj->getPublicKeyStr()<< std::endl;

    std::cout<<"DER Encoded  RSA-Public Key:\n";
    auto vec1 = rsaObj->getPublicKeyVec();
    for(int i = 0 ; i < vec1.size(); i++ ){
        std::cout<<std::setfill('0')<<std::setw(2)<<std::hex<<static_cast<unsigned int>(vec1.at(i));
    }
    std::cout<<std::endl<<std::endl;
    
    std::cout<<"Raw RSA-Public Key:\n";
    auto vec2 = rsaObj->getPublicKeyVec_usingBN();
    for(int i = 0 ; i < vec2.size(); i++ ){
        std::cout<<std::setfill('0')<<std::setw(2)<<std::hex<<static_cast<unsigned int>(vec2.at(i));
    }
    std::cout<<std::endl;
    
    std::cout<<"------------------------------------------------------------------------------------------------------------------\n";
    // Print EC Object Details
    std::cout<<"PEM Formmatted EC - Public Key:\n";
    std::cout<< ecObj->getPublicKeyStr()<< std::endl;

    std::cout<<"DER Encoded EC - Public Key:\n";
    auto vec3 = ecObj->getPublicKeyVec();
    for(int i = 0 ; i < vec3.size(); i++ ){
        std::cout<<std::setfill('0')<<std::setw(2)<<std::hex<<static_cast<unsigned int>(vec3.at(i));
    }
    std::cout<<std::endl<<std::endl;

    //Delete dynamic pointer objects
    if(rsaKeygenObj!=nullptr){
        delete rsaKeygenObj ;
        rsaKeygenObj = nullptr;
    }
    
    if(ecKeygenObj!=nullptr){
        delete ecKeygenObj ;
        ecKeygenObj = nullptr;
    }
    
    return 0;
}