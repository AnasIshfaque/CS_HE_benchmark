#include <iomanip>
#include <tuple>
#include <unistd.h>
#include <ctime>  
#include <chrono> 

#include "openfhe.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
// #include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

int main(){
    std::string cipherOneLocation = "../ciphertext_bfv.txt";

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(4);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Generate keys
    // Key Generation
    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();


    std::vector<int64_t> x1 = {25, 5, 75, 1, 2, 3, 4, 5};
    // Calculate the size of the vector 
    int vecSize = x1.size(); 
    // Calculate the size of any individual element in the 
    // vector 
    int elementSize = sizeof(x1[0]); 
    // Calculate the size of the vector in bytes 
    int size = vecSize * elementSize; 
    std::cout << "Size of vector x1: " << size << " bytes\n";
    // Encrypt the data
    Plaintext ptxt1 = cryptoContext->MakePackedPlaintext(x1);
    std::cout << "Size of plaintext: " << sizeof(ptxt1) << " bytes\n";
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, ptxt1);
    std::cout << "Size of ciphertext: " << sizeof(ciphertext1) << " bytes\n";

    // track the time taken to serialize the ciphertext in milliseconds
    auto start = std::chrono::high_resolution_clock::now();

    // Serialize the ciphertext
    Serial::SerializeToFile(cipherOneLocation, ciphertext1, SerType::BINARY);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;

    // print the time taken to serialize the ciphertext in milliseconds
    std::cout << "Serialization time: " << elapsed.count() << " milliseconds" << std::endl;

    return 0;
}


