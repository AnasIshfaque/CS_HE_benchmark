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
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

int main(){
    std::string cipherOneLocation = "../ciphertext_ckks.txt";

    // Set CryptoContext
    uint32_t multDepth = 1;
    uint32_t scaleModSize = 50;
    uint32_t batchSize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(batchSize);

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


    std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    // Calculate the size of the vector 
    int vecSize = x1.size(); 
    // Calculate the size of any individual element in the 
    // vector 
    int elementSize = sizeof(x1[0]); 
    // Calculate the size of the vector in bytes 
    int size = vecSize * elementSize; 
    std::cout << "Size of vector x1: " << size << " bytes\n";
    // Encrypt the data
    Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(x1);
    std::cout << "Size of plaintext: " << sizeof(ptxt1) << " bytes\n";
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, ptxt1);
    std::cout << "Size of ciphertext: " << sizeof(ciphertext1) << " bytes\n";

    // track the time taken to serialize the ciphertext in microseconds
    auto start = std::chrono::high_resolution_clock::now();

    // Serialize the ciphertext
    Serial::SerializeToFile(cipherOneLocation, ciphertext1, SerType::BINARY);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    //print the time taken to serialize the ciphertext in microseconds

    auto serial_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    std::cout << "Serialization time: " << serial_time_millis << " milliseconds" << std::endl;
    return 0;
}


