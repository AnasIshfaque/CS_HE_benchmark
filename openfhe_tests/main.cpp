#include "openfhe.h"
#include <iostream>
#include <cstdlib>
#include <cstdio> 
#include <cstring>
#include <chrono> 
#include <thread> 
#include <ctime>  

#include <vector>
#include <random>
#include <cstdint>

using namespace lbcrypto;

void terminateProcess(const char* processName) {
    char command[100];
    std::strcpy(command, "pkill ");
    std::strcat(command, processName);
    std::system(command);
}

int main() {
    // starting the device tracking
    std::thread bash_thread([](){
        std::system("../rasp_check.sh");
    });

    bash_thread.detach();

    // std::this_thread::sleep_for(std::chrono::seconds(10));

    // Get the current time
    auto now = std::chrono::system_clock::now();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    std::time_t current_time = std::chrono::system_clock::to_time_t(now);

    // Format the current time as a string
    char time_str[100];
    std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&current_time));

    // Print the current time including milliseconds
    std::cout << "Start time with milliseconds: " << time_str << "." << millis % 1000 << std::endl;

    // Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    // Key Generation
    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey); // not sure

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    // Encryption
    // Creating 3 plaintext vectors with random integers
    // Seed for the random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dis(std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max());

    // Create vectorOfInts1 and populate it with 300 random int64_t values
    std::vector<int64_t> vectorOfInts1(300);
    for (int i = 0; i < 300; ++i) {
        vectorOfInts1[i] = dis(gen);
    }

    // Create vectorOfInts2 and populate it with 300 random int64_t values
    std::vector<int64_t> vectorOfInts2(300);
    for (int i = 0; i < 300; ++i) {
        vectorOfInts2[i] = dis(gen);
    }

    // Create vectorOfInts3 and populate it with 300 random int64_t values
    std::vector<int64_t> vectorOfInts3(300);
    for (int i = 0; i < 300; ++i) {
        vectorOfInts3[i] = dis(gen);
    }
    // First plaintext vector is encoded
    // std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    // std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    // Third plaintext vector is encoded
    // std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3               = cryptoContext->MakePackedPlaintext(vectorOfInts3);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);

    // Evaluation

    // Homomorphic additions
    auto ciphertextAdd12     = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

    // Homomorphic multiplications
    auto ciphertextMul12      = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

    // Homomorphic rotations
    auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    // Decryption

    // Decrypt the result of additions
    Plaintext plaintextAddResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);

    // Decrypt the result of multiplications
    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMultResult);

    // Decrypt the result of rotations
    Plaintext plaintextRot1;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
    Plaintext plaintextRot2;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
    Plaintext plaintextRot3;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
    Plaintext plaintextRot4;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

    plaintextRot1->SetLength(vectorOfInts1.size());
    plaintextRot2->SetLength(vectorOfInts1.size());
    plaintextRot3->SetLength(vectorOfInts1.size());
    plaintextRot4->SetLength(vectorOfInts1.size());

    std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // Output results
    std::cout << "\nResults of homomorphic computations" << std::endl;
    std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    // Get the current time
    auto end_time = std::chrono::system_clock::now();
    auto end_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(end_time.time_since_epoch()).count();
    std::time_t full_end_time = std::chrono::system_clock::to_time_t(end_time);

    // Format the current time as a string
    char end_time_str[100];
    std::strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&full_end_time));

    // Print the current time including milliseconds
    std::cout << "End time with milliseconds: " << end_time_str << "." << end_time_millis % 1000 << std::endl;

    // std::this_thread::sleep_for(std::chrono::seconds(10));

    // Terminate the bash script process
    terminateProcess("../rasp_check.sh");

    return 0;
}