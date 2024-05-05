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
    std::strcpy(command, "pkill -f ");
    std::strcat(command, processName);
    std::system(command);
}

int main() {

    // starting the device tracking
    std::thread bash_thread([](){
        std::system("../laptopcheck.sh");
    });

    bash_thread.detach();

    // std::this_thread::sleep_for(std::chrono::seconds(3));

    // Get the current time
    auto start_time = std::chrono::system_clock::now();
    auto start_millis = std::chrono::duration_cast<std::chrono::milliseconds>(start_time.time_since_epoch()).count();
    std::time_t current_time = std::chrono::system_clock::to_time_t(start_time);

    // Format the current time as a string
    char start_time_str[100];
    std::strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&current_time));

    // Print the current time including milliseconds
    std::cout << "Start time with milliseconds: " << start_time_str << "." << start_millis % 1000 << std::endl;

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
    std::cout << "CKKS scheme is using ring dimension " << cryptoContext->GetRingDimension() << std::endl << std::endl;

    auto key_gen_start_time = std::chrono::system_clock::now();

    // Key Generation
    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey); // not sure

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    auto key_gen_end_time = std::chrono::system_clock::now();
    auto key_gen_time = key_gen_end_time - key_gen_start_time;
    auto key_gen_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(key_gen_time).count();

    std::cout << "Key generation time: " << key_gen_time_millis << " milliseconds" << std::endl;

    // Encryption

    // Creating 3 plaintext vectors with random integers
    // Seed for the random number generator
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::uniform_int_distribution<int64_t> dis(0, 999);

    // Create vectorOfInts1 and populate it with 300 random int64_t values
    // std::vector<int64_t> vectorOfInts1(1000);
    // for (int i = 0; i < 1000; ++i) {
    //     vectorOfInts1[i] = dis(gen);
    // }

    // Create vectorOfInts2 and populate it with 300 random int64_t values
    // std::vector<int64_t> vectorOfInts2(1000);
    // for (int i = 0; i < 1000; ++i) {
    //     vectorOfInts2[i] = dis(gen);
    // }

    // Create vectorOfInts3 and populate it with 300 random int64_t values
    // std::vector<int64_t> vectorOfInts3(1000);
    // for (int i = 0; i < 1000; ++i) {
    //     vectorOfInts3[i] = dis(gen);
    // }

    std::vector<double> x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    std::vector<double> x2 = {5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25};
    // std::vector<double> x3 = {0.45, 0.65, 0.8, 1.3, 4.4, 3.9, 5.8, 2.1};

    auto encryption_start_time = std::chrono::system_clock::now();

    // Encoding as plaintexts
    Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(x1);
    Plaintext ptxt2 = cryptoContext->MakeCKKSPackedPlaintext(x2);
    // Plaintext ptxt3 = cryptoContext->MakeCKKSPackedPlaintext(x3);

    std::cout << "Input x1: " << ptxt1 << std::endl;
    std::cout << "Input x2: " << ptxt2 << std::endl;
    // std::cout << "Input x3: " << ptxt3 << std::endl;

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, ptxt1);
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, ptxt2);
    // auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, ptxt3);

    auto encryption_end_time = std::chrono::system_clock::now();
    auto encryption_time = encryption_end_time - encryption_start_time;
    auto encryption_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(encryption_time).count();
    std::cout << "Encryption time: " << encryption_time_millis << " milliseconds" << std::endl;

    // Evaluation

    auto add_start_time = std::chrono::system_clock::now();
    // Homomorphic additions
    auto ciphertextAdd12     = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    // auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

    auto add_end_time = std::chrono::system_clock::now();
    auto add_time = add_end_time - add_start_time;
    auto add_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(add_time).count();
    std::cout << "Addition time: " << add_time_millis << " milliseconds" << std::endl;


    auto mult_start_time = std::chrono::system_clock::now();
    // Homomorphic multiplications
    auto ciphertextMul12      = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    // auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);

    auto mult_end_time = std::chrono::system_clock::now();
    auto mult_time = mult_end_time - mult_start_time;
    auto mult_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(mult_time).count();
    std::cout << "Multiplication time: " << mult_time_millis << " milliseconds" << std::endl;

    auto rot_start_time = std::chrono::system_clock::now();
    // Homomorphic rotations
    auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    auto rot_end_time = std::chrono::system_clock::now();
    auto rot_time = rot_end_time - rot_start_time;
    auto rot_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(rot_time).count();
    std::cout << "Rotation time: " << rot_time_millis << " milliseconds" << std::endl;

    auto decryption_start_time = std::chrono::system_clock::now();
    // Decryption
    std::cout.precision(8);
    // Decrypt the result of additions
    Plaintext result;

    // Decrypt the result of addition
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextAdd12, &result);
    result->SetLength(batchSize);
    std::cout << "x1 + x2 = " << result;
    std::cout << "Estimated precision in bits: " << result->GetLogPrecision() << std::endl;


    // Decrypt the result of multiplication
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12, &result);
    result->SetLength(batchSize);
    std::cout << "x1 * x2 = " << result << std::endl;


    // Decrypt the result of rotations
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &result);
    result->SetLength(batchSize);
    std::cout << std::endl << "In rotations, very small outputs (~10^-10 here) correspond to 0's:" << std::endl;
    std::cout << "x1 rotate by 1 = " << result << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &result);
    result->SetLength(batchSize);
    std::cout << "x1 rotate by 2 = " << result << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &result);
    result->SetLength(batchSize);
    std::cout << "x1 rotate by -1 = " << result << std::endl;

    cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &result);
    result->SetLength(batchSize);
    std::cout << "x1 rotate by -2 = " << result << std::endl;
    
    auto decryption_end_time = std::chrono::system_clock::now();
    auto decryption_time = decryption_end_time - decryption_start_time;
    auto decryption_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(decryption_time).count();
    std::cout << "Decryption time: " << decryption_time_millis << " milliseconds" << std::endl;

    // std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    // std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    // std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // Output results
    // std::cout << "\nResults of homomorphic computations" << std::endl;
    // std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    // std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    // std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    // std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    // std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    // std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    // Get the end time
    auto end_time = std::chrono::system_clock::now();
    auto end_millis = std::chrono::duration_cast<std::chrono::milliseconds>(end_time.time_since_epoch()).count();

    std::time_t full_end_time = std::chrono::system_clock::to_time_t(end_time);

    // Format the current time as a string
    char end_time_str[100];
    std::strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&full_end_time));

    // Print the current time including milliseconds
    std::cout << "End time with milliseconds: " << end_time_str << "." << end_millis % 1000 << std::endl;

    // Calculate the difference in milliseconds
    auto duration = end_time - start_time;
    auto duration_millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

    std::cout << "Duration: " << duration_millis << " milliseconds" << std::endl;

    // Print the size of cryptoContext
    std::cout << "Size of cryptoContext: " << sizeof(*cryptoContext) << " bytes" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Terminate the bash script process
    terminateProcess("../laptopcheck.sh");

    return 0;
}
