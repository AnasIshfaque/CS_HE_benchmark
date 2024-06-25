#include <iomanip>
#include <tuple>
#include <unistd.h>
#include <ctime>  
#include <chrono> 

#include "seal/seal.h"


using namespace std;
using namespace seal;

// using namespace lbcrypto;

int main(){
    stringstream data_stream;

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 50);

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    // Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> x1;
    x1.reserve(slot_count);

    x1 = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
    // std::cout << "Size of vector x1: " << sizeof(x1) << " bytes\n";
    // Calculate the size of the vector 
    int vecSize = x1.size(); 
    // Calculate the size of any individual element in the 
    // vector 
    int elementSize = sizeof(x1[0]); 
    // Calculate the size of the vector in bytes 
    int size = vecSize * elementSize; 
    // print size of x
    std::cout << "Size of vector x: " << size << " bytes\n";

    Plaintext plain1;
    encoder.encode(x1, scale, plain1);
    std::cout << "Size of plaintext: " << sizeof(plain1) << " bytes\n";

    // auto encrypted1;
    // encryptor.encrypt(plain1, encrypted1);

    // track the time taken to serialize the ciphertext in microseconds
    auto start = std::chrono::high_resolution_clock::now();

    // Serialize the ciphertext
    auto size_encrypted1 = encryptor.encrypt(plain1).save(data_stream);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << "Size of ciphertext: " << size_encrypted1 << " bytes\n";

    //print the time taken to serialize the ciphertext in microseconds
    auto serial_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    std::cout << "Serialization time: " << serial_time_millis << " milliseconds" << std::endl;
    return 0;
}


