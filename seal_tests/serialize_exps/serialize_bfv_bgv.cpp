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

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    // Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();

    cout << "Number of slots: " << slot_count << endl;

    vector<int64_t> x;
    x.reserve(slot_count);

    x = {25, 5, 75, 1, 2, 3, 4, 5};

    // Calculate the size of the vector 
    int vecSize = x.size(); 
    // Calculate the size of any individual element in the 
    // vector 
    int elementSize = sizeof(x[0]); 
    // Calculate the size of the vector in bytes 
    int size = vecSize * elementSize; 
    // print size of x
    std::cout << "Size of vector x: " << size << " bytes\n";
    
    Plaintext plain;
    batch_encoder.encode(x, plain);

    // track the time taken to serialize the ciphertext in microseconds
    auto start = std::chrono::high_resolution_clock::now();

    // Serialize the ciphertext
    auto size_encrypted = encryptor.encrypt(plain).save(data_stream);

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    std::cout << " Size of ciphertext: " << size_encrypted << " bytes\n";

    //print the time taken to serialize the ciphertext in microseconds
    auto serial_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    std::cout << "Serialization time: " << serial_time_millis << " milliseconds" << std::endl;


    return 0;
}


