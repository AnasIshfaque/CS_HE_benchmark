#include "seal/seal.h"
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

using namespace std;
using namespace seal;

void terminateProcess(const char* processName) {
    char command[100];
    std::strcpy(command, "pkill -f ");
    std::strcat(command, processName);
    std::system(command);
}

std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}

int main() {

    // starting the device tracking
    std::thread bash_thread([](){
        std::system("../device_check.sh");
    });

    bash_thread.detach();

    // Get the current time
    auto start_time = std::chrono::system_clock::now();
    auto start_millis = std::chrono::duration_cast<std::chrono::milliseconds>(start_time.time_since_epoch()).count();
    std::time_t current_time = std::chrono::system_clock::to_time_t(start_time);

    // Format the current time as a string
    char start_time_str[100];
    std::strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&current_time));

    // Print the current time including milliseconds
    std::cout << "Start time with milliseconds: " << start_time_str << "." << start_millis % 1000 << std::endl;

    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    // parms.set_plain_modulus(65537);
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    SEALContext context(parms);

    // Key Generation
    auto key_gen_start_time = std::chrono::system_clock::now();

    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    // IntegerEncoder encoder(context);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();


    auto key_gen_end_time = std::chrono::system_clock::now();
    auto key_gen_time = key_gen_end_time - key_gen_start_time;
    auto key_gen_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(key_gen_time).count();

    std::cout << "Key generation time: " << key_gen_time_millis << " milliseconds" << std::endl;

    // Generate three integer vectors
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, 999);

    // Create vectorOfInts1 and populate it with 300 random int64_t values
    vector<uint64_t> vectorOfInts1(1000);
    for (int i = 0; i < 1000; ++i) {
        vectorOfInts1[i] = dis(gen);
    }

    // Create vectorOfInts2 and populate it with 300 random int64_t values
    vector<uint64_t> vectorOfInts2(1000);
    for (int i = 0; i < 1000; ++i) {
        vectorOfInts2[i] = dis(gen);
    }

    // Create vectorOfInts3 and populate it with 300 random int64_t values
    vector<uint64_t> vectorOfInts3(1000);
    for (int i = 0; i < 1000; ++i) {
        vectorOfInts3[i] = dis(gen);
    }

    auto encryption_start_time = std::chrono::system_clock::now();

    // Encode the three vectors
    Plaintext plain1, plain2, plain3;
    batch_encoder.encode(vectorOfInts1, plain1);
    batch_encoder.encode(vectorOfInts2, plain2);
    batch_encoder.encode(vectorOfInts3, plain3);

    Ciphertext encrypted1;
    Ciphertext encrypted2;
    Ciphertext encrypted3;

    encryptor.encrypt(plain1, encrypted1);
    encryptor.encrypt(plain2, encrypted2);
    encryptor.encrypt(plain3, encrypted3);

    // for (int i = 0; i < 1000; ++i) {
    //     Plaintext plain1(uint64_to_hex_string(vectorOfInts1[i]));
    //     Plaintext plain2(uint64_to_hex_string(vectorOfInts2[i]));
    //     Plaintext plain3(uint64_to_hex_string(vectorOfInts3[i]));

    //     Ciphertext encrypted1_temp;
    //     Ciphertext encrypted2_temp;
    //     Ciphertext encrypted3_temp;

    //     encryptor.encrypt(plain1, encrypted1_temp);
    //     encryptor.encrypt(plain2, encrypted2_temp);
    //     encryptor.encrypt(plain3, encrypted3_temp);

    //     encrypted1.push_back(encrypted1_temp);
    //     encrypted2.push_back(encrypted2_temp);
    //     encrypted3.push_back(encrypted3_temp);
    // }

    auto encryption_end_time = std::chrono::system_clock::now();
    auto encryption_time = encryption_end_time - encryption_start_time;
    auto encryption_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(encryption_time).count();
    std::cout << "Encryption time: " << encryption_time_millis << " milliseconds" << std::endl;

    //Evaluation

    // Add the first two vectors, then add the third vector
    auto add_start_time = std::chrono::system_clock::now();
    // auto add_start_time = std::chrono::high_resolution_clock::now();
    Ciphertext sum;

    evaluator.add(encrypted1, encrypted2, sum);
    evaluator.add_inplace(sum, encrypted3);

    // for (int i = 0; i < 1000; ++i) {
    //     Ciphertext sum_temp;
    //     evaluator.add(encrypted1[i], encrypted2[i], sum_temp);
    //     evaluator.add_inplace(sum_temp, encrypted3[i]);
    //     sum.push_back(sum_temp);
    // }

    auto add_end_time = std::chrono::system_clock::now();
    // auto add_end_time = std::chrono::high_resolution_clock::now();
    auto add_time = add_end_time - add_start_time;
    auto add_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(add_time).count();
    // auto add_time_micro = std::chrono::duration_cast<std::chrono::microseconds>(add_time).count();
    std::cout << "Addition time: " << add_time_millis << " milliseconds" << std::endl;

    //Multiply the three vectors
    auto mult_start_time = std::chrono::system_clock::now();
    Ciphertext product;

    evaluator.multiply(encrypted1, encrypted2, product);
    evaluator.multiply_inplace(product, encrypted3);

    // for (int i = 0; i < 1000; ++i) {
    //     Ciphertext product_temp;
    //     evaluator.multiply(encrypted1[i], encrypted2[i], product_temp);
    //     evaluator.multiply_inplace(product_temp, encrypted3[i]);
    //     product.push_back(product_temp);
    // }

    auto mult_end_time = std::chrono::system_clock::now();
    auto mult_time = mult_end_time - mult_start_time;
    auto mult_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(mult_time).count();
    std::cout << "Multiplication time: " << mult_time_millis << " milliseconds" << std::endl;

    // Rotation
    auto rot_start_time = std::chrono::system_clock::now();

    // Rotate the first vector to the left by 1
    Ciphertext rotated1;
    evaluator.rotate_rows(encrypted1, 1, galois_keys, rotated1);
    // for (int i = 0; i < 1000; ++i) {
    //     Ciphertext rotated_temp;
    //     evaluator.rotate_rows(encrypted1[i], 1, galois_keys, rotated_temp);
    //     rotated1.push_back(rotated_temp);
    // }

    // Rotate the first vector to the left by 2
    Ciphertext rotated2;
    evaluator.rotate_rows(encrypted1, 2, galois_keys, rotated2);
    // for (int i = 0; i < 1000; ++i) {
    //     Ciphertext rotated_temp;
    //     evaluator.rotate_rows(encrypted1[i], 2, galois_keys, rotated_temp);
    //     rotated2.push_back(rotated_temp);
    // }

    // Rotate the first vector to the right by 1
    Ciphertext rotated3;
    evaluator.rotate_rows(encrypted1, -1, galois_keys, rotated3);
    // for (int i = 0; i < 1000; ++i) {
    //     Ciphertext rotated_temp;
    //     evaluator.rotate_rows(encrypted1[i], -1, galois_keys, rotated_temp);
    //     rotated3.push_back(rotated_temp);
    // }

    // Rotate the first vector to the right by 2
    Ciphertext rotated4;
    evaluator.rotate_rows(encrypted1, -2, galois_keys, rotated4);
    // for (int i = 0; i < 1000; ++i) {
    //     Ciphertext rotated_temp;
    //     evaluator.rotate_rows(encrypted1[i], -2, galois_keys, rotated_temp);
    //     rotated4.push_back(rotated_temp);
    // }

    auto rot_end_time = std::chrono::system_clock::now();
    auto rot_time = rot_end_time - rot_start_time;
    auto rot_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(rot_time).count();
    std::cout << "Rotation time: " << rot_time_millis << " milliseconds" << std::endl;

    // Decryption
    // Decrypt the results
    auto decryption_start_time = std::chrono::system_clock::now();

    Plaintext decrypted_sum;
    Plaintext decrypted_product;
    Plaintext decrypted_rotated1;
    Plaintext decrypted_rotated2;
    Plaintext decrypted_rotated3;
    Plaintext decrypted_rotated4;

    decryptor.decrypt(sum, decrypted_sum);
    decryptor.decrypt(product, decrypted_product);
    decryptor.decrypt(rotated1, decrypted_rotated1);
    decryptor.decrypt(rotated2, decrypted_rotated2);
    decryptor.decrypt(rotated3, decrypted_rotated3);
    decryptor.decrypt(rotated4, decrypted_rotated4);
    // for (int i = 0; i < 1000; ++i) {
    //     Plaintext decrypted_sum_temp;
    //     Plaintext decrypted_product_temp;
    //     Plaintext decrypted_rotated1_temp;
    //     Plaintext decrypted_rotated2_temp;
    //     Plaintext decrypted_rotated3_temp;
    //     Plaintext decrypted_rotated4_temp;

    //     decryptor.decrypt(sum[i], decrypted_sum_temp);
    //     decryptor.decrypt(product[i], decrypted_product_temp);
    //     decryptor.decrypt(rotated1[i], decrypted_rotated1_temp);
    //     decryptor.decrypt(rotated2[i], decrypted_rotated2_temp);
    //     decryptor.decrypt(rotated3[i], decrypted_rotated3_temp);
    //     decryptor.decrypt(rotated4[i], decrypted_rotated4_temp);

    //     decrypted_sum.push_back(decrypted_sum_temp);
    //     decrypted_product.push_back(decrypted_product_temp);
    //     decrypted_rotated1.push_back(decrypted_rotated1_temp);
    //     decrypted_rotated2.push_back(decrypted_rotated2_temp);
    //     decrypted_rotated3.push_back(decrypted_rotated3_temp);
    //     decrypted_rotated4.push_back(decrypted_rotated4_temp);
    // }

    auto decryption_end_time = std::chrono::system_clock::now();
    auto decryption_time = decryption_end_time - decryption_start_time;
    auto decryption_time_millis = std::chrono::duration_cast<std::chrono::milliseconds>(decryption_time).count();
    std::cout << "Decryption time: " << decryption_time_millis << " milliseconds" << std::endl;

    // Print the results
    // for (int i = 0; i < 1000; ++i) {
    //     cout << "Sum: " << decrypted_sum[i].to_string() << endl;
    //     cout << "Product: " << decrypted_product[i].to_string() << endl;
    //     cout << "Rotated1: " << decrypted_rotated1[i].to_string() << endl;
    //     cout << "Rotated2: " << decrypted_rotated2[i].to_string() << endl;
    //     cout << "Rotated3: " << decrypted_rotated3[i].to_string() << endl;
    //     cout << "Rotated4: " << decrypted_rotated4[i].to_string() << endl;
    // }

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
    std::cout << "Size of cryptoContext: " << sizeof(context) << " bytes" << std::endl;

    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Terminate the bash script process
    terminateProcess("../device_check.sh");

    return 0;
}