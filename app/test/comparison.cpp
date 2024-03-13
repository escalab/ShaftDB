/*
 * Comparison tests
 */
#include "shaftdb/shaftdb.h"
using namespace seal;

template<typename T>
void verifyIneq(std::vector<T> a,
            std::vector<T> b,
            std::vector<T> res)
{
    for(int i = 0; i < a.size(); i++)
    {
        if(res[i] != (a[i]<b[i]))
        {
            print_matrix(res, a.size()/2);
            printf("a: %ld < b: %ld\nres[%d] Expected: %d Result: %ld\n", a[i], b[i],i, a[i]<b[i], res[i]);
            std::exit(1);
        }
    }
}

template<typename T>
void verifyEq(std::vector<T> a,
            std::vector<T> b,
            std::vector<T> res)
{
    for(int i = 0; i < a.size(); i++)
    {
        if(res[i] != (a[i]==b[i]))
        {
            print_matrix(res, a.size()/2);
            printf("a: %ld, b: %ld\nres[%d] Expected: %d Result: %ld\n", a[i], b[i],i, a[i]==b[i], res[i]);
            std::exit(1);
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cout << "./comparison < # runs > <debug mode=1/0>" << std::endl;
        std::exit(1);
    }
    int runs = std::stoi(argv[1]);
    int debug = std::stoi(argv[1]);

    TOC time_parm("[PARAM SETUP] ");
    TOC time_eval_eq("[COMPARE EQ] ");
    TOC time_eval_lte("[COMPARE LTE] ");
    TOC time_keygen("[KEY GEN] ");

    time_parm.start();
    EncryptionParameters parms(scheme_type::bfv);
    size_t plaintext_modulus = 65537;
    size_t poly_modulus_degree = 16384 *2;//8192; //16384*2;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(plaintext_modulus);
    SEALContext context(parms);
    time_parm.stop();

    print_parameters(context);
    std::cout << std::endl;


    time_keygen.start();
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Comparator comparator(context);


    BatchEncoder batch_encoder(context);
    Decryptor decryptor(context, secret_key);
    time_keygen.stop();

    std::cout << "Total Elements: " << batch_encoder.slot_count() << std::endl;

    for(int i = 0; i < runs; i++)
    {
        size_t slot_count = batch_encoder.slot_count();
        std::vector<int64_t> input_A, input_B;
        srand (time(NULL));
        for (int i = 0; i < slot_count; i++)
        {
            input_A.push_back(rand() % plaintext_modulus/2);
            input_B.push_back(rand() % plaintext_modulus/2);
        }

        Plaintext plain_input_A, plain_input_B;
        batch_encoder.encode(input_A, plain_input_A);
        batch_encoder.encode(input_B, plain_input_B);
        Ciphertext ctxt_inputA, ctxt_inputB;
        encryptor.encrypt(plain_input_A, ctxt_inputA);
        encryptor.encrypt(plain_input_B, ctxt_inputB);
        std::cout << "    + Fresh noise budget: " << decryptor.invariant_noise_budget(ctxt_inputA) << " bits" << std::endl;
        
        time_eval_lte.start();
        std::vector<Ciphertext> ctxt_cmp = comparator.isLessThan(evaluator, relin_keys, ctxt_inputA, ctxt_inputB);
        std::cout << "    + LT noise budget: " << decryptor.invariant_noise_budget(ctxt_cmp[0]) << " bits" << std::endl;;
        time_eval_lte.pause();
        
        time_eval_eq.start();
        Ciphertext ctxt_eq = comparator.isEqual(evaluator, relin_keys, ctxt_inputA, ctxt_inputB);
        std::cout << "    + EQ noise budget: " << decryptor.invariant_noise_budget(ctxt_eq) << " bits" << std::endl;;
        time_eval_eq.pause();
        
        Ciphertext lt = ctxt_cmp[0];
        Ciphertext eq = ctxt_cmp[1];

        Plaintext ptxt_lt, ptxt_eq;
        std::vector<int64_t> res_lt, res_eq;
        decryptor.decrypt(lt, ptxt_lt);
        batch_encoder.decode(ptxt_lt, res_lt);
        if(debug) {
            print_matrix(res_lt, batch_encoder.slot_count()/2);
            verifyIneq<int64_t>(input_A, input_B,res_lt);
        }

        decryptor.decrypt(eq, ptxt_eq);
        batch_encoder.decode(ptxt_eq, res_eq);
        if(debug) {
            print_matrix(res_eq, batch_encoder.slot_count()/2);
            verifyEq<int64_t>(input_A, input_B, res_eq);
        }

        decryptor.decrypt(ctxt_eq, ptxt_eq);
        batch_encoder.decode(ptxt_eq, res_eq);
        if(debug) {
            print_matrix(res_eq, batch_encoder.slot_count()/2);
            verifyEq<int64_t>(input_A, input_B, res_eq);
        }
    }
    time_eval_eq.stop(runs);
    time_eval_lte.stop(runs);
    if(debug)
        std::cout << "Verified. Done." << std::endl;
    else
        std::cout << "Verifying skipped. Done" << std::endl;
    return 0;
}