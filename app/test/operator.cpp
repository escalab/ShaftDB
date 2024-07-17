/*
 * SQL Operator test
 */

#include "nshedb/nshedb.h"
using namespace seal;
using namespace std;


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("./operation < # runs > \n");
        exit(1);
    }

    int runs = stoi(argv[1]);
    TOC time_parm("[PARAM SETUP] ");
    TOC time_keygen("[KEY GEN] ");
    TOC time_count("[COUT] ");
    TOC time_gt("[GT] ");
    TOC time_gte("[GTE] ");
    TOC time_groupby("[GROUP BY] ");
    TOC time_in("[IN] ");
    TOC time_btw("[BETWEEN] ");
    TOC time_sum("[SUM] ");
    TOC time_avg("[AVG] ");
    TOC time_equal("[EQUAL] ");

    time_parm.start();
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 16384*2; //32768
    size_t plaintext_modulus = 65537;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(plaintext_modulus);
    SEALContext context(parms);
    time_parm.stop();


    time_keygen.start();
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    keygen.create_public_key(public_key);
    keygen.create_relin_keys(relin_keys);
    keygen.create_galois_keys(galois_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Comparator comparator(context);
    BatchEncoder batch_encoder(context);
    Decryptor decryptor(context, secret_key);
    time_keygen.stop();

    print_parameters(context);
    cout << endl;

    int slot_count = batch_encoder.slot_count();
    cout << "Total slots: " << slot_count << endl;
    Plaintext pt, pt_c("0");
    Ciphertext ct;
    vector<int64_t> data(10, slot_count);
    batch_encoder.encode(data, pt);
    encryptor.encrypt(pt, ct);
    for(int k = 0; k < runs; k++) {
        {
            time_equal.start();
            Ciphertext res = comparator.isEqual(evaluator, relin_keys, ct, ct);
            time_equal.pause();
        }
        
        {
            time_count.start();
            Ciphertext res = COUNT(evaluator, ct, slot_count, galois_keys);
            time_count.pause();
        }
        {
            time_gt.start();
            Ciphertext res = GT(comparator, evaluator, relin_keys, ct, pt);
            time_gt.pause();
        }

        {
            time_gte.start();
            Ciphertext res = GTE(comparator, evaluator, relin_keys, ct, pt);
            time_gte.pause();
        }


        {
            vector<Plaintext> p = {pt_c}; //{pt_c, pt_c, pt_c, pt_c};
            time_groupby.start();
            vector<Ciphertext> res = GROUPBY(comparator, evaluator, relin_keys, ct, p);
            time_groupby.pause();
        }


        {
            vector<Plaintext> p = {pt_c}; //{pt_c, pt_c, pt_c, pt_c};
            time_in.start();
            Ciphertext res = IN(comparator, evaluator, relin_keys, ct, p);
            time_in.pause();
        }

        {
            time_btw.start();
            Ciphertext res = BETWEEN(comparator, evaluator, relin_keys, ct, pt_c, pt_c);
            time_btw.pause();
        }

        {
            time_sum.start();
            Ciphertext res = SUM(evaluator, ct, slot_count, galois_keys);
            time_sum.pause();
        }
    }
    time_count.stop(runs, slot_count);
    time_gt.stop(runs, slot_count);
    time_gte.stop(runs, slot_count);
    time_groupby.stop(runs, slot_count);
    time_in.stop(runs, slot_count);
    time_btw.stop(runs, slot_count);
    time_sum.stop(runs, slot_count);
    time_equal.stop(runs, slot_count);
    time_avg.stop(runs, slot_count);
}