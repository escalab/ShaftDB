/*
 * Test for the case that BETWEEN is evaluated in the same way as IN
*/

#include "nshedb/nshedb.h"
using namespace seal;
using namespace std;

void verify(vector<int64_t> l_shipdate, vector<int64_t> l_quantity, vector<int64_t> l_extendedprice, vector<int64_t> l_discount, int64_t res)
{
    int64_t sum = 0;
    for(int i=0; i < l_shipdate.size(); i++) {
        int64_t tmp = 0;
        if(l_shipdate[i] >= toDays(Date{1994,1,1})  && l_shipdate[i] < (toDays(Date{1994,1,1})+365) && l_quantity[i] < 24 && (l_discount[i] >= 5 && l_discount[i] <= 7))
        {
            tmp = (l_extendedprice[i] * l_discount[i]);
        }
        sum += tmp;
    }
    if (sum != res) {
        printf("SUM Expected: %ld Result: %ld\n", sum, res);
        exit(1);
    }
}


int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("./tpch6 < # runs > < # numEle > < debug mode >\n"
            "[Debug Mode]\n0 - no debug\n"
            "1 - verify once at the end\n"
            "2 - verify after each operation\n");
        exit(1);
    }

    int runs = stoi(argv[1]);
    int numEle = stoi(argv[2]);
    int debug = stoi(argv[3]);
    TOC time_parm("[PARAM SETUP] ");
    TOC time_keygen("[KEY GEN] ");
    TOC time_tpch("[TPCH-6] ");
    TOC time_select("[SELECT] ");
    TOC time_where("[WHERE] ");
    TOC time_filter("[FILTER] ");
    TOC time_agg("[AGG] ");

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
    cout << "Total elements: " << numEle << endl;

    for(int i = 0; i < runs; i++)
    {
        vector<int64_t> l_shipdate, l_quantity, l_extendedprice, l_discount;
        srand (time(NULL));
        for (int i = 0; i < numEle; i++) {
            l_shipdate.push_back(rand()%1000-3000);
            l_quantity.push_back(rand()%50);
            l_extendedprice.push_back(rand()%201);
            l_discount.push_back(rand()%11);
        }

        Plaintext ptxt_l_shipdate, ptxt_l_quantity, ptxt_l_extendedprice, ptxt_l_discount;
        Ciphertext ctxt_l_shipdate, ctxt_l_quantity, ctxt_l_extendedprice, ctxt_l_discount;
        batch_encoder.encode(l_shipdate, ptxt_l_shipdate);
        batch_encoder.encode(l_quantity, ptxt_l_quantity);
        batch_encoder.encode(l_extendedprice, ptxt_l_extendedprice);
        batch_encoder.encode(l_discount, ptxt_l_discount);
        encryptor.encrypt(ptxt_l_shipdate, ctxt_l_shipdate);
        encryptor.encrypt(ptxt_l_quantity, ctxt_l_quantity);
        encryptor.encrypt(ptxt_l_extendedprice, ctxt_l_extendedprice);
        encryptor.encrypt(ptxt_l_discount, ctxt_l_discount);
        
        
        //l_shipdate >= date '1994-01-01' 
        time_tpch.start();
        time_where.start();
        Plaintext tgt_gte_l_shipdate(intToHex(toDays(Date{1994,01,01}), plaintext_modulus));
        Ciphertext gte_shipdate = GTE(comparator, evaluator, relin_keys, ctxt_l_shipdate, tgt_gte_l_shipdate);

        if(debug == 2) {
            time_tpch.pause();
            time_where.pause();
            cout << "1994 01 01: " << toDays(Date{1994,01,01}) <<endl;
            print_vec("L_SHIPDATE", l_shipdate, numEle);
            vector<int64_t>l_debug = print_dec_<int64_t>("l_shipdate >= date '1994-01-01", gte_shipdate, numEle, batch_encoder, decryptor);
            for(int i = 0; i < numEle; i++) {
                int cond;
                if(l_shipdate[i] >= toDays(Date{1994, 01, 01})) cond = 1;
                else cond = 0;
                if (cond != l_debug[i]){
                    printf("res[%d] Expected: %d Result: %ld\n", i, cond, l_debug[i]);
                    exit(1);
                }
            }
            time_tpch.start();
            time_where.start();
        }


        //l_shipdate < date '1994-01-01' + interval '1' year
        Plaintext tgt_lt_l_shipdate(intToHex(toDays(Date{1994,01,01})+365, plaintext_modulus));
        Ciphertext lt_shipdate = LT(comparator, evaluator, relin_keys, ctxt_l_shipdate, tgt_lt_l_shipdate);
        if(debug == 2) {
             time_tpch.pause();
            time_where.pause();
            cout << "1994 01 01 + 365: " << toDays(Date{1994,01,01}) + 365 <<endl;
            print_vec("L_SHIPDATE", l_shipdate, numEle);
            vector<int64_t>l_debug = print_dec_<int64_t>("l_shipdate < date '1994-01-01' + interval '1' year", lt_shipdate, numEle, batch_encoder, decryptor);
            for(int i = 0; i < numEle; i++) {
                int cond;
                if(l_shipdate[i] < toDays(Date{1994, 01, 01})+365) cond = 1;
                else cond = 0;
                if (cond != l_debug[i]){
                    printf("res[%d] Expected: %d Result: %ld\n", i, cond, l_debug[i]);
                    exit(1);
                }
            }         
            time_tpch.start();
            time_where.start();             
        }
        
        Ciphertext btw_discount;
        vector<Ciphertext> tmp;
        for(int i = 5; i < 8; i++) {
            Plaintext tgt_l_discount(intToHex(i, plaintext_modulus));
            tmp.push_back(comparator.isEqual(evaluator, relin_keys, ctxt_l_discount, tgt_l_discount));
        }
        evaluator.multiply_inplace(tmp[0], tmp[1]);
        evaluator.relinearize_inplace(tmp[0], relin_keys);
        evaluator.multiply(tmp[0], tmp[2], btw_discount);
        evaluator.relinearize_inplace(btw_discount, relin_keys);
        if(debug == 2) {
            time_tpch.pause();
            time_where.stop();
            print_vec("L_DISCOUNT", l_discount, numEle);
            vector<int64_t>l_debug = print_dec_<int64_t>("l_discount between 0.06 - 0.01 AND 0.06 + 0.01", btw_discount, numEle, batch_encoder, decryptor);
            for(int i = 0; i < numEle; i++) {
                int cond;
                if(l_discount[i] <= 7 && l_discount[i] >= 5) cond = 1;
                else cond = 0;
                if (cond != l_debug[i]){
                    printf("res[%d] Expected: %d Result: %ld\n", i, cond, l_debug[i]);
                    exit(1);
                }
            }
            time_tpch.start();
            time_where.start();
        }

        
        //l_quantity < 24;
        Plaintext tgt_lt_l_quantity(intToHex(24, plaintext_modulus));
        Ciphertext lt_quantity = LT(comparator, evaluator, relin_keys, ctxt_l_quantity, tgt_lt_l_quantity);
        
        if(debug == 2){
            time_tpch.pause();
            time_where.pause();
            print_vec("L_QUANTITY", l_quantity, numEle);
            vector<int64_t>l_debug = print_dec_<int64_t>("l_quantity < 24", lt_quantity, numEle, batch_encoder, decryptor);
            for(int i = 0; i < numEle; i++) {
                int cond;
                if(l_quantity[i] < 24) cond = 1;
                else cond = 0;
                if (cond != l_debug[i]) {
                    printf("res[%d] Expected: %d Result: %ld\n", i, cond, l_debug[i]);
                    exit(1);
                }
            }
            time_tpch.start();
            time_where.start();
        }


        // Combining predicates
        Ciphertext tmp_res1, filter;
        evaluator.multiply(gte_shipdate, lt_shipdate, tmp_res1);
        evaluator.relinearize_inplace(tmp_res1, relin_keys);
        evaluator.multiply(tmp_res1, btw_discount, filter);
        evaluator.relinearize_inplace(filter, relin_keys);
        evaluator.multiply_inplace(filter, lt_quantity);
        evaluator.relinearize_inplace(filter, relin_keys);
        time_tpch.pause();
        time_where.pause();


        time_tpch.start();
        time_select.start();
        // sum(l_extendedprice * l_discount) as revenue
        Ciphertext ctxt_res;
        evaluator.multiply(ctxt_l_extendedprice, ctxt_l_discount, ctxt_res);
        evaluator.relinearize_inplace(ctxt_res, relin_keys);
        evaluator.multiply_inplace(ctxt_res, filter);
        evaluator.relinearize_inplace(ctxt_res, relin_keys);
        ctxt_res = SUM(evaluator, ctxt_res, slot_count, galois_keys);


        time_tpch.pause();
        time_select.pause();

        if(debug != 0) {
            vector<int64_t> res = print_dec_<int64_t>("RES", ctxt_res, numEle, batch_encoder, decryptor);
            verify(l_shipdate, l_quantity, l_extendedprice, l_discount, res[0]);
        }
        cout << "    + noise budget left: " << decryptor.invariant_noise_budget(ctxt_res) << " bits"
        << endl;
    }
    time_tpch.stop(runs);
    time_agg.stop(runs);
    time_filter.stop(runs);
    cout<<"========="<<endl;
    time_select.stop(runs);
    time_where.stop(runs);

    if(debug != 0)
        cout << "Verified. Done.\n";
    else
        cout << "Verify skipped. Done" << endl;
    return 0;
}