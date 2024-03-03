/*
 * Test for packing multiple return values into one ciphertext
 */
#include <map> // for verification
#include "shaftdb/shaftdb.h"
using namespace seal;
using namespace std;


int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("./tpch1 < # runs > < # numEle > < debug mode >\n"
            "[Debug Mode]\n0 - no debug\n"
            "1 - verify once at the end\n"
            "2 - verify each operation\n");
        exit(1);
    }

    int runs = stoi(argv[1]);
    int numEle = stoi(argv[2]);
    int debug = stoi(argv[3]);
    TOC time_parm("[PARAM SETUP] ");
    TOC time_keygen("[KEY GEN] ");
    TOC time_tpch("[TPCH-1] ");
    TOC time_groupby("[GROUP BY] ");
    TOC time_select("[SELECT] ");
    TOC time_where("[WHERE] ");
    TOC time_filter("[FILTER] ");
    TOC time_agg("[AGG] ");
    TOC time_mem_saving("EXTRA OVERHEAD FOR MEMORY SAVING: ");

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

    cout << "Total slots: " << slot_count << endl;
    cout << "Total elements: " << numEle << endl;
    cout << "Evaluator size: " << sizeof(evaluator) << "bytes" << endl;
    cout << "Comparator size: " << sizeof(comparator) << "bytes" << endl;
    cout << "Batch encoder: " << sizeof(batch_encoder) << "bytes" << endl;
    std::cout << " ZZZZ " << std::endl;

   for(int k = 0; k < runs; k++)
    {
        std::cout << "IN SIDE !!!" << std::endl;
        /*
         Prepare Data...
        */
        vector<int64_t> l_shipdate, l_quantity, l_extendedprice, l_discount, 
                        l_returnflag, l_linestatus, l_tax,
                        l_disc_price, l_charge;
        vector<Plaintext> ptxt_returnflag = {Plaintext("1"),
                                            Plaintext("2"),
                                            Plaintext("3")};
        vector<Plaintext> ptxt_linestatus = {Plaintext("1"),
                                            Plaintext("2")};

        srand (time(NULL));
        for (int i = 0; i < numEle; i++) {
            l_shipdate.push_back(rand()%1000 - 3000);
            l_quantity.push_back(rand()%50);
            l_extendedprice.push_back(rand()%201);
            l_discount.push_back(rand()%11);
            l_returnflag.push_back((rand()%3)+1);
            l_linestatus.push_back((rand()%2)+1);
            l_tax.push_back(rand()%5);
            l_disc_price.push_back(l_extendedprice[i] * ((100-l_discount[i]/100)));
            l_charge.push_back(l_disc_price[i]*(100+l_tax[i])/100);
        }

        Plaintext ptxt_l_shipdate, ptxt_l_quantity, ptxt_l_extendedprice, 
                  ptxt_l_discount, ptxt_l_returnflag, ptxt_l_linestatus,
                  ptxt_l_tax, ptxt_l_charge, ptxt_l_disc_price;
        Ciphertext ctxt_l_shipdate, ctxt_l_quantity, ctxt_l_extendedprice, 
                  ctxt_l_discount, ctxt_l_returnflag, ctxt_l_linestatus,
                  ctxt_l_tax, ctxt_l_charge, ctxt_l_disc_price;
        batch_encoder.encode(l_disc_price, ptxt_l_disc_price);
        batch_encoder.encode(l_charge, ptxt_l_charge);
        batch_encoder.encode(l_shipdate, ptxt_l_shipdate);
        batch_encoder.encode(l_quantity, ptxt_l_quantity);
        batch_encoder.encode(l_extendedprice, ptxt_l_extendedprice);
        batch_encoder.encode(l_discount, ptxt_l_discount);
        batch_encoder.encode(l_linestatus, ptxt_l_linestatus);
        batch_encoder.encode(l_returnflag, ptxt_l_returnflag);
        batch_encoder.encode(l_tax, ptxt_l_tax);
        encryptor.encrypt(ptxt_l_charge, ctxt_l_charge);
        encryptor.encrypt(ptxt_l_disc_price, ctxt_l_disc_price);
        encryptor.encrypt(ptxt_l_shipdate, ctxt_l_shipdate);
        encryptor.encrypt(ptxt_l_quantity, ctxt_l_quantity);
        encryptor.encrypt(ptxt_l_extendedprice, ctxt_l_extendedprice);
        encryptor.encrypt(ptxt_l_discount, ctxt_l_discount);
        encryptor.encrypt(ptxt_l_linestatus, ctxt_l_linestatus);
        encryptor.encrypt(ptxt_l_returnflag, ctxt_l_returnflag);
        encryptor.encrypt(ptxt_l_tax, ctxt_l_tax);
        
        stringstream data_stream;
        auto dataSize = ctxt_l_shipdate.save(data_stream);
        auto pksze = public_key.save(data_stream);
        auto rlksz = relin_keys.save(data_stream);
        auto gsz = galois_keys.save(data_stream);
        auto sksz = secret_key.save(data_stream);
        cout << "Ctxt size: " << dataSize << "bytes" << endl;
        cout << "publick key: " << pksze << "bytes" << endl;
        cout << "rlk size: " << rlksz << "bytes" << endl;
        cout << "gal size: " << gsz << "bytes" << endl;
        cout << "sk size: " << sksz << "bytes" << endl;
        
        /*
         Query Starts...
        */
        Ciphertext ctxt_result;
        //l_shipdate <= date '1998-12-01'- interval '90' day
        time_tpch.start();
        time_where.start();
        time_filter.start();
        Ciphertext lte_l_shipdate;
        Plaintext tgt_lte_l_shipdate(intToHex(toDays(Date{1998,12,01})-90, plaintext_modulus));
        lte_l_shipdate = LTE(comparator, evaluator, relin_keys, ctxt_l_shipdate, tgt_lte_l_shipdate);
        time_tpch.pause();
        time_where.pause();
        time_filter.pause();


        // groupby returnflag, linestatus
        time_tpch.start();
        time_groupby.start();
        time_filter.start();
        vector<Ciphertext> ctxt_res_grp;
        vector<Ciphertext> ctxt_group = {ctxt_l_returnflag, ctxt_l_linestatus};
        vector<vector<Plaintext>> ptxt_groups = {ptxt_returnflag, 
                                                ptxt_linestatus};
        ctxt_res_grp = GROUPBY(comparator, evaluator, relin_keys, ctxt_group, ptxt_groups);
        time_tpch.pause();
        time_groupby.pause();
        time_filter.pause();

        time_tpch.start();
        time_select.start();
        time_agg.start();
        Plaintext ptxt_mask;
        for(int i = 0; i < ctxt_res_grp.size(); i++) {
            Ciphertext ctxt_sum_qty, ctxt_sum_base_price, ctxt_sum_disc_price, 
                        ctxt_sum_charge, ctxt_count_order, ctxt_sum_disc;
            vector<Ciphertext>  ctxt_avg_price, ctxt_avg_qty, ctxt_avg_disc;
            
            evaluator.multiply_inplace(ctxt_res_grp[i], lte_l_shipdate);
            evaluator.relinearize_inplace(ctxt_res_grp[i], relin_keys);
            //count(*) as count_order
            ctxt_count_order = COUNT(evaluator, ctxt_res_grp[i], slot_count, galois_keys);
      
            //sum(l_quantity) as sum_qty
            evaluator.multiply(ctxt_l_quantity, ctxt_res_grp[i], ctxt_sum_qty);
            evaluator.relinearize_inplace(ctxt_sum_qty, relin_keys);
            ctxt_sum_qty = SUM(evaluator, ctxt_sum_qty, slot_count, galois_keys);

            //sum(l_extendedprice) as sum_base_price
            evaluator.multiply(ctxt_l_extendedprice, ctxt_res_grp[i], ctxt_sum_base_price);
            evaluator.relinearize_inplace(ctxt_sum_base_price, relin_keys);
            ctxt_sum_base_price = SUM(evaluator, ctxt_sum_base_price, slot_count, galois_keys);

            // sum(l_extendedprice * (1 - l_discount)) as sum_disc_price ,
            evaluator.multiply(ctxt_l_disc_price, ctxt_res_grp[i], ctxt_sum_disc_price);
            evaluator.relinearize_inplace(ctxt_sum_disc_price, relin_keys);
            ctxt_sum_disc_price = SUM(evaluator, ctxt_sum_disc_price, slot_count, galois_keys);

            // sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)) as sum_charge
            evaluator.multiply(ctxt_l_charge, ctxt_res_grp[i], ctxt_sum_charge);
            evaluator.relinearize_inplace(ctxt_sum_charge, relin_keys);
            ctxt_sum_charge = SUM(evaluator, ctxt_sum_charge, slot_count, galois_keys);

            // avg(l_quantity) as avg_qty
            // Return SUM(l_quantity) and COUNT. We don't need to calculate again.
            ctxt_avg_qty = {ctxt_sum_qty, ctxt_count_order};

            // avg(l_extendedprice) as avg_price
            // Return SUM(l_extendedprice) and COUNT. We don't need to calculate again.
            ctxt_avg_price = {ctxt_sum_base_price, ctxt_count_order};

            //avg(l_discount) as avg_disc
            evaluator.multiply(ctxt_l_discount, ctxt_res_grp[i], ctxt_sum_disc);
            evaluator.relinearize_inplace(ctxt_sum_disc, relin_keys);
            ctxt_sum_disc = SUM(evaluator, ctxt_sum_disc, slot_count, galois_keys);
        
            ctxt_avg_disc = {ctxt_sum_disc, ctxt_count_order};

            Ciphertext tmp;
            time_mem_saving.start();
            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 2] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_sum_qty, ptxt_mask);
            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 3] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_sum_base_price, ptxt_mask);
            evaluator.add(ctxt_sum_qty, ctxt_sum_base_price, ctxt_result);

            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 4] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_sum_disc_price, ptxt_mask);
            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 5] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_sum_charge, ptxt_mask);
            evaluator.add(ctxt_sum_disc_price, ctxt_sum_charge, tmp);
            evaluator.add_inplace(ctxt_result, tmp);

            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 6] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_avg_qty[0], ptxt_mask);
            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 7] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_avg_qty[1], ptxt_mask); 
            evaluator.add(ctxt_avg_qty[0], ctxt_avg_qty[1], tmp);
            evaluator.add_inplace(ctxt_result, tmp);


            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 8] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_avg_price[0], ptxt_mask);
            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 9] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_avg_price[1], ptxt_mask); 
            evaluator.add(ctxt_avg_price[0], ctxt_avg_price[1], tmp);
            evaluator.add_inplace(ctxt_result, tmp);


            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 8] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_avg_disc[0], ptxt_mask);
            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*10 + 9] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_avg_disc[1], ptxt_mask); 
            evaluator.add(ctxt_avg_disc[0], ctxt_avg_disc[1], tmp);
            evaluator.add_inplace(ctxt_result, tmp);

            {
                vector<int64_t> mask(slot_count, 0);
                mask[i*11 + 10] = 1;
                batch_encoder.encode(mask, ptxt_mask);
            }
            evaluator.multiply_plain_inplace(ctxt_count_order, ptxt_mask); 
            evaluator.add_inplace(ctxt_result, ctxt_count_order);
        }

        auto context_data = context.first_context_data();
        while (context_data->next_context_data())
        {
            evaluator.mod_switch_to_next_inplace(ctxt_result);
            context_data = context_data->next_context_data();
        }
        time_agg.pause();
        time_tpch.pause();
        
    }
    time_mem_saving.stop(runs);
    time_tpch.stop(runs);
    time_agg.stop(runs);
    time_filter.stop(runs);
    
    cout << "Verify skipped. Done" << endl;
    return 0;
}