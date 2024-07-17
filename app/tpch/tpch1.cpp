#include <map> // for verification
#include "nshedb/nshedb.h"
using namespace seal;
using namespace std;

void verify(vector<int64_t> l_quantity, vector<int64_t> l_extendedprice, 
            vector<int64_t> l_discount, vector<int64_t> l_returnflag, 
            vector<int64_t> l_linestatus, vector<int64_t> l_shipdate,
            vector<int64_t> l_tax,
            vector<int64_t> sum_qty, vector<int64_t> sum_base_price, 
            vector<int64_t> sum_disc_price, vector<int64_t> sum_charge,
            vector<vector<int64_t>> avg_qty, vector<vector<int64_t>> avg_price,
            vector<vector<int64_t>> avg_disc, vector<int64_t> count_order)
{
    vector<string> index = {"11", "12", "21", "22", "31", "32"};
    map<string, int64_t> sol_sum_qty, sol_sum_base_price, sol_sum_disc_price, 
                         sol_sum_charge, sol_count_order;
    map<string, vector<int64_t>> sol_avg_disc, sol_avg_price, sol_avg_qty;
    
    for(int i = 0; i < index.size(); i++) {
        sol_sum_qty[index[i]] = 0;
        sol_sum_disc_price[index[i]] = 0;
        sol_sum_base_price[index[i]] = 0;
        sol_sum_charge[index[i]] = 0;
        sol_avg_disc[index[i]] = {0, 0};
        sol_avg_price[index[i]] = {0, 0};
        sol_avg_qty[index[i]] = {0, 0};
        sol_count_order[index[i]] = 0;
    }

    for(int i = 0; i < l_quantity.size(); i++) {
        if(l_shipdate[i] <= (toDays(Date{1998, 12, 01})-90)) {
            string comb = to_string(l_returnflag[i]) + to_string(l_linestatus[i]);
            if(sol_sum_qty.find(comb) != sol_sum_qty.end()) {
                sol_sum_qty[comb] += l_quantity[i];
                sol_sum_base_price[comb] += l_extendedprice[i];
                sol_sum_disc_price[comb] += l_extendedprice[i]*(10-l_discount[i]);//l_extendedprice*discount
                sol_sum_charge[comb] += l_extendedprice[i]*(10-l_discount[i])*(10+l_tax[i]); 
                sol_avg_disc[comb][0] += l_discount[i];
                sol_avg_disc[comb][1]++;
                sol_avg_price[comb][0] += l_extendedprice[i];
                sol_avg_price[comb][1]++;
                sol_avg_qty[comb][0] += l_quantity[i];
                sol_avg_qty[comb][1]++;
                sol_count_order[comb]++;
            }
        }
    }


    for(int i = 0; i < index.size(); i++) {
        if(sol_sum_qty[index[i]] != sum_qty[i]){
            printf("SUM_QTY res[%s] Expected: %ld Result: %ld\n", 
                    index[i].c_str(), sol_sum_qty[index[i]], sum_qty[i]);
            exit(1);
        }

        if(sol_sum_disc_price[index[i]] != sum_disc_price[i]){
            printf("SUM_DISC_PRICE res[%s] Expected: %ld Result: %ld\n", 
                    index[i].c_str(), sol_sum_disc_price[index[i]], sum_disc_price[i]);
            exit(1);
        }
        if(sol_sum_charge[index[i]] != sum_charge[i]){
            printf("SUM_CHARGE res[%s] Expected: %ld Result: %ld\n", 
                    index[i].c_str(), sol_sum_charge[index[i]], sum_charge[i]);
            exit(1);
        }
        if(sol_sum_base_price[index[i]] != sum_base_price[i]){
            printf("SUM_BASE_PRICE res[%s] Expected: %ld Result: %ld\n", 
                    index[i].c_str(), sol_sum_base_price[index[i]], sum_base_price[i]);
            exit(1);
        }

        if(sol_avg_disc[index[i]][0] != avg_disc[i][0] 
          && sol_avg_disc[index[i]][1] != avg_disc[i][0]){
            printf("AVG_DISC res[%s] Expected: %ld/%ld Result: %ld/%ld\n", 
                    index[i].c_str(), sol_avg_disc[index[i]][0], sol_avg_disc[index[i]][1],
                    avg_disc[i][0], avg_disc[i][1]);
            exit(1);
        }
  
        if(sol_avg_qty[index[i]][0] != avg_qty[i][0]
          && sol_avg_qty[index[i]][1] != avg_qty[i][1]){
            printf("AVG_QTY res[%s] Expected: %ld/%ld Result: %ld/%ld\n", 
                    index[i].c_str(), sol_avg_qty[index[i]][0], sol_avg_qty[index[i]][1],
                    avg_qty[i][0], avg_qty[i][1]);
            exit(1);
        }
        if(sol_avg_price[index[i]][0] != avg_price[i][0]
          && sol_avg_price[index[i]][1] != avg_price[i][1]){
            printf("AVG_PRICE res[%s] Expected: %ld/%ld Result: %ld/%ld\n", 
                    index[i].c_str(), sol_avg_price[index[i]][0], sol_avg_price[index[i]][1],
                    avg_price[i][0], avg_price[i][1]);
            exit(1);
        }
        if(sol_count_order[index[i]] != count_order[i]){
            printf("COUNT res[%s] Expected: %ld Result: %ld\n", 
                    index[i].c_str(), sol_count_order[index[i]], count_order[i]);
            exit(1);
        }
    }
}

void verify_shipdate_less_than_equal_to_date(Decryptor &decryptor, BatchEncoder &batch_encoder, int numEle, 
                                            Ciphertext lte_l_shipdate, vector<int64_t> l_shipdate)
{
    vector<int64_t> decrypted;
    decrypted = print_dec_<int64_t>("l_shipdate <= date '1998-12-01' - interval '90' day -397-90", 
                                    lte_l_shipdate, numEle, batch_encoder, decryptor);
    for(int i = 0; i < numEle; i++) {
        int64_t res = l_shipdate[i] <= (toDays(Date{1998, 12, 01})-90);
        if (res != decrypted[i]){
            printf("res[%d] Expected: %ld Result: %ld\n", i,res, decrypted[i]);
            exit(1);
        }
    }
}

void verify_count_order(Decryptor &decryptor, BatchEncoder &batch_encoder, int numEle, 
                        vector<Ciphertext> ctxt_count_order, 
                        vector<int64_t> l_shipdate,
                        vector<int64_t> l_returnflag,
                        vector<int64_t> l_linestatus)
{
    map<string, int> m;
    for(int i = 0; i < numEle; i++) {
        if(l_shipdate[i] <= (toDays(Date{1998, 12, 01})-90)) {
            string comb = to_string(l_returnflag[i]) + to_string(l_linestatus[i]);
            if(m.find(comb) != m.end()) {
                m[comb] += 1;
            }
            else m[comb] = 1;
        }
    }
    vector<string> index = {"11", "12", "21", "22", "31", "32"};
    for(int i = 0; i < index.size(); i++) {
        vector<int64_t> decrypted = print_dec_<int64_t>("count(*) as count_order", ctxt_count_order[i], numEle, batch_encoder, decryptor);
        if((m.find(index[i]) == m.end() && decrypted[0] != 0) || (m[index[i]] != decrypted[0])) {
            printf("Expected: %d Result: %ld\n", m[index[i]], decrypted[0]);
            exit(1);
        }
    }
}


void verify_sum_base_price(Decryptor &decryptor, BatchEncoder &batch_encoder, int numEle, 
                        vector<Ciphertext> ctxt_sum_base_price, 
                        vector<int64_t> l_shipdate,
                        vector<int64_t> l_extendedprice,
                        vector<int64_t> l_returnflag,
                        vector<int64_t> l_linestatus)
{
    vector<int64_t> decrypted;
    map<string, int> m;
    for(int i = 0; i < numEle; i++) {
        if(l_shipdate[i] <= (toDays(Date{1998, 12, 01})-90)) {
            string comb = to_string(l_returnflag[i]) + to_string(l_linestatus[i]);
            if(m.find(comb) != m.end()) {
                m[comb] += l_extendedprice[i];
            }
            else m[comb] = l_extendedprice[i];
        }
    }
    vector<string> index = {"11", "12", "21", "22", "31", "32"};
    for(int i = 0; i < index.size(); i++) {
        decrypted = print_dec_<int64_t>("sum(l_extendedprice) as sum_base_price", ctxt_sum_base_price[i], numEle, batch_encoder, decryptor);
        if((m.find(index[i]) == m.end() && decrypted[0] != 0) || (m[index[i]] != decrypted[0])) {
            printf("Expected: %d Result: %ld\n", m[index[i]], decrypted[0]);
            exit(1);
        }
    }   
}


void verify_sum_qty(Decryptor &decryptor, BatchEncoder &batch_encoder, int numEle, 
                    vector<Ciphertext> ctxt_sum_qty, 
                    vector<int64_t> l_shipdate,
                    vector<int64_t> l_quantity,
                    vector<int64_t> l_returnflag,
                    vector<int64_t> l_linestatus)
{
    map<string, int> m;
    vector<int64_t> decrypted;
    for(int i = 0; i < numEle; i++) {
        if(l_shipdate[i] <= (toDays(Date{1998, 12, 01})-90)) {
            string comb = to_string(l_returnflag[i]) + to_string(l_linestatus[i]);
            if(m.find(comb) != m.end()) {
                m[comb] += l_quantity[i];
            }
            else m[comb] = l_quantity[i];
        }
    }
    vector<string> index = {"11", "12", "21", "22", "31", "32"};
    for(int i = 0; i < index.size(); i++) {
        decrypted = print_dec_<int64_t>("sum(l_quantity) as sum_qty", ctxt_sum_qty[i], numEle, batch_encoder, decryptor);
        if((m.find(index[i]) == m.end() && decrypted[0] != 0) || (m[index[i]] != decrypted[0])) {
            printf("Expected: %d Result: %ld\n", m[index[i]], decrypted[0]);
            exit(1);
        }
    }
}

void verify_avg_disc(Decryptor &decryptor, BatchEncoder &batch_encoder, int numEle, 
                        vector<Ciphertext> ctxt_avg_disc, 
                        vector<int64_t> l_shipdate,
                        vector<int64_t> l_discount,
                        vector<int64_t> l_returnflag,
                        vector<int64_t> l_linestatus)
{
    vector<int64_t> decrypted;
    map<string, int> m;
    for(int i = 0; i < numEle; i++) {
        if(l_shipdate[i] <= (toDays(Date{1998, 12, 01})-90)) {
            string comb = to_string(l_returnflag[i]) + to_string(l_linestatus[i]);
            if(m.find(comb) != m.end()) {
                m[comb] += l_discount[i];
            }
            else m[comb] = l_discount[i];
        }
    }
    vector<string> index = {"00", "01", "10", "11", "20", "21"};
    for(int i = 0; i < index.size(); i++) {
        decrypted = print_dec_<int64_t>("avg(l_discount) as avg_disc -- calculating only SUM", ctxt_avg_disc[i], numEle, batch_encoder, decryptor);
        if((m.find(index[i]) == m.end() && decrypted[0] != 0) || (m[index[i]] != decrypted[0])) {
            printf("Expected: %d Result: %ld\n", m[index[i]], decrypted[0]);
            exit(1);
        }
    }
}


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

    cout << "Total slots: " << slot_count << endl;
    cout << "Total elements: " << numEle << endl;
    cout << "Evaluator size: " << sizeof(evaluator) << " bytes" << endl;
    cout << "Comparator size: " << sizeof(comparator) << " bytes" << endl;
    cout << "Batch encoder: " << sizeof(batch_encoder) << " bytes" << endl;


   for(int k = 0; k < runs; k++)
    {

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
            l_disc_price.push_back(l_extendedprice[i] * ((100-l_disc_price[i]/100)));
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
        
        Plaintext tgt_lte_l_shipdate_(intToHex(toDays(Date{1998,12,01})-90, plaintext_modulus));
        Ciphertext tgt_lte_l_shipdate;
        encryptor.encrypt(tgt_lte_l_shipdate_, tgt_lte_l_shipdate);

        stringstream data_stream;
        auto dataSize = ctxt_l_shipdate.save(data_stream);
        auto pksze = public_key.save(data_stream);
        auto rlksz = relin_keys.save(data_stream);
        auto gsz = galois_keys.save(data_stream);
        auto sksz = secret_key.save(data_stream);
        cout << "Ctxt size: " << dataSize << " bytes" << endl;
        cout << "publick key: " << pksze << " bytes" << endl;
        cout << "rlk size: " << rlksz << " bytes" << endl;
        cout << "gal size: " << gsz << " bytes" << endl;
        cout << "sk size: " << sksz << " bytes" << endl;
        
        /*
         Query Starts...
        */
        //l_shipdate <= date '1998-12-01'- interval '90' day
        time_tpch.start();
        time_filter.start();
        Ciphertext lte_l_shipdate;
        lte_l_shipdate = LTE(comparator, evaluator, relin_keys, ctxt_l_shipdate, tgt_lte_l_shipdate);
        time_tpch.pause();
        time_filter.pause();
        if(debug == 2) {
            print_vec("L_SHIPDATE", l_shipdate, numEle);
            verify_shipdate_less_than_equal_to_date(decryptor, batch_encoder, numEle, 
                                                    lte_l_shipdate, l_shipdate);
        }
        cout << "[[After lte l_shipdate]] Comparator size: " << sizeof(comparator) << "bytes" << endl;

        // groupby returnflag, linestatus
        time_tpch.start();
        time_filter.start();
        vector<Ciphertext> ctxt_res_grp;
        vector<Ciphertext> ctxt_group = {ctxt_l_returnflag, ctxt_l_linestatus};
        vector<vector<Plaintext>> ptxt_groups = {ptxt_returnflag, 
                                                ptxt_linestatus};
        ctxt_res_grp = GROUPBY(comparator, evaluator, relin_keys, ctxt_group, ptxt_groups);
        time_tpch.pause();
        time_filter.pause();
        cout << "[[After Groupby]] Comparator size: " << sizeof(comparator) << "bytes" << endl;

        time_tpch.start();
        time_agg.start();
        // Ciphertexts for results
        vector<Ciphertext> ctxt_sum_qty, ctxt_sum_base_price, ctxt_sum_disc_price, 
                            ctxt_sum_charge, ctxt_count_order;
        vector<vector<Ciphertext>> ctxt_avg_disc, ctxt_avg_price, ctxt_avg_qty;
        vector<Ciphertext> filter_group(ctxt_res_grp.size());
        ctxt_sum_qty.resize(filter_group.size());
        ctxt_sum_base_price.resize(filter_group.size());
        ctxt_sum_disc_price.resize(filter_group.size());
        ctxt_sum_charge.resize(filter_group.size());
        
        for(int i = 0; i < ctxt_res_grp.size(); i++) {
            Ciphertext tmp;
            evaluator.multiply(ctxt_res_grp[i], lte_l_shipdate, tmp);
            evaluator.relinearize_inplace(tmp, relin_keys);
            filter_group[i] = tmp;
        }

        //count(*) as count_order
        ctxt_count_order = filter_group;
        for(int j = 0; j < ctxt_count_order.size(); j++) {
            ctxt_count_order[j] = COUNT(evaluator, ctxt_count_order[j], slot_count, galois_keys);
        }
        if(debug == 2){ 
            time_tpch.pause();
            time_agg.pause();
            verify_count_order(decryptor, batch_encoder, numEle, 
                              ctxt_count_order, l_shipdate, l_returnflag, l_linestatus);
            time_tpch.start();
            time_agg.start();
        }
      
        //sum(l_quantity) as sum_qty
        for(int j = 0; j < filter_group.size(); j++) {
            evaluator.multiply(ctxt_l_quantity, filter_group[j], ctxt_sum_qty[j]);
            evaluator.relinearize_inplace(ctxt_sum_qty[j], relin_keys);
            ctxt_sum_qty[j] = SUM(evaluator, ctxt_sum_qty[j], slot_count, galois_keys);
        }
        
        if(debug == 2){
            time_tpch.pause();
            time_agg.pause();
            verify_sum_base_price(decryptor, batch_encoder, numEle, ctxt_sum_qty, 
                                l_shipdate, l_quantity, l_returnflag, l_linestatus);
            time_tpch.start();
            time_agg.start();
        }


        //sum(l_extendedprice) as sum_base_price
        vector<Ciphertext> ctxt_base_price(filter_group.size());
        for(int j = 0; j < filter_group.size(); j++) {
            evaluator.multiply(ctxt_l_extendedprice, filter_group[j], ctxt_base_price[j]);
            evaluator.relinearize_inplace(ctxt_base_price[j], relin_keys);
            ctxt_sum_base_price[j] = SUM(evaluator, ctxt_base_price[j], slot_count, galois_keys);
        }
        
        if(debug == 2){
            time_tpch.pause();
            time_agg.pause();
            verify_sum_base_price(decryptor, batch_encoder, numEle, ctxt_sum_base_price, 
                                l_shipdate, l_extendedprice, l_returnflag, l_linestatus);
            time_tpch.start();
            time_agg.start();
        }


        // sum(l_extendedprice * (1 - l_discount)) as sum_disc_price ,
        for(int j = 0; j < filter_group.size(); j++) {
            evaluator.multiply_inplace(ctxt_sum_disc_price[j], ctxt_l_disc_price);
            evaluator.relinearize_inplace(ctxt_sum_disc_price[j], relin_keys);
            ctxt_sum_disc_price[j] = SUM(evaluator, ctxt_sum_disc_price[j], slot_count, galois_keys);
        }
      

        // sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)) as sum_charge ,
        ctxt_sum_charge = filter_group;
        for(int j = 0; j < filter_group.size(); j++) {
            evaluator.multiply_inplace(ctxt_sum_charge[j], ctxt_l_charge);
            evaluator.relinearize_inplace(ctxt_sum_charge[j], relin_keys);
            ctxt_sum_charge[j] = SUM(evaluator, ctxt_sum_charge[j], slot_count, galois_keys);
        }
        

        //avg(l_discount) as avg_disc
        vector<Ciphertext> ctxt_sum_disc(filter_group.size());
        for(int j = 0; j < filter_group.size(); j++) {
            evaluator.multiply(ctxt_l_discount, filter_group[j], ctxt_sum_disc[j]);
            evaluator.relinearize_inplace(ctxt_sum_disc[j], relin_keys);
            ctxt_sum_disc[j] = SUM(evaluator, ctxt_sum_disc[j], slot_count, galois_keys);
        }
        time_agg.pause();
        auto context_data = context.first_context_data();
        while (context_data->next_context_data())
        {
            for(int p = 0; p < ctxt_sum_qty.size(); p++) {
                evaluator.mod_switch_to_next_inplace(ctxt_sum_qty[p]);
                evaluator.mod_switch_to_next_inplace(ctxt_sum_base_price[p]);
                evaluator.mod_switch_to_next_inplace(ctxt_sum_disc_price[p]);
                evaluator.mod_switch_to_next_inplace(ctxt_sum_charge[p]);
                evaluator.mod_switch_to_next_inplace(ctxt_count_order[p]);
            }
            context_data = context_data->next_context_data();
        }
        ctxt_avg_qty = {ctxt_sum_qty, ctxt_count_order};
        ctxt_avg_price = {ctxt_sum_base_price, ctxt_count_order};        
        ctxt_avg_disc = {ctxt_sum_disc, ctxt_count_order};
        time_tpch.pause();
        
        if(debug == 2){
            verify_sum_base_price(decryptor, batch_encoder, numEle, ctxt_sum_disc, 
                                l_shipdate, l_discount, l_returnflag, l_linestatus);
        }
        if (debug != 0) {
            vector<int64_t> sum_qty, sum_base_price, sum_disc_price, sum_charge, count_order;
            vector<vector<int64_t>> avg_qty, avg_price, avg_disc;
            for(int i = 0; i < filter_group.size(); i++) {
                sum_qty.push_back(dec<int64_t>(ctxt_sum_qty[i], numEle, batch_encoder, decryptor)[0]);
                sum_base_price.push_back(dec<int64_t>(ctxt_sum_base_price[i], numEle, batch_encoder, decryptor)[0]);
                sum_disc_price.push_back(dec<int64_t>(ctxt_sum_disc_price[i], numEle, batch_encoder, decryptor)[0]);
                sum_charge.push_back(dec<int64_t>(ctxt_sum_charge[i], numEle, batch_encoder, decryptor)[0]);
                vector<int64_t> avgqty = {dec<int64_t>(ctxt_avg_qty[0][i], numEle, batch_encoder, decryptor)[0],
                                             dec<int64_t>(ctxt_avg_qty[1][i], numEle, batch_encoder, decryptor)[0]};
                vector<int64_t> avgprice = {dec<int64_t>(ctxt_avg_price[0][i], numEle, batch_encoder, decryptor)[0],
                                             dec<int64_t>(ctxt_avg_price[1][i], numEle, batch_encoder, decryptor)[0]};
                vector<int64_t> avgdisc = {dec<int64_t>(ctxt_avg_disc[0][i], numEle, batch_encoder, decryptor)[0],
                                             dec<int64_t>(ctxt_avg_disc[1][i], numEle, batch_encoder, decryptor)[0]};
                avg_qty.push_back(avgqty);
                avg_price.push_back(avgprice);
                avg_disc.push_back(avgdisc);
                count_order.push_back(dec<int64_t>(ctxt_count_order[i], numEle, batch_encoder, decryptor)[0]);
            }
            
            verify(l_quantity, l_extendedprice, l_discount, l_returnflag, l_linestatus, l_shipdate, l_tax,
                    sum_qty, sum_base_price, sum_disc_price, sum_charge, 
                    avg_qty, avg_price, avg_disc, count_order);
        }
        cout << "    + noise budget left: " << decryptor.invariant_noise_budget(ctxt_avg_disc[0][0]) << " bits"
        << endl;
    }
    
    time_tpch.stop(runs);
    time_agg.stop(runs);
    time_filter.stop(runs);

    if(debug != 0)
        cout << "Verified. Done.\n";
    else
        cout << "Verify skipped. Done" << endl;
    return 0;
}