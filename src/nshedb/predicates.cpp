#include "predicates.h"

Ciphertext COUNT(Evaluator &evaluator, const Ciphertext &a, int slot_count, GaloisKeys &galois_keys)
{
    Ciphertext res = a;
    for(int i = 1; i < slot_count/2; i <<= 1) {
        Ciphertext tmp;
        evaluator.rotate_rows(res, i, galois_keys, tmp);
        evaluator.add_inplace(res, tmp);
    }
    Ciphertext rot;
    evaluator.rotate_columns(res, galois_keys, rot);
    evaluator.add_inplace(res, rot);
    return res;
}

Ciphertext SUM(Evaluator &evaluator, Ciphertext &a, int slot_count, GaloisKeys& galois_keys)
{
    Ciphertext res = a;
    for(int i = 1; i < slot_count/2; i <<= 1) {
        Ciphertext tmp;
        evaluator.rotate_rows(res, i, galois_keys, tmp);
        evaluator.add_inplace(res, tmp);        
    }
    Ciphertext rot;
    evaluator.rotate_columns(res, galois_keys, rot);
    evaluator.add_inplace(res, rot);
    return res;
}

Ciphertext LTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b)
{
    vector<Ciphertext> cmp;
    Ciphertext res;
    cmp = comparator.isLessThan(evaluator, relin_keys, a, b);
    evaluator.add(cmp[0], cmp[1], res);
    return res;
}


Ciphertext LTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,  Ciphertext &a, Plaintext &b)
{
    vector<Ciphertext> cmp;
    Ciphertext res;
    cmp = comparator.isLessThan(evaluator, relin_keys, a, b);
    evaluator.add(cmp[0], cmp[1], res);
    return res;
}


Ciphertext LTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,  Plaintext &a, Ciphertext &b)
{
    vector<Ciphertext> cmp;
    Ciphertext res;
    cmp = comparator.isLessThan(evaluator, relin_keys, a, b);
    evaluator.add(cmp[0], cmp[1], res);
    return res;
}

Ciphertext LT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b)
{
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, a, b);
    return cmp[0];
}
Ciphertext LT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,  Ciphertext &a, Plaintext &b)
{
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, a, b);
    return cmp[0];
}
Ciphertext LT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,  Plaintext &a, Ciphertext &b)
{
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, a, b);
    return cmp[0];
}
Ciphertext GT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b)
{
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, b, a);
    return cmp[0];
}
Ciphertext GT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &b)
{
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, b, a);
    return cmp[0];
}
Ciphertext GT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Plaintext &a, Ciphertext &b)
{
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, b, a);
    return cmp[0];
}
Ciphertext GTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b)
{
    Ciphertext res;
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, b, a);
    evaluator.add(cmp[0], cmp[1], res);
    return res;
}

Ciphertext GTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Plaintext &a, Ciphertext &b)
{
    Ciphertext res;
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, b, a);
    evaluator.add(cmp[0], cmp[1], res);
    return res;
}

Ciphertext GTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &b)
{
    Ciphertext res;
    vector<Ciphertext> cmp = comparator.isLessThan(evaluator, relin_keys, b, a);
    evaluator.add(cmp[0], cmp[1], res);
    return res;
}

vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                            vector<Ciphertext> &ctxt_group, 
                            vector<vector<Plaintext>> &ptxt_groups)
{
    vector<vector<Ciphertext>> ctxt_tmp_filter(ctxt_group.size()), ctxt_comb_grp;

    for (int i = 0; i < ptxt_groups.size(); i++)
        ctxt_tmp_filter[i] = GROUPBY(comparator, evaluator, relin_keys, ctxt_group[i], ptxt_groups[i]);

    ctxt_comb_grp = generateCombinations<Ciphertext>(ctxt_tmp_filter);

    vector<Ciphertext> ctxt_res_grp(ctxt_comb_grp.size());
    for (int i = 0; i < ctxt_comb_grp.size(); i++)
        evaluator.multiply_many(ctxt_comb_grp[i], relin_keys, ctxt_res_grp[i]);
    return ctxt_res_grp;
}

vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                           vector<Ciphertext> &ctxt_group, 
                           vector<vector<Ciphertext>> &ctxt_groups)
{
    vector<vector<Ciphertext>> ctxt_tmp_filter(ctxt_group.size()), ctxt_comb_grp;

    for (int i = 0; i < ctxt_groups.size(); i++)
        ctxt_tmp_filter[i] = GROUPBY(comparator, evaluator, relin_keys, ctxt_group[i], ctxt_groups[i]);

    ctxt_comb_grp = generateCombinations<Ciphertext>(ctxt_tmp_filter);

    vector<Ciphertext> ctxt_res_grp(ctxt_comb_grp.size());
    for (int i = 0; i < ctxt_comb_grp.size(); i++)
        evaluator.multiply_many(ctxt_comb_grp[i], relin_keys, ctxt_res_grp[i]);
    return ctxt_res_grp;
}


vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                           Ciphertext &ctxt_group, vector<Plaintext> &ptxt_groups){
    vector<Ciphertext> ctxt_res_grp(ptxt_groups.size());
    for(int i = 0; i < ptxt_groups.size(); i++){
        ctxt_res_grp[i] = comparator.isEqual(evaluator, relin_keys, ctxt_group, ptxt_groups[i]);
    }
    return ctxt_res_grp;
}

vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                           Ciphertext &ctxt_group, vector<Ciphertext> &ctxt_groups){
    vector<Ciphertext> ctxt_res_grp(ctxt_groups.size());
    for(int i = 0; i < ctxt_groups.size(); i++){
        ctxt_res_grp[i] = comparator.isEqual(evaluator, relin_keys, ctxt_group, ctxt_groups[i]);
    }
    return ctxt_res_grp;
}


Ciphertext IN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, 
              Ciphertext &a, vector<Plaintext> &set) {
    vector<Ciphertext> res(set.size());
    for(int i = 0; i < set.size(); i++) {
        res[i] = comparator.isEqual(evaluator, relin_keys, a, set[i]);
    }
    for(int i = 1; i <set.size(); i++) {
        evaluator.add(res[0], res[i], res[0]);
    }
    return res[0];
}
Ciphertext IN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, 
              Ciphertext &a, vector<Ciphertext> &set) {
    vector<Ciphertext> res(set.size());
    for(int i = 0; i < set.size(); i++) {
        res[i] = comparator.isEqual(evaluator, relin_keys, a, set[i]);
    }
    for(int i = 1; i <set.size(); i++) {
        evaluator.add(res[0], res[i], res[0]);
    }
    return res[0];
}


Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, 
                   Ciphertext &a, Ciphertext &cond1, Ciphertext &cond2)
{
    Ciphertext res, filtered1, filtered2;
    vector<Ciphertext> cmp_cond1, cmp_cond2;

    cmp_cond1 = comparator.isLessThan(evaluator, relin_keys, cond1, a);
    evaluator.add(cmp_cond1[0], cmp_cond1[1], filtered1);

    cmp_cond2 = comparator.isLessThan(evaluator, relin_keys, a, cond1);
    evaluator.add(cmp_cond2[0], cmp_cond2[1], filtered2);
    
    evaluator.multiply(filtered1, filtered2, res);
    evaluator.relinearize_inplace(res, relin_keys);
    return res;
}

Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, 
                   Ciphertext &a, Plaintext &cond1, Plaintext &cond2)
{
    Ciphertext res, filtered1, filtered2;
    filtered1 = LTE(comparator, evaluator, relin_keys, a, cond2);
    filtered2 = GTE(comparator, evaluator, relin_keys, a, cond1);
    evaluator.multiply(filtered1, filtered2, res);
    evaluator.relinearize_inplace(res, relin_keys);
    return res;
}

Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, 
                   Ciphertext &a, Plaintext &cond1, Ciphertext &cond2)
{
    Ciphertext res, filtered1, filtered2;
    filtered1 = LTE(comparator, evaluator, relin_keys, a, cond1);
    filtered2 = GTE(comparator, evaluator, relin_keys, a, cond2);
    evaluator.multiply(filtered1, filtered2, res);
    evaluator.relinearize_inplace(res, relin_keys);
    return res;
}

Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, 
                   Ciphertext &a, Ciphertext &cond1, Plaintext &cond2)
{
    Ciphertext res, filtered1, filtered2;
    filtered1 = LTE(comparator, evaluator, relin_keys, a, cond1);
    filtered2 = GTE(comparator, evaluator, relin_keys, a, cond2);
    evaluator.multiply(filtered1, filtered2, res);
    evaluator.relinearize_inplace(res, relin_keys);
    return res;
}