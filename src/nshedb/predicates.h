#pragma once
#include "comparator.h"
#include "utils.h"

Ciphertext COUNT(Evaluator &evaluator, const Ciphertext &a, int slot_count, GaloisKeys& galois_keys);
Ciphertext SUM(Evaluator &evaluator, Ciphertext &a, int slot_count, GaloisKeys& galois_keys);
Ciphertext LT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b);
Ciphertext LT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Plaintext &a, Ciphertext &b);
Ciphertext LT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &b);
Ciphertext LTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b);
Ciphertext LTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Plaintext &a, Ciphertext &b);
Ciphertext LTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &b);
Ciphertext GT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b);
Ciphertext GT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Plaintext &a, Ciphertext &b);
Ciphertext GT(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &b);
Ciphertext GTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &b);
Ciphertext GTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Plaintext &a, Ciphertext &b);
Ciphertext GTE(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &b);
vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                                vector<Ciphertext> &ctxt_group, 
                                vector<vector<Plaintext>> &ptxt_groups);
vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                                vector<Ciphertext> &ctxt_group, 
                                vector<vector<Ciphertext>> &ctxt_groups);
vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                                Ciphertext &ctxt_group, vector<Plaintext> &ptxt_groups);
vector<Ciphertext> GROUPBY(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys,
                                Ciphertext &ctxt_group, vector<Ciphertext> &ctxt_groups);
Ciphertext IN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, vector<Plaintext> &set);
Ciphertext IN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, vector<Ciphertext> &set);

// BETWEEN cond1 AND cond2
Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &cond1, Ciphertext &cond2);
Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &cond1, Plaintext &cond2);
Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Plaintext &cond1, Ciphertext &cond2);
Ciphertext BETWEEN(Comparator &comparator, Evaluator &evaluator, RelinKeys &relin_keys, Ciphertext &a, Ciphertext &cond1, Plaintext &cond2);