#pragma once
#include "seal/seal.h"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>
#include "utils.h"
using namespace seal;
using namespace std;
/*
 * Inequality comparison algorithm ref:
 * Faster homomorphic comparison operations for BGV and BFV by Ilia Iliashenko and Vincent Zucca.
 * https://github.com/iliailia/comparison-circuit-over-fq
 */


struct polyDiv {
    vector<int64_t> q;
    vector<int64_t> r;

    polyDiv() {}
    polyDiv(const vector<int64_t>& q0, const vector<int64_t>& r0) : q(q0), r(r0) {}
};

class Comparator
{
    public:
        Comparator(const SEALContext &context);

        /**
        Evaluate if a is less than b
        @param[in] a Ciphertext to evaluate inequality (less than)
        @param[in] b Ciphertext to compare
        @param[out] res Ciphertext that contains the result of less than
        */
        vector<Ciphertext> isLessThan(Evaluator& evaluator, RelinKeys &relin_keys, Ciphertext& a, Ciphertext& b);
        vector<Ciphertext> isLessThan(Evaluator& evaluator, RelinKeys &relin_keys, Ciphertext& a, const Plaintext& b);
        vector<Ciphertext> isLessThan(Evaluator& evaluator, RelinKeys &relin_keys, const Plaintext& a, Ciphertext& b);
        /**

        Evaluate if a equal to b
        @param[in] a Ciphertext to evaluate equality
        @param[in] b Ciphertext to compare
        @param[out] res Ciphertext that contains the result of equality evaluation
        */
        Ciphertext isEqual(Evaluator& evaluator, RelinKeys &relin_keys, Ciphertext& a, Ciphertext& b);
        Ciphertext isEqual(Evaluator& evaluator, RelinKeys &relin_keys, Ciphertext& a, Plaintext& b);
        int64_t getK(){return k_;};
        int64_t getM() {return m_;};


    private:
        void evalPolyHelper(Evaluator& evaluator, RelinKeys &relin_keys,
                            Ciphertext& x, vector<int64_t> poly,
                            vector<Ciphertext>& babyStep,
                            vector<Ciphertext>& giantStep);

        void evalPolyHelperPowerOf2(Evaluator& evaluator, RelinKeys &relin_keys,
                                    Ciphertext& x, vector<int64_t>& poly,
                                    vector<Ciphertext>& babyStep,
                                    vector<Ciphertext>& giantStep);

        void evalPolyPS(Evaluator& evaluator, RelinKeys &relin_keys,
                        Ciphertext& x, vector<int64_t>& poly,
                        vector<Ciphertext>& babyStep,
                        vector<Ciphertext>& giantStep,
                        int64_t t, int64_t delta);

        void evalPolySimple(Evaluator& evaluator, RelinKeys &relin_keys,
                            Ciphertext& x, vector<int64_t>& poly,
                            vector<Ciphertext>& babyStep);

        void initCoeff();
        void initPolyParam();
        int64_t getLeadCoeff(const vector<int64_t>& coefficients);
        int64_t nextPowerOf2(int64_t n);
        int64_t pow_p(int64_t a, int64_t e);
        int64_t degree(const vector<int64_t>& coefficients);
        Ciphertext getPower(Evaluator& evaluator, RelinKeys &relin_keys,
                            vector<Ciphertext>& x, int64_t e);
        shared_ptr<polyDiv> dividePoly(const vector<int64_t>& dividend,
                                       const vector<int64_t>& divisor);
        vector<Ciphertext> evalPoly(Evaluator& evaluator, RelinKeys &relin_keys,
                                    Ciphertext& x);

        vector<int64_t> poly_;
        int64_t p_;
        int64_t top_coef_;
        int64_t topInv_;
        int64_t extra_coef_;
        int64_t top_deg_;
        int64_t m_; // gs
        int64_t k_; // bs
        int64_t d_comp_;
        int64_t baby_idx_;
        int64_t giant_idx_;
        int64_t kk_;
        bool divisible_;
};