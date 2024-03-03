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
#include <thread>
#include <vector>
#include <ctime>

using namespace std;
#define PRINT_TITLE(a) std::cout<< a << std::endl


//[FROM SEAL example.h] ================================================
/*
Helper function: Prints the name of the example in a fancy banner.
*/
inline void print_example_banner(std::string title)
{
    if (!title.empty())
    {
        std::size_t title_length = title.length();
        std::size_t banner_length = title_length + 2 * 10;
        std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
        std::string banner_middle = "|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

        std::cout << std::endl << banner_top << std::endl << banner_middle << std::endl << banner_top << std::endl;
    }
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(const seal::SEALContext &context)
{
    auto &context_data = *context.key_context_data();

    /*
    Which scheme are we using?
    */
    std::string scheme_name;
    switch (context_data.parms().scheme())
    {
    case seal::scheme_type::bfv:
        scheme_name = "BFV";
        break;
    case seal::scheme_type::ckks:
        scheme_name = "CKKS";
        break;
    case seal::scheme_type::bgv:
        scheme_name = "BGV";
        break;
    default:
        throw std::invalid_argument("unsupported scheme");
    }
    std::cout << "/" << std::endl;
    std::cout << "| Encryption parameters :" << std::endl;
    std::cout << "|   scheme: " << scheme_name << std::endl;
    std::cout << "|   poly_modulus_degree: " << context_data.parms().poly_modulus_degree() << std::endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    std::cout << "|   coeff_modulus size: ";
    std::cout << context_data.total_coeff_modulus_bit_count() << " (";
    auto coeff_modulus = context_data.parms().coeff_modulus();
    std::size_t coeff_modulus_size = coeff_modulus.size();
    for (std::size_t i = 0; i < coeff_modulus_size - 1; i++)
    {
        std::cout << coeff_modulus[i].bit_count() << " + ";
    }
    std::cout << coeff_modulus.back().bit_count();
    std::cout << ") bits" << std::endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == seal::scheme_type::bfv)
    {
        std::cout << "|   plain_modulus: " << context_data.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator<<(std::ostream &stream, seal::parms_id_type parms_id)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    stream << std::hex << std::setfill('0') << std::setw(16) << parms_id[0] << " " << std::setw(16) << parms_id[1]
           << " " << std::setw(16) << parms_id[2] << " " << std::setw(16) << parms_id[3] << " ";

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);

    return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template <typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
    /*
    Save the formatting information for std::cout.
    */
    std::ios old_fmt(nullptr);
    old_fmt.copyfmt(std::cout);

    std::size_t slot_count = vec.size();

    std::cout << std::fixed << std::setprecision(prec);
    std::cout << std::endl;
    if (slot_count <= 2 * print_size)
    {
        std::cout << "    [";
        for (std::size_t i = 0; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    else
    {
        vec.resize(std::max(vec.size(), 2 * print_size));
        std::cout << "    [";
        for (std::size_t i = 0; i < print_size; i++)
        {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * print_size)
        {
            std::cout << " ...,";
        }
        for (std::size_t i = slot_count - print_size; i < slot_count; i++)
        {
            std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
        }
    }
    std::cout << std::endl;

    /*
    Restore the old std::cout formatting.
    */
    std::cout.copyfmt(old_fmt);
}

/*
Helper function: Prints a matrix of values.
*/
template <typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
    /*
    We're not going to print every column of the matrix (there are 2048). Instead
    print this many slots from beginning and end of the matrix.
    */
    std::size_t print_size = 5;

    std::cout << std::endl;
    std::cout << "    [";
    for (std::size_t i = 0; i < print_size; i++)
    {
        std::cout << std::setw(3) << std::right << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = row_size - print_size; i < row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != row_size - 1) ? "," : " ]\n");
    }
    std::cout << "    [";
    for (std::size_t i = row_size; i < row_size + print_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ",";
    }
    std::cout << std::setw(3) << " ...,";
    for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
    {
        std::cout << std::setw(3) << matrix[i] << ((i != 2 * row_size - 1) ? "," : " ]\n");
    }
    std::cout << std::endl;
}

/*
Helper function: Print line number.
*/
inline void print_line(int line_number)
{
    std::cout << "Line " << std::setw(3) << line_number << " --> ";
}

/*
Helper function: Convert a value into a hexadecimal string, e.g., uint64_t(17) --> "11".
*/
inline std::string uint64_to_hex_string(std::uint64_t value)
{
    return seal::util::uint_to_hex_string(&value, std::size_t(1));
}



inline void print_vec(std::string st, std::vector<int64_t> vec, int numEle)
{
    std::cout << st << ":" << std::setw(3) << "[";
    for (std::size_t i = 0; i < numEle; i++)
    {
        std::cout << std::setw(3) << std::right << vec[i] << ",";
    }
    std::cout << "] " << std::endl;
}

template <typename T>
inline void print_dec(std::string st, const seal::Ciphertext ctxt_res, int numEle, seal::BatchEncoder& batch_encoder, seal::Decryptor& decryptor) {
    seal::Plaintext ptxt_res;
    std::vector<T> res;
    decryptor.decrypt(ctxt_res, ptxt_res);
    batch_encoder.decode(ptxt_res, res);
    std::cout << st << ":" << std::setw(3) << "[";
    for (std::size_t i = 0; i < numEle; i++)
    {
        std::cout << std::setw(3) << std::right << res[i] << ",";
    }
    std::cout << "] " << std::endl;
    std::cout << "    + noise budget: " << decryptor.invariant_noise_budget(ctxt_res) << " bits"
         << std::endl;
}

template <typename T>
inline std::vector<T> print_dec_(std::string st, const seal::Ciphertext ctxt_res, int numEle, seal::BatchEncoder& batch_encoder, seal::Decryptor& decryptor) {
    seal::Plaintext ptxt_res;
    std::vector<T> res;
    decryptor.decrypt(ctxt_res, ptxt_res);
    batch_encoder.decode(ptxt_res, res);
    std::cout << st << ":" << std::setw(3) << "[";
    for (std::size_t i = 0; i < numEle; i++)
    {
        std::cout << std::setw(3) << std::right << res[i] << ",";
    }
    std::cout << "] " << std::endl;
    std::cout << "    + noise budget: " << decryptor.invariant_noise_budget(ctxt_res) << " bits"
         << std::endl;
    return res;
}

template <typename T>
inline std::vector<T> dec(const seal::Ciphertext ctxt_res, int numEle, seal::BatchEncoder& batch_encoder, seal::Decryptor& decryptor) {
    seal::Plaintext ptxt_res;
    std::vector<T> res;
    decryptor.decrypt(ctxt_res, ptxt_res);
    batch_encoder.decode(ptxt_res, res);
    return res;
}

//=======================================================[END]




inline std::string intToHex(int64_t num, int64_t p) {
    uint64_t unum =  (num < 0) ?(p + static_cast<uint64_t>(num))  : static_cast<uint64_t>(num);
    return seal::util::uint_to_hex_string(&unum, 1);
}


struct TOC 
{
    std::chrono::high_resolution_clock::time_point time_start, time_end;
    std::chrono::microseconds time_diff, time_acc;
    std::string _name;

    TOC(std::string name) : _name(name) {
        time_acc = std::chrono::duration_cast<std::chrono::microseconds>(time_start - time_start);
    };

    void start() {
        time_start = std::chrono::high_resolution_clock::now();
    }

    void resume() {
        time_start = std::chrono::high_resolution_clock::now();
    }
    void pause() {
        time_end = std::chrono::high_resolution_clock::now();
        time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
        time_acc += time_diff;
    }
    void stop() {
        time_end = std::chrono::high_resolution_clock::now();
        time_diff = std::chrono::duration_cast<std::chrono::microseconds>(time_end - time_start);
        time_acc += time_diff;
        std::cout << _name << time_acc.count() << " us (" \
                                 << static_cast<float>(time_acc.count()/ 1000000.0f) << " s)" <<std::endl; 
        time_acc = std::chrono::duration_cast<std::chrono::microseconds>(time_start - time_start);
    }

    void stop(int n) {
        time_acc = time_acc/n;
        std::cout << _name << " avg of " << n << " iterations: " \
                                 << time_acc.count() << " us (" \
                                 << static_cast<float>(time_acc.count()/ 1000000.0f) << " s)" <<std::endl; 
    }

    void stop(int n, int ele) {
        time_acc = (time_acc/n)/ele;
        std::cout << _name << " avg of " << n << " iterations (amortize -- per ele) : " \
                                 << time_acc.count() << " us (" \
                                 << static_cast<float>(time_acc.count()/ 1000000.0f) << " s)" <<std::endl; 
    }

    void print(int n) {
        time_acc = time_acc/n;
        std::cout << _name << " avg of " << n << " iterations: " \
                << time_acc.count() << " us (" \
                << static_cast<float>(time_acc.count()/ 1000000.0f) << " s)" <<std::endl; 
    }

};

// assume all elements are distinct
template<typename T>
int numCombinations(const vector<vector<T>>& vectors) {
    int count = 0;
    for (int i = 0; i < vectors.size(); i++)
        count += vectors[i].size();
    return count;
}

template<typename T>
vector<vector<T>> generateCombinations(const vector<vector<T>>& vectors) {
    vector<int> indices(vectors.size());
    vector<vector<T>> res;
    while (true) {
        vector<T> tmp;
        for (int i = 0; i < vectors.size(); ++i)
            tmp.push_back(vectors[i][indices[i]]);
        res.push_back(tmp);

        // the next combination
        int carry = 1;
        for (int i = vectors.size() - 1; i >= 0; --i) {
            indices[i] += carry;
            if (indices[i] == vectors[i].size()) {
                indices[i] = 0;
                carry = 1;
            } 
            else carry = 0;
        }

        if (carry == 1)
            break; // All combinations got generated
    }
    return res;
}


struct Date {
    int year;
    int month;
    int day;
};

inline int toDays(const Date& date) {
    Date base_date = {2000, 01, 01};
    std::tm tm1 = {0};
    tm1.tm_year = base_date.year - 1900;
    tm1.tm_mon = base_date.month - 1;  
    tm1.tm_mday = base_date.day;

    std::tm tm2 = {0};
    tm2.tm_year = date.year - 1900;
    tm2.tm_mon = date.month - 1;
    tm2.tm_mday = date.day;

    std::time_t time1 = std::mktime(&tm1);
    std::time_t time2 = std::mktime(&tm2);

    if (time1 == -1 || time2 == -1) {
        // Error in mktime
        std::cout << "Convert to days failed" << std::endl;
        exit(-1);
    }
    // Calculate the difference in seconds and convert to days
    double differenceInSeconds = std::difftime(time2, time1);
    return static_cast<int>(differenceInSeconds / (60 * 60 * 24));
}

inline Date fromDays(int days) {
    Date base_date = {2000, 1, 1};
    std::tm tm1 = {0};
    tm1.tm_year = base_date.year - 1900;
    tm1.tm_mon = base_date.month - 1;
    tm1.tm_mday = base_date.day;

    // Calculate the time_t for the base date
    std::time_t time1 = std::mktime(&tm1);

    // Calculate the time_t for the target date by adding days
    std::time_t time2 = time1 + days * (60 * 60 * 24);

    std::tm* target_tm = std::localtime(&time2);

    Date target_date;
    target_date.year = target_tm->tm_year + 1900;
    target_date.month = target_tm->tm_mon + 1;
    target_date.day = target_tm->tm_mday;

    return target_date;
}