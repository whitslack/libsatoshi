#include <string>

#include "common/compiler.h"


size_t base58check_encode(char * _restrict out, size_t n_out, const void * _restrict in, size_t n_in);

std::string base58check_encode(const void *in, size_t n_in);

size_t base58check_decode(void * _restrict out, size_t n_out, const char * _restrict in, size_t n_in);
