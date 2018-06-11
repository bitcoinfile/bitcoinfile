#ifndef H_GLOBLE_H
#define H_GLOBLE_H
#include <stdint.h>
typedef unsigned int uint32_t;
#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif
#endif//H_GLOBLE_H