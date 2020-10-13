#include <cstring>
#include <cstdint>


// Generate CRC lookup table
template <unsigned c, int k = 8>
struct f : f<((c & 1) ? 0xedb88320 : 0) ^ (c >> 1), k - 1> {};
template <unsigned c> struct f<c, 0> { enum { value = c }; };

#define A(x) B(x) B(x + 128)
#define B(x) C(x) C(x +  64)
#define C(x) D(x) D(x +  32)
#define D(x) E(x) E(x +  16)
#define E(x) F(x) F(x +   8)
#define F(x) G(x) G(x +   4)
#define G(x) H(x) H(x +   2)
#define H(x) I(x) I(x +   1)
#define I(x) f<x>::value ,

constexpr unsigned crc_table[] = { A(0) };

// Constexpr implementation and helpers
constexpr uint32_t crc32_impl(const char* p, size_t len, uint32_t crc) {
	return len ?
		crc32_impl(p + 1, len - 1, (crc >> 8) ^ crc_table[(crc & 0xFF) ^ *p])
		: crc;
}

constexpr uint32_t crc32(const char* data, size_t length) {
	return ~crc32_impl(data, length, ~0);
}

constexpr size_t strlen_c(const char* str) {
	return *str ? 1 + strlen_c(str + 1) : 0;
}

constexpr int WSID(const char* str) {
	return crc32(str, strlen_c(str));
}
