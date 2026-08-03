#pragma once
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define AIRVAULT_API __declspec(dllexport)
#else
#define AIRVAULT_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif
AIRVAULT_API int airvault_safe_relative_path(const char* path);
AIRVAULT_API int airvault_constant_time_equal(const uint8_t* left, const uint8_t* right, size_t length);
AIRVAULT_API void airvault_secure_zero(uint8_t* data, size_t length);
AIRVAULT_API int airvault_sha256_file(const char* path, uint8_t output[32]);
#ifdef __cplusplus
}
#endif
