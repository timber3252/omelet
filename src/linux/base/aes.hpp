//
// Created by timber3252 on 7/30/19.
//

#ifndef OMELET_SRC_LINUX_BASE_AES_HPP
#define OMELET_SRC_LINUX_BASE_AES_HPP

#include "include.hpp"

namespace ra {

#define OMELET_AES_KEY_LENGTH 128

extern uint8_t aes_key[OMELET_AES_KEY_LENGTH];

int aes_encrypt(const uint8_t *data, const size_t len, const uint8_t *key,
                uint8_t *encrypt_data);

int aes_decrypt(const uint8_t *encrypt_data, const size_t len,
                const uint8_t *key, uint8_t *decrypt_data);

} // namespace ra

#endif // OMELET_SRC_LINUX_BASE_AES_HPP
