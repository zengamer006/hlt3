#pragma once
/*
  crypto_utils.h — ESP32-C6 Arduino ESP-NOW application-payload encryption

  API compatible with the transmitter sketch:
      CryptoCtx crypto;
      crypto.init(deviceID);  // deviceID: 16 bytes
      crypto.seal(plaintext, plaintextLen, timestamp, output, outputLen);

  Wire format returned by seal():
      [12-byte random nonce][ciphertext][16-byte AES-GCM authentication tag]

  CRYPTO_PACKET_OVERHEAD = 28 bytes.

  IMPORTANT:
  - Set the same 32-byte CRYPTO_MASTER_KEY on transmitter AND receiver.
  - The receiver must implement the same AES-256-GCM format and derive the same
    device key from the same 16-byte deviceID. This header alone cannot make
    an unrelated/older receiver protocol-compatible.
  - Keep the master key private. The placeholder below is for bring-up only.
*/

#include <Arduino.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <esp_system.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>

#ifndef CRYPTO_PACKET_OVERHEAD
#define CRYPTO_PACKET_OVERHEAD 28  // 12-byte nonce + 16-byte GCM tag
#endif

#ifndef CRYPTO_MASTER_KEY
// CHANGE THIS to your own random 32-byte key, and use the identical key
// in the receiver's crypto implementation. Placeholder key for testing only.
#define CRYPTO_MASTER_KEY { \
  0x51, 0x7A, 0x2C, 0x91, 0xE4, 0x06, 0xB8, 0x3D, \
  0x6F, 0xD2, 0x44, 0xA9, 0x13, 0xC7, 0x80, 0x5E, \
  0xB1, 0x39, 0x62, 0xF0, 0x8D, 0x25, 0xCA, 0x74, \
  0x0B, 0xE6, 0x93, 0x4F, 0xD8, 0x17, 0xAA, 0x60  \
}
#endif

class CryptoCtx {
public:
  CryptoCtx() : initialized_(false) {
    memset(key_, 0, sizeof(key_));
  }

  // Derive a per-device AES-256 key using HMAC-SHA256(master key, device ID).
  bool init(const uint8_t deviceID[16]) {
    if (deviceID == nullptr) {
      initialized_ = false;
      return false;
    }

    static const uint8_t masterKey[32] = CRYPTO_MASTER_KEY;
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) {
      initialized_ = false;
      return false;
    }

    int rc = mbedtls_md_hmac(mdInfo,
                            masterKey, sizeof(masterKey),
                            deviceID, 16,
                            key_);
    initialized_ = (rc == 0);
    return initialized_;
  }

  /*
    Encrypt plaintext into output.
    timestamp is retained for compatibility with the source sketch's API.
    A fresh 96-bit nonce is generated for every call using esp_random().
    Returns outputLen=0 on failure.
  */
  bool seal(const uint8_t *plaintext,
            size_t plaintextLen,
            uint32_t timestamp,
            uint8_t *output,
            size_t &outputLen) {
    (void)timestamp;
    outputLen = 0;

    if (!initialized_ || output == nullptr ||
        (plaintext == nullptr && plaintextLen != 0)) {
      return false;
    }

    if (plaintextLen > SIZE_MAX - CRYPTO_PACKET_OVERHEAD) return false;

    uint8_t nonce[12];
    for (size_t i = 0; i < sizeof(nonce); i += 4) {
      uint32_t r = esp_random();
      nonce[i]     = (uint8_t)(r);
      nonce[i + 1] = (uint8_t)(r >> 8);
      nonce[i + 2] = (uint8_t)(r >> 16);
      nonce[i + 3] = (uint8_t)(r >> 24);
    }

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);

    int rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key_, 256);
    if (rc == 0) {
      memcpy(output, nonce, sizeof(nonce));
      uint8_t *ciphertext = output + sizeof(nonce);
      uint8_t *tag = ciphertext + plaintextLen;

      rc = mbedtls_gcm_crypt_and_tag(
          &ctx,
          MBEDTLS_GCM_ENCRYPT,
          plaintextLen,
          nonce, sizeof(nonce),
          nullptr, 0,                 // no additional authenticated data
          plaintext, ciphertext,
          16, tag);
    }

    mbedtls_gcm_free(&ctx);

    if (rc != 0) {
      memset(output, 0, plaintextLen + CRYPTO_PACKET_OVERHEAD);
      return false;
    }

    outputLen = plaintextLen + CRYPTO_PACKET_OVERHEAD;
    return true;
  }

  // Matching decrypt helper for use on a receiver that shares this protocol.
  // deviceID must be the same 16-byte ID used by the transmitting device.
  bool open(const uint8_t *input,
            size_t inputLen,
            const uint8_t deviceID[16],
            uint8_t *plaintext,
            size_t &plaintextLen) {
    plaintextLen = 0;
    if (input == nullptr || deviceID == nullptr ||
        plaintext == nullptr || inputLen < CRYPTO_PACKET_OVERHEAD) {
      return false;
    }

    // Derive key for the specified device ID.
    uint8_t rxKey[32];
    static const uint8_t masterKey[32] = CRYPTO_MASTER_KEY;
    const mbedtls_md_info_t *mdInfo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mdInfo == nullptr) return false;

    int rc = mbedtls_md_hmac(mdInfo, masterKey, sizeof(masterKey),
                            deviceID, 16, rxKey);
    if (rc != 0) {
      memset(rxKey, 0, sizeof(rxKey));
      return false;
    }

    const size_t nonceLen = 12;
    const size_t tagLen = 16;
    const size_t cipherLen = inputLen - nonceLen - tagLen;
    const uint8_t *nonce = input;
    const uint8_t *ciphertext = input + nonceLen;
    const uint8_t *tag = input + nonceLen + cipherLen;

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    rc = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, rxKey, 256);
    if (rc == 0) {
      rc = mbedtls_gcm_auth_decrypt(
          &ctx, cipherLen,
          nonce, nonceLen,
          nullptr, 0,                 // no additional authenticated data
          tag, tagLen,
          ciphertext, plaintext);
    }
    mbedtls_gcm_free(&ctx);
    memset(rxKey, 0, sizeof(rxKey));

    if (rc != 0) {
      if (cipherLen > 0) memset(plaintext, 0, cipherLen);
      return false;
    }

    plaintextLen = cipherLen;
    return true;
  }

  bool isReady() const {
    return initialized_;
  }

private:
  uint8_t key_[32];
  bool initialized_;
};
