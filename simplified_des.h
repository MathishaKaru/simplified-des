#ifndef _SIMPLIFIED_DES_H_
#define _SIMPLIFIED_DES_H_

/**
 * Header file for our Simplified DES encryption library.
 *
 * COMP280 @ USD
 */

#include <stdint.h>

/**
 * Expands a 6-bit input to 8-bits.
 *
 * @note The input uses only 6 of the 8 available bits. The 2 most significant
 * bits will be ignored.
 *
 * @param input The 6-bit input value
 *
 * @return The expanded version of the input.
 */
uint8_t expand(uint8_t input);

/**
 * Uses sboxes to transform the input.
 *
 * @param input The 8-bit value to transform
 *
 * @return The transformed input, which will be 6 bits. The 2 most significant
 *   bits are to be ignored.
 */
uint8_t confuse(uint8_t input);

/**
 * Performs the feistel function, which consists of an expansion step
 * followed by a confusion step.
 *
 * @param input A 6-bit value to transform.
 * @param key An 8-bit key.
 *
 * @return A 6-bit value that has gone through the two major steps.
 */
uint8_t feistel(uint8_t input, uint8_t key);

/**
 * Performs one round in the feistel cipher.
 *
 * @note The input and output use only 12 of the 16 available bits. The 4 most
 * significant bits of both should be ignored.
 *
 * @param A 12-bit input to transform.
 * @param An 8-bit key, used only for this round.
 *
 * @param The 12-bit result of going through the round.
 */
uint16_t feistel_round(uint16_t input, uint8_t key);

/**
 * Generates 8-bit keys for a specific number of rounds of computation.
 * These keys are generated based off of the given 9-bit key.
 *
 * @param original_key The 9-bit key to use as a basis for the round keys.
 * @param num_rounds The number of keys to generate. This must be less than 10.
 *
 * @return An array of 8-bit keys, each of which will be used for one round of
 * 			computation. If num_rounds > 9, NULL is returned.
 */
uint8_t *generate_round_keys(uint16_t original_key, unsigned int num_rounds);

/**
 * Encrypts 12-bits of data using the given number of rounds of the simplified
 * DES encryption algorithm.
 *
 * @note The unencrypted and encrypted data uses only 12 of the 16 available
 * bits. The 4 most significant bits of both should be ignored.
 *
 * @param unencrypted_data The 12-bit block of data to encrypt.
 * @param round_keys The keys for each round of the cipher.
 * @param num_rounds The number of rounds of the cipher to perform.
 *
 * @return The encrypted version of the original 12-bit block. The encrypted
 * 			version will be the same as the unencrypted if the number of
 * 			rounds is less than 1.
 */
uint16_t encrypt(uint16_t unencrypted_data, uint8_t *round_keys, int num_rounds);

/**
 * Decrypts 12-bits of data using the given number of rounds of the simplified
 * DES encryption algorithm.
 *
 * @note The unencrypted and encrypted data uses only 12 of the 16 available
 * bits. The 4 most significant bits of both should be ignored.
 *
 * @param encrypted_data The 12-bit block of data to decrypt.
 * @param round_keys The keys for each round of the cipher.
 * @param num_rounds The number of rounds of the cipher to perform.
 *
 * @return The decrypted version of the original 12-bit block. The decrypted
 * 			version will be the same as the encrypted if the number of
 * 			rounds is less than 1.
 */
uint16_t decrypt(uint16_t encrypted_data, uint8_t *round_keys, int num_rounds);

#endif
