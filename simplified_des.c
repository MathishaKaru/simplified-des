/*
 * simplified_des.c
 *
 * This file contains code to encrypt and decrypt using the simplified DES
 * algorithm.
 *
 * This file is part of Comp 280 Project 2.
 *
 * Authors:
 *   1 Kieran Kennedy (kierankennedy@sandiego.edu)
 *   2 Mathisha Karunaratne (mkarunaratne@sandiego.edu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "simplified_des.h"

// The values (e.g. 5) in s1_box are the decimal representation of the binary
// value given in the lab writeup
const uint8_t s1_box[16] = { 5, 2, 1, 6, 3, 4, 7, 0, 1, 4, 6, 2, 0, 7, 5, 3 };
const uint8_t s2_box[16] = { 4, 0, 6, 5, 7, 1, 3, 2, 5, 3, 0, 7, 6, 2, 1, 4 };

/* Expands a 6 bit integer into an 8 bit value using the given instructions.
 *
 * @param input A 6-bit integer in 8-bit form.
 * @return input The digit expanded to a full 8-bits. 
 */
uint8_t expand(uint8_t input) {
	uint8_t r_mask = 3;
	r_mask = r_mask & input;

	int8_t l_mask = 48;
	l_mask = (l_mask & input) << 2;

	//Moving the values that were originially in the 3 and 4th slots into the
	//correct spaces.
	uint8_t three_mask_1 = (8 & input) >> 1;
	uint8_t three_mask_2 = (8 & input) << 1;
	uint8_t four_mask_1 = (4 & input) << 3;
	uint8_t four_mask_2 = (4 & input) << 1;

	//Combining the values
	input = r_mask | l_mask | three_mask_1 | three_mask_2 | four_mask_1 | four_mask_2;

	return input;
}

/* Splits the expanded 8 bit value into two 4-bit halves, and uses S boxes to
 * transform those 4-bit halves into 3-bit values.
 *
 * @param input The expanded 8 bit value
 * @return input The two 3-bit values combined 
 */
uint8_t confuse(uint8_t input) {
	uint8_t right_mask = 15 & input;
	uint8_t left_mask = ((15 << 4) & input) >> 4;

	// Uses S boxes to turn the 4 bit halves into 3 bits
	left_mask = s1_box[left_mask];
	right_mask = s2_box[right_mask];

	left_mask = left_mask << 3;

	// Combines the two 3-bit halves
	input = left_mask | right_mask;

	return input;
}

/* Takes the right side bits, expands it, XOR's it with the key, and then runs the
 * confused function on this value.
 *
 * @param input A 6-bit value in 8-bit form, the right side of the original
 * input value.
 * @param key The round key.
 * @return input The digit expanded and run through the confuse function. 
 */
uint8_t feistel(uint8_t input, uint8_t key) {
	input = expand(input);

	input = input ^ key;

	input = confuse(input);

	return input;
}

/* Peforms the feistel cipher for the whole round.
 *
 * @param input A 6-bit integer in 8-bit form.
 * @param key The round key.
 * @return input The digit expanded to a full 8-bits. 
 */
uint16_t feistel_round(uint16_t input, uint8_t key) {
	// Creates the two masks
	uint8_t right_mask = 63 & input;
	uint16_t temp_left_mask = (63 << 6) & input;

	uint8_t left_mask = temp_left_mask >> 6;
	uint8_t final_right_mask = feistel(right_mask, key);
	// Finalizes the right and left masks
	final_right_mask = left_mask ^ final_right_mask;
	left_mask = right_mask;

	// Creates the final value for the round
	uint16_t round_final = left_mask;
	round_final = (round_final<< 6);
	round_final = round_final | final_right_mask;

	return round_final;
}

/* Generates round keys using a cipher algorithm.
 *
 *@param original_key The 9-bit master key used to generate round keys.
 *@param num_rounds The number of rounds to generate keys for.
 *@return round_keys Returns all the created round keys.
 */
uint8_t *generate_round_keys(uint16_t original_key, unsigned int num_rounds) {
	if (num_rounds > 9) {
		return NULL;
	}

	uint8_t *round_keys = calloc(num_rounds, sizeof(uint8_t));
	uint16_t left_mask, master_mask;

	// Loop which contains the cipher algorith
	for(uint16_t i = 0; i < num_rounds; i++){

		// Creates a left mask only if needed (i.e. If generating more than 2
		// rounds worth of keys)	
		if (num_rounds >= 2){
			left_mask = 64512;
		}
		master_mask = 510;

		// Shifts masks correct number of times to capture correct values for
		// each round.
		master_mask = master_mask >> i;
		left_mask = left_mask >> i;

		// Combines masks with original key to get correctly masked values
		uint16_t temp_val_r = master_mask & original_key;
		uint16_t temp_val_l = left_mask & original_key;

		if (i == 0){
			// If on round 0, use only right mask as left is not needed. 
			round_keys[i] = temp_val_r >> 1;
		} else {
			// Else combine left and right masks after shifting correct
			// amounts.
			round_keys[i] = (temp_val_l >> (10-i)) | (temp_val_r << (i-1));	
		}	
	}

	return round_keys;
}

/*Encrypts the given data over the specified number of rounds using the given
 * keys.
 *
 * @param unencrypted_data The 12-bit unencrypted data.
 * @param round_keys The keys to use for encryption.
 * @param num_rounds The total number of rounds.
 */
uint16_t encrypt(uint16_t unencrypted_data, uint8_t *round_keys, int num_rounds) {
	for (uint16_t i = 0; i < num_rounds; i++) {
		unencrypted_data = feistel_round(unencrypted_data, round_keys[i]);
	}
	//Shifts the bits and combines them in order to swap places.
	uint16_t right_mask = (63 & unencrypted_data) << 6;
	unencrypted_data = unencrypted_data >> 6;
	unencrypted_data = unencrypted_data | right_mask;

	return unencrypted_data;
}

/*Decrypts the given data over the specified number of rounds using the given
 * keys.
 *
 * @param encrypted_data The 12-bit encrypted data.
 * @param round_keys The keys to use for decryption.
 * @param num_rounds The total number of rounds.
 */
uint16_t decrypt(uint16_t encrypted_data, uint8_t *round_keys, int num_rounds) {
	for (uint16_t i = num_rounds; i > 0; i--) {
		encrypted_data = feistel_round(encrypted_data, round_keys[i - 1]);
	}
	//Shifts the bits and combines them in order to swap the places.
	uint16_t right_mask = (63 & encrypted_data) << 6;
	encrypted_data = encrypted_data >> 6;
	encrypted_data = encrypted_data | right_mask;

	return encrypted_data;
}
