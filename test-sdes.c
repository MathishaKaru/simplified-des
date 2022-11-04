#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "simplified_des.h"
#include "mut.h"

TESTSUITE_BEGIN

TEST_BEGIN ("expand")
	// test case 1 (only bit 1 set)
	uint8_t expanded = expand(0x20);
	//printf("%hhx\n", expanded);
	CHECK(expanded == 0x80);

	// test case 2 (only bit 2 set)
	expanded = expand(0x10);
	CHECK(expanded == 0x40);

	// test case 3 (only bit 3 set)
	expanded = expand(0x8);
	CHECK(expanded == 0x14);

	// test case 4 (only bit 4 set)
	expanded = expand(0x4);
	CHECK(expanded == 0x28);

	// test case 5 (only bit 5 set)
	expanded = expand(0x2);
	CHECK(expanded == 0x2);

	// test case 6 (only bit 6 set)
	expanded = expand(0x1);
	CHECK(expanded == 0x1);

	// test case 7 (a couple bits set)
	expanded = expand(0x24);
	CHECK(expanded == 0xA8);
	
	// test case 8 (several bits set)
	expanded = expand(0x35);
	CHECK(expanded == 0xE9);

TEST_END

TEST_BEGIN ("confuse")
	// test case 1
	uint8_t jumbled = confuse(0x74);
	//printf("%hhx\n", jumbled);
	CHECK(jumbled == 0x07);

	// test case 2
	jumbled = confuse(0x0A);
	//printf("%hhx\n", jumbled);
	CHECK(jumbled == 0x28);

	// test case 3 (s2_box contents)
	uint8_t inputs[16] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F};
	uint8_t results[16] = {0xC, 0x8, 0xE, 0xD, 0xF, 0x9, 0xB, 0xA, 0xD, 0xB, 0x8, 0xF, 0xE, 0xA, 0x9, 0xC};

	for (int i = 0; i < 16; i++) {
		jumbled = confuse(inputs[i]);
		//printf("input[%d] = %hhx, result = %hhx\n", i, inputs[i], jumbled);
		CHECK(jumbled == results[i]);
	}

TEST_END

TEST_BEGIN ("feistel function")
	// test case 1
	uint8_t output = feistel(0x25, 0x3B);
	//printf("%hhx\n", output);
	CHECK(output == 0x26);

	// test case 2
	output = feistel(0x35, 0xE3);
	//printf("%hhx\n", output);
	CHECK(output == 0x28);
TEST_END

TEST_BEGIN ("one feistel round")
	// test case 1 function
	uint16_t round_output = feistel_round(0xD65, 0x3B);
	//printf("%hx\n", round_output);
	CHECK(round_output == 0x953)

	// test case 2 function
	round_output = feistel_round(0x8B5, 0xE3);
	//printf("%hx\n", round_output);
	CHECK(round_output == 0xD4A)
TEST_END

TEST_BEGIN ("generate_round_keys")
	// test case 1
	uint8_t *keys = generate_round_keys(0x13B, 4);
	/*
	for (int i = 0; i < 4; i++) {
		printf("round %d: %hhx\n", i, keys[i]);
	}
	*/
	CHECK(keys[0] == 0x9D);
	CHECK(keys[1] == 0x3B);
	CHECK(keys[2] == 0x77);
	CHECK(keys[3] == 0xEE);
	free(keys);

	// test case 2
	keys = generate_round_keys(0x1C7, 2);
	/*
	for (int i = 0; i < 2; i++) {
		printf("round %d: %hhx\n", (i+1), keys[i]);
	}
	*/
	CHECK(keys[0] == 0xE3);
	CHECK(keys[1] == 0xC7);
	free(keys);

	// test case 3 (too many rounds!)
	keys = generate_round_keys(0x1C7, 10);
	CHECK(keys == NULL);
TEST_END

TEST_BEGIN ("encrypt")
	// test case 1
	uint8_t keys[2] = { 0x9D, 0x3B };
	uint16_t encrypted = encrypt(0x8B5, keys, 2);
	//printf("%hx\n", encrypted);
	CHECK(encrypted == 0x4E5);
TEST_END

TEST_BEGIN ("decrypt")
	// test case 1
	uint8_t keys[2] = { 0x9D, 0x3B };
	uint16_t decrypted = decrypt(0x4E5, keys, 2);
	//printf("%hx\n", decrypted);
	CHECK(decrypted == 0x8B5);
TEST_END

TESTSUITE_END
