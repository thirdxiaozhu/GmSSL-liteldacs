//
// Created by 邹嘉旭 on 2025/5/4.
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/rand.h>
#include <gmssl/error.h>


int generate_kek(unsigned int uiKEKIndex)
{
	char filename[256];
	uint8_t kek[16];
	FILE *file;

	if (rand_bytes(kek, sizeof(kek)) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "/var/sdf/kek-%u.key", uiKEKIndex);
	if (!(file = fopen(filename, "wb"))) {
		error_print();
		return -1;
	}
	if (fwrite(kek, 1, sizeof(kek), file) != sizeof(kek)) {
		fclose(file);
		error_print();
		return -1;
	}
	fclose(file);

	printf("KEK #%u generated, saved to kek-%u.key\n", uiKEKIndex, uiKEKIndex);

	return 1;
}

 int generate_sign_key(unsigned int uiKeyIndex, const char *pass)
{
	SM2_KEY sm2_key;
	char filename[256];
	FILE *file;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "sm2sign-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	snprintf(filename, sizeof(filename), "sm2signpub-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_public_key_info_to_pem(&sm2_key, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	printf("SM2 signing key pair #%u generated, saved to sm2sign-%u.pem and sm2signpub-%u.pem\n", uiKeyIndex, uiKeyIndex, uiKeyIndex);

	return 1;
}

 int generate_enc_key(unsigned int uiKeyIndex, const char *pass)
{
	SM2_KEY sm2_key;
	char filename[256];
	FILE *file;

	if (sm2_key_generate(&sm2_key) != 1) {
		error_print();
		return -1;
	}

	snprintf(filename, sizeof(filename), "sm2enc-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_private_key_info_encrypt_to_pem(&sm2_key, pass, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	snprintf(filename, sizeof(filename), "sm2encpub-%u.pem", uiKeyIndex);
	if ((file = fopen(filename, "wb")) == NULL) {
		fclose(file);
		error_print();
		return -1;
	}
	if (sm2_public_key_info_to_pem(&sm2_key, file) != 1) {
		error_print();
		return -1;
	}
	fclose(file);

	printf("SM2 encryption key pair #%u generated, saved to sm2enc-%u.pem and sm2encpub-%u.pem\n", uiKeyIndex, uiKeyIndex, uiKeyIndex);

	return 1;
}