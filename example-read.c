// Copyright (c) 2023, LINKS Foundation
// SPDX-License-Identifier: Apache-2.0
// All Rights Reserved. See LICENSE for license details.



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <WAM.h>



static int char2int(char input) {
  if (input >= '0' && input <= '9') return input - '0';
  if (input >= 'A' && input <= 'F') return input - 'A' + 10;
  if (input >= 'a' && input <= 'f') return input - 'a' + 10;
  return -1;  // invalid char
}

int hex2bin(char const str[], size_t str_len, byte_t bin[], size_t bin_len) {
  if (!str || !bin) {
    return -1;
  }

  size_t expected_bin_len = str_len / 2;
  if (bin_len < expected_bin_len) {
    // buffer size is not sufficient
    return -2;
  }

  char* pos = (char*)str;
  for (size_t i = 0; i < expected_bin_len; i++) {
    int v_h = char2int(pos[0]);
    int v_l = char2int(pos[1]);
    if (v_h < 0 || v_l < 0) {
      // invalid char
      return -3;
    }
    bin[i] = v_h * 16 + v_l;
    pos += 2;
  }
  return 0;
}

void WAM_example_read(char* str_index) {
	uint8_t mykey[]="supersecretkeyforencryption!!!!";
	WAM_channel ch_send, ch_read;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t read_buff[2000] = {0};
	uint32_t expected_size = strlen("Hello SPIRS! (0000)"); // assumption: message len is know, future improvement better manage fragmentation
	uint8_t ret = 0;
	uint8_t read_idx[32] = {0};
	
	IOTA_Endpoint testnet0tls = {.hostname = MAINNET00_HOSTNAME,
							 .port = MAINNET00_PORT,
							 .tls = MAINNET00_USETLS};

	// Read
	fprintf(stdout, "WAM_read ...\nStart reading from index: %s\n", str_index);
	WAM_init_channel(&ch_read, 1, &testnet0tls, &k, &a);
	hex2bin(str_index, 64, read_idx, 32);
	set_channel_index_read(&ch_read, read_idx);
	while (1) {
		ret = WAM_read(&ch_read, read_buff, &expected_size);
		if ( ret != WAM_NOT_FOUND) {
			// fprintf(stdout, " bytes_read=%d\n", ch_read.recv_bytes);
			fprintf(stdout, " msg_read=%s\n\n", read_buff);

	 	}	
	}
}


int main(int argc, char **argv) {

	if (argc < 2) {
		// no arguments were passed
		printf("Insert an INDEX as arguments\n");
		exit(-1);
    }

	WAM_example_read( argv[1] );
	
	return 0;
}