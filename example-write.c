// Copyright (c) 2023, LINKS Foundation
// SPDX-License-Identifier: Apache-2.0
// All Rights Reserved. See LICENSE for license details.



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <WAM.h>



void WAM_example_write(char* msg) {
	uint8_t mykey[]="my_super_secret_key_for_encryption";
	WAM_channel ch_send, ch_read;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	char write_buff[2000];
	
	IOTA_Endpoint testnet0tls = {.hostname = MAINNET00_HOSTNAME,
							.port = MAINNET00_PORT,
							.tls = MAINNET00_USETLS};

	// Write
	WAM_init_channel(&ch_send, 1, &testnet0tls, &k, &a);
	int i=0;
	while (1) {
		msg[strlen(msg)-1] = i%10 + '0';
		fprintf(stdout, "\nWAM_write \"%s\"...\n", msg);
		WAM_write(&ch_send, msg, strlen(msg), false);
		fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);
		i++;
	}

}


int main(int argc, char **argv) {

	if (argc < 2) {
		// no arguments were passed
		printf("insert a message as argument");
		exit(-1);
    }
	WAM_example_write(argv[1]);
	return 0;
}