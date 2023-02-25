// Copyright (c) 2023, LINKS Foundation
// SPDX-License-Identifier: Apache-2.0
// All Rights Reserved. See LICENSE for license details.



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <WAM.h>



void WAM_example_write() {
	uint8_t mykey[]="supersecretkeyforencryption!!!!";
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
		sprintf(write_buff, "Hello SPIRS! (%.4d)", i);
		fprintf(stdout, "\nWAM_write \"%s\"...\n", write_buff);
		WAM_write(&ch_send, write_buff, strlen(write_buff), false);
		i++;
	}

}


int main(int argc, char **argv) {
	WAM_example_write();
	return 0;
}