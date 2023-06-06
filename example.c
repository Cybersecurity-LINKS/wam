// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <WAM.h>



void WAM_example_write_read() {
	uint8_t mykey[]="supersecretkeyforencryption!!!!";
	WAM_channel ch_send, ch_read;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t my_msg[] = "Hello";
	uint8_t read_buff[2000];
	uint32_t expected_size = 6;
	uint8_t ret = 0;
	
	IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
							 .port = 443,
							 .tls = true};

	// Write
	fprintf(stdout, "WAM_write ...\n");
	WAM_init_channel(&ch_send, 1, &testnet0tls, &k, &a);
	WAM_write(&ch_send, my_msg, 6, false);
	fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

	// Read
	WAM_init_channel(&ch_read, 1, &testnet0tls, &k, &a);
	set_channel_index_read(&ch_read, ch_send.start_index.index);
	ret = WAM_read(&ch_read, read_buff, &expected_size);

	fprintf(stdout, "WAM_read ret:");
	fprintf(stdout, "\n\t val=%d", ret);
	fprintf(stdout, "\n\t expctsize=%d \t", expected_size);
	fprintf(stdout, "\n\t msg_read=%d \t", ch_read.recv_msg);
	fprintf(stdout, "\n\t bytes_read=%d \t", ch_read.recv_bytes);
	fprintf(stdout, "\n\t cmpbuff=%s \n", (memcmp(my_msg, read_buff, 6)==0) ? "success" : "failure");
}


int main() {
	WAM_example_write_read();
	return 0;
}
