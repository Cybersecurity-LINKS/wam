// Copyright (c) 2023, LINKS Foundation
// SPDX-License-Identifier: Apache-2.0
// All Rights Reserved. See LICENSE for license details.



#include "WAM.h"
#include "WAM_def.h"



const uint8_t wam_tag[WAM_TAG_SIZE] = {
    0x3c, 0xab, 0x78, 0xb6, 0x2, 0x64, 0x47, 0xe9, 0x30, 0x26, 0xd4, 0x1f, 0xad, 0x68, 0x22, 0x27,
    0x41, 0xa4, 0x32, 0xba, 0xbe, 0x54, 0x83, 0xee, 0xab, 0x6b, 0x62, 0xce, 0xf0, 0x5c, 0x7, 0x91
};



uint8_t create_wam_msg(WAM_channel* channel, uint8_t* data, size_t data_len, uint8_t* msg, uint16_t* msg_len);
uint8_t sign_auth_do(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* signature, size_t sig_len);
uint8_t sign_hash_do(uint8_t* data, size_t data_len, uint8_t* key, uint16_t key_len, uint8_t* signature, size_t sig_len);
uint16_t get_messages_number(uint32_t len);
uint8_t reset_index(IOTA_Index* index);
uint8_t update_channel_indexes(WAM_channel* channel);
uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex);
bool is_null_index(uint8_t* idx);
uint8_t generate_iota_index(IOTA_Index* idx);
uint8_t send_wam_message(WAM_channel* ch, uint8_t* raw_data, uint16_t raw_data_size);
uint8_t convert_wam_endpoint(IOTA_Endpoint* wam_ep, iota_client_conf_t *ep);

uint8_t find_wam_msg(find_msg_t* msg_id_list, WAM_channel* channel, uint8_t* msg, uint32_t* msg_len, uint8_t* next_idx);
bool is_wam_valid_msg(uint8_t* msg, uint32_t* msg_len, WAM_channel* channel, uint8_t* next_idx);
uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index);
uint8_t get_msg_from_id(WAM_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint32_t* msg_bin_len);
uint8_t get_msg_id_list(WAM_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len);
uint8_t sign_auth_check(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* recv_signature, size_t recv_sig_len);
uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk);
uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin);
uint8_t set_channel_current_index(WAM_channel* channel, uint8_t* index_bin);
uint8_t set_channel_index_write(WAM_channel* channel, IOTA_Index index);
void print_raw_hex(uint8_t* array, uint16_t array_len);



uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint, WAM_Key* PSK, WAM_AuthCtx* auth) {
	if((channel == NULL) || (endpoint == NULL) || (PSK == NULL) || (auth == NULL)) return WAM_ERR_NULL; 
	if(id < 0) return WAM_ERR_CH_INIT;

	memset(channel->buff_hex_data, 0, IOTA_MAX_MSG_SIZE);
	memset(channel->buff_hex_index, 0, INDEX_HEX_SIZE);
	
	generate_iota_index(&(channel->start_index));
	generate_iota_index(&(channel->next_index));
	copy_iota_index(&(channel->current_index), &(channel->start_index));

	channel->id = id;
	channel->node = endpoint;
	channel->PSK = PSK;
	channel->auth = auth;
	channel->sent_msg = 0;
	channel->recv_msg = 0;
	channel->sent_bytes = 0;
	channel->recv_bytes = 0;
	

	return(WAM_OK);
}


uint8_t WAM_read(WAM_channel* channel, uint8_t* outData, uint32_t *outDataSize) {
	uint8_t msg_to_read[WAM_MSG_SIZE]; uint32_t msg_len = 0;
	uint8_t next_index[INDEX_SIZE];
	uint32_t i = 0, messages = 0, expected_size = *outDataSize;
	find_msg_t* msg_id_list = NULL; uint32_t msg_id_list_len = 0;
	size_t s = 0;
	res_find_msg_t* response;
    uint8_t ret = 0;

	if((channel == NULL) || (outData == NULL)) return WAM_ERR_NULL;

	messages = get_messages_number(expected_size);
	for(i = 0; i <= messages; i++) {
		response = res_find_msg_new();
		
		if((ret = get_msg_id_list(channel, response, &msg_id_list, &msg_id_list_len)) != WAM_OK) {
			break;
		}
		
		if((ret = find_wam_msg(msg_id_list, channel, msg_to_read, &msg_len, next_index)) == WAM_OK){
			if(s + msg_len > expected_size) {
				memcpy(outData + s, msg_to_read, (*outDataSize - s));
				channel->recv_msg++;
				channel->recv_bytes += (*outDataSize - s);
				res_find_msg_free(response);
				return(WAM_BUFF_FULL);
			} else {
				memcpy(outData + s, msg_to_read, msg_len);
				s += msg_len;
			}			
			set_channel_current_index(channel, next_index);
			channel->recv_msg++;
			channel->recv_bytes += msg_len;
		} else {
            if(i > 0){
                ret = WAM_BROKEN_MESSAGE;
            }
            res_find_msg_free(response);
            break;
		}
		res_find_msg_free(response);
	}


    return(ret);
}


uint8_t find_wam_msg(find_msg_t* msg_id_list, WAM_channel* channel, uint8_t* msg, uint32_t* msg_len, uint8_t* next_idx) {
	char **msg_id = NULL;
	res_message_t *response_msg = NULL;

	if((msg_id_list == NULL) || (channel == NULL) || (msg == NULL)) return(WAM_ERR_NULL);

	msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
	while (msg_id != NULL) {
		response_msg = res_message_new();
		if(get_msg_from_id(channel, *msg_id, response_msg, msg, msg_len) == WAM_OK) {
			if(is_wam_valid_msg(msg, msg_len, channel, next_idx)){
				res_message_free(response_msg);
				return(WAM_OK);
			}
		}
		res_message_free(response_msg);

		msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
	}


	return(WAM_NOT_FOUND);
}


bool is_wam_valid_msg(uint8_t* msg, uint32_t* msg_len, WAM_channel* channel, uint8_t* next_idx) {
	uint8_t tmp_data[WAM_MSG_PLAIN_SIZE];
	uint8_t plaintext[WAM_MSG_PLAIN_SIZE];
	uint8_t ciphertext[WAM_MSG_CIPH_SIZE];
	uint8_t AuthSign[AUTH_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t nonce[NONCE_SIZE];
	uint8_t next_index[INDEX_SIZE];
	uint8_t pubk[PUBK_SIZE];
	uint8_t err = 0;
	size_t plain_len = 0, cipher_len = 0;
	uint32_t data_len = 0;

	if((msg == NULL) || (channel == NULL)) return(false);
	if(*msg_len < WAM_MSG_HEADER_SIZE) return false;

	memset(tmp_data, 0, WAM_MSG_PLAIN_SIZE);
	memset(plaintext, 0, WAM_MSG_PLAIN_SIZE);
	memset(ciphertext, 0, WAM_MSG_CIPH_SIZE);
	memset(AuthSign, 0, AUTH_SIZE);
	memset(signature, 0, SIGN_SIZE);
	memset(next_index, 0, INDEX_SIZE);
	memset(pubk, 0, PUBK_SIZE);

	cipher_len = ((size_t) *msg_len) - WAM_TAG_SIZE - NONCE_SIZE;	

	if(memcmp(msg, wam_tag, WAM_TAG_SIZE) != 0) return false;
	memcpy(nonce, msg + WAM_TAG_SIZE, NONCE_SIZE);
	memcpy(ciphertext, msg + WAM_TAG_SIZE + NONCE_SIZE, cipher_len);

	plain_len = cipher_len - ENCMAC_SIZE;

	err |= crypto_secretbox_open_easy(plaintext, ciphertext, cipher_len, nonce, channel->PSK->data);
	if(err) {fprintf(stdout, "\n\n ERROR DECRYPT.\nKey is:\n"); print_raw_hex(channel->PSK->data, PSK_SIZE);}
	if(err) return(false);

	_GET32(plaintext, WAM_OFFSET_DLEN, data_len);
	_GET256(plaintext, WAM_OFFSET_PUBK, pubk);
	_GET256(plaintext, WAM_OFFSET_NIDX, next_index);
	_GET512(plaintext, WAM_OFFSET_AUTH, AuthSign);
	_GET512(plaintext, WAM_OFFSET_SIGN, signature);
	memcpy(tmp_data, plaintext + WAM_OFFSET_DATA, data_len);
	
	if(sign_auth_check(tmp_data, data_len, channel->auth, AuthSign, AUTH_SIZE) != WAM_OK) return(false);
	
	memcpy(tmp_data, plaintext, WAM_OFFSET_SIGN);
	memcpy(tmp_data + WAM_OFFSET_SIGN, plaintext + WAM_OFFSET_DATA, data_len);
	if(sign_hash_check(tmp_data, WAM_OFFSET_SIGN + data_len, signature, pubk) != WAM_OK) return(false);

	if(ownership_check(pubk, channel->read_idx) != WAM_OK) return(false);


	if(err != WAM_OK){
		return(false);
	} else {
		memset(msg, 0, WAM_MSG_SIZE);
		memcpy(msg, plaintext + WAM_OFFSET_DATA, data_len);
		*msg_len = data_len;
		memcpy(next_idx, next_index, INDEX_SIZE);
		return(true);
	}

}


uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index) {
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);

	iota_blake2b_sum(pubk, PUBK_SIZE, hash, BLAKE2B_HASH_SIZE);
	if(memcmp(hash, current_index, INDEX_SIZE) != 0){
		return(WAM_ERR_CRYPTO_OWNERSHIP);
	}
	return(WAM_OK);
}


uint8_t get_msg_from_id(WAM_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint32_t* msg_bin_len) {
	iota_client_conf_t iota_node;
	payload_index_t *indexation_msg = NULL;
	char *msg_data = NULL;
	char msg_string[2*WAM_MSG_HEX_SIZE] = {0};
	int32_t ret = WAM_ERR_RECV;
	
	if((channel == NULL) || (msg_id == NULL)) return(WAM_ERR_NULL);

	convert_wam_endpoint(channel->node, &iota_node);

	ret = get_message_by_id(&iota_node, msg_id, response_info);
	if(ret != 0) return(WAM_ERR_RECV_API);

	if((response_info->is_error == false) && (response_info->u.msg->type == MSG_PAYLOAD_INDEXATION)) {
		indexation_msg = (payload_index_t *)response_info->u.msg->payload;
		msg_data = (char *)indexation_msg->data->data;
		if(strlen(msg_data) <= 2*WAM_MSG_HEX_SIZE) {
			hex2string(msg_data, msg_string, WAM_MSG_HEX_SIZE);
			hex_2_bin(msg_string, strlen(msg_string), (byte_t *)msg_bin, WAM_MSG_SIZE);
			*msg_bin_len = strlen(msg_string) / 2;
			return(WAM_OK);
		}
	}


	return(WAM_ERR_RECV);
}


uint8_t get_msg_id_list(WAM_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len) {
	iota_client_conf_t iota_node;
	int32_t ret = WAM_ERR_RECV;

	if(channel == NULL) return WAM_ERR_NULL;
	if(is_null_index(channel->read_idx)) return(WAM_NO_MESSAGES);
	
	bin_2_hex(channel->read_idx, INDEX_SIZE, (char *) (channel->buff_hex_index), INDEX_HEX_SIZE);

	convert_wam_endpoint(channel->node, &iota_node);

	ret = find_message_by_index(&iota_node, (char *) channel->buff_hex_index, response_info);


	if(ret != 0) return(WAM_ERR_RECV_API);

	if(response_info->is_error == false) {
		*list = response_info->u.msg_ids;
		*list_len = response_info->u.msg_ids->count;
		return(WAM_OK);
	} else {
		return(WAM_ERR_RECV);
	}
}



uint8_t WAM_write(WAM_channel* channel, uint8_t* inData, uint32_t inDataSize, bool finalize) {
	uint8_t msg_to_send[WAM_MSG_SIZE];
	uint16_t msg_len = 0, i = 0, messages = 0;
	size_t s = 0, sent_data = 0;
	uint8_t* d = inData;

	if((channel == NULL) || (inData == NULL)) return WAM_ERR_NULL;


	messages = get_messages_number(inDataSize);
	for(i = 0; i < messages; i++) {
		s = (inDataSize - sent_data) > (DATA_SIZE) ? (DATA_SIZE) : (inDataSize - sent_data);

		if((finalize == true) && (i == messages - 1)) {
			reset_index(&(channel->next_index));
		}

		create_wam_msg(channel, d, s, msg_to_send, &msg_len);  // == wrap

		if(send_wam_message(channel, msg_to_send, msg_len) == WAM_OK) {
			update_channel_indexes(channel);
			d += s;
			sent_data += s;
			channel->sent_bytes += s;
			channel->sent_msg++;
		}
	}


	return(WAM_OK);
}



uint8_t create_wam_msg(WAM_channel* channel, uint8_t* data, size_t data_len, uint8_t* msg, uint16_t* msg_len) {
	uint8_t tmp_data[WAM_MSG_PLAIN_SIZE];
	uint8_t plaintext[WAM_MSG_PLAIN_SIZE];
	uint8_t ciphertext[WAM_MSG_CIPH_SIZE];
	uint8_t AuthSign[AUTH_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t nonce[NONCE_SIZE];
	uint8_t err = 0;
	size_t plain_len = 0, cipher_len = 0;

	memset(tmp_data, 0, WAM_MSG_PLAIN_SIZE);
	memset(plaintext, 0, WAM_MSG_PLAIN_SIZE);
	memset(ciphertext, 0, WAM_MSG_CIPH_SIZE);
	memset(AuthSign, 0, AUTH_SIZE);
	memset(signature, 0, SIGN_SIZE);

	_SET32(plaintext, WAM_OFFSET_DLEN, data_len);
	_SET256(plaintext, WAM_OFFSET_PUBK, channel->current_index.keys.pub);
	_SET256(plaintext, WAM_OFFSET_NIDX, channel->next_index.index);

	err |= sign_auth_do(data, data_len, channel->auth, AuthSign, AUTH_SIZE);
	_SET512(plaintext, WAM_OFFSET_AUTH, AuthSign);

	memcpy(tmp_data, plaintext, WAM_OFFSET_SIGN);
	memcpy(tmp_data + WAM_OFFSET_SIGN, data, data_len);
	err |= sign_hash_do(tmp_data, WAM_OFFSET_SIGN + data_len, 
					   channel->current_index.keys.priv, 64, signature, SIGN_SIZE);
	_SET512(plaintext, WAM_OFFSET_SIGN, signature);

	memcpy(plaintext + WAM_OFFSET_DATA, data, data_len);
	plain_len = data_len + WAM_MSG_HEADER_SIZE;

	iota_crypto_randombytes(nonce, NONCE_SIZE);
	err |= crypto_secretbox_easy(ciphertext, plaintext, plain_len, nonce, channel->PSK->data);
	cipher_len = plain_len + ENCMAC_SIZE;

	memcpy(msg, wam_tag, WAM_TAG_SIZE);
	memcpy(msg + WAM_TAG_SIZE, nonce, NONCE_SIZE);
	memcpy(msg + WAM_TAG_SIZE + NONCE_SIZE, ciphertext, cipher_len);
	*msg_len = cipher_len + WAM_TAG_SIZE + NONCE_SIZE;


	return(err);
}



uint8_t sign_auth_check(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* recv_signature, size_t recv_sig_len) {
	uint8_t tmp_sig[AUTH_SIZE];

	if(a->type == AUTHS_KEY) {
		if(sign_hash_check(data, data_len, recv_signature, a->data) != 0) {
			return(WAM_ERR_CRYPTO_VERAUTHSIGN);
		}
	}
	if(a->type == AUTHS_NONE) {
		memset(tmp_sig, 0xFF, AUTH_SIZE);
		if(memcmp(tmp_sig, recv_signature, AUTH_SIZE) != 0) {
			return(WAM_ERR_CRYPTO_VERAUTHSIGN);
		}   
	}


	return(WAM_OK);
}


uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk) {
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);

	iota_blake2b_sum(data, data_len, hash, BLAKE2B_HASH_SIZE);

	if(crypto_sign_ed25519_verify_detached(recv_sign, hash, BLAKE2B_HASH_SIZE, recv_pubk) != 0) {
		return(WAM_ERR_CRYPTO_VERSIGN);
	}


	return(WAM_OK);
}


uint8_t sign_auth_do(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* signature, size_t sig_len) {
	if(a->type==AUTHS_KEY) {
		sign_hash_do(data, data_len, a->data, a->data_len, signature, sig_len);
	}
	if(a->type == AUTHS_NONE) {
		memset(signature, 0xFF, sig_len);
	}


	return(WAM_OK);
}


uint8_t sign_hash_do(uint8_t* data, size_t data_len, uint8_t* key, uint16_t key_len, uint8_t* signature, size_t sig_len) {
	uint8_t hash[BLAKE2B_HASH_SIZE];

	memset(hash, 0, BLAKE2B_HASH_SIZE);
	iota_blake2b_sum(data, data_len, hash, BLAKE2B_HASH_SIZE);
	iota_crypto_sign(key, hash, BLAKE2B_HASH_SIZE, signature);


	return(WAM_OK);
}


uint16_t get_messages_number(uint32_t len) {
	uint16_t nblocks = len / DATA_SIZE;
    if (len % DATA_SIZE != 0) {
		nblocks++;
	}


    return nblocks;
}


uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin) {
	
	memcpy(channel->read_idx, start_index_bin, INDEX_SIZE);

	return(WAM_OK);
}


uint8_t set_channel_current_index(WAM_channel* channel, uint8_t* index_bin) {

	memcpy(channel->current_index.index, index_bin, INDEX_SIZE);
	memcpy(channel->read_idx, index_bin, INDEX_SIZE);

	return(WAM_OK);
}


uint8_t reset_index(IOTA_Index* index){
	if(index == NULL) return WAM_ERR_NULL;

	memset(index->berry, 0, SEED_SIZE);
	memset(index->index, 0, INDEX_SIZE);
	memset(index->keys.pub, 0, PUBK_SIZE);
	memset(index->keys.priv, 0, PRIK_SIZE);

	return WAM_OK;
}


uint8_t update_channel_indexes(WAM_channel* channel) {
	if(channel == NULL) return(WAM_ERR_NULL);

	copy_iota_index(&(channel->current_index), &(channel->next_index));
	generate_iota_index(&(channel->next_index));

	return(WAM_OK);
}


uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex) {
	if((srcIndex == NULL) || (dstIndex == NULL)) return WAM_ERR_NULL;

	memcpy(dstIndex->index, srcIndex->index, INDEX_SIZE);
	memcpy(dstIndex->berry, srcIndex->berry, SEED_SIZE);
	memcpy(dstIndex->keys.pub, srcIndex->keys.pub, ED_PUBLIC_KEY_BYTES);
	memcpy(dstIndex->keys.priv, srcIndex->keys.priv, ED_PRIVATE_KEY_BYTES);

	return(WAM_OK);
}


bool is_null_index(uint8_t* idx) {
	uint8_t a = 0, i = 0;

	if(idx == NULL) return WAM_ERR_NULL;

	for(i=0; i<INDEX_SIZE; i++) a |= idx[i];
	
	return( (a==0) ? true : false);
}


uint8_t generate_iota_index(IOTA_Index* idx) {
	if(idx == NULL) return WAM_ERR_NULL;

	iota_crypto_randombytes(idx->berry, SEED_SIZE);
	iota_crypto_keypair(idx->berry, &(idx->keys));
	address_from_ed25519_pub(idx->keys.pub, idx->index);


	return(WAM_OK);
}


uint8_t send_wam_message(WAM_channel* ch, uint8_t* raw_data, uint16_t raw_data_size) {
	int32_t ret = WAM_ERR_SEND;
	res_send_message_t response;
	iota_client_conf_t iota_node;

	if(raw_data_size > WAM_MSG_SIZE) return WAM_ERR_SIZE_EXCEEDED;

	bin_2_hex(raw_data, raw_data_size, (char *) (ch->buff_hex_data), IOTA_MAX_MSG_SIZE);
	bin_2_hex(ch->current_index.index, INDEX_SIZE, (char *) (ch->buff_hex_index), INDEX_HEX_SIZE);

	convert_wam_endpoint(ch->node, &iota_node);
	
	memset(&response, 0, sizeof(res_send_message_t));

	ret = send_indexation_msg(&iota_node, (char *) (ch->buff_hex_index), (char *) (ch->buff_hex_data), &response);
	if(ret == 0) {
		if (!response.is_error) {
			fprintf(stdout, "Sent message - ID: %s\n", response.u.msg_id);
			fprintf(stdout, "Sent message - index: %s\n", ch->buff_hex_index);
			// print_raw_hex(ch->buff_hex_data, WAM_MSG_HEX_SIZE);
			return(WAM_OK);
		} else {
			fprintf(stderr, "Node response: %s\n", response.u.error->msg);
			res_err_free(response.u.error);
			return(WAM_ERR_SEND_API);
		}
	} else {
		fprintf(stderr, "function [%s]: returned %d\n", __func__, ret);
		return(WAM_ERR_SEND);
	}


	return(ret);
}


uint8_t convert_wam_endpoint(IOTA_Endpoint* wam_ep, iota_client_conf_t *ep) {
	if ((wam_ep == NULL) || (ep == NULL)) return WAM_ERR_NULL;

	memcpy(ep->host, wam_ep->hostname, IOTA_ENDPOINT_MAX_LEN);
	ep->port = wam_ep->port;
	ep->use_tls = wam_ep->tls;


	return(WAM_OK);
}


void print_raw_hex(uint8_t* array, uint16_t array_len) {

	for(int i = 0; i < array_len; i++)
    	fprintf(stdout, "%#x ", array[i]);
	
	fprintf(stdout, "\n");
}


