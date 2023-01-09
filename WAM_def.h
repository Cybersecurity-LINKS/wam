// Copyright (c) 2023, LINKS Foundation
// SPDX-License-Identifier: Apache-2.0
// All Rights Reserved. See LICENSE for license details.



#ifndef WAM_DEF_H
#define WAM_DEF_H



#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "sodium.h"
#include "core/address.h"
#include "crypto/iota_crypto.h"
#include "core/utils/byte_buffer.h"
#include "client/api/v1/send_message.h"
#include "client/api/v1/get_message.h"
#include "client/api/v1/find_message.h"
#include "client/client_service.h"



#define _SET512(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 64); }while(0)
#define _SET256(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 32); }while(0)
#define _SET128(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 16); }while(0)
#define _SET64(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 8); }while(0)
#define _SET32(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 4); }while(0)
#define _SET16(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 2); }while(0)
#define _GET512(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 64); }while(0)
#define _GET256(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 32); }while(0)
#define _GET128(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 16); }while(0)
#define _GET64(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 8); }while(0)
#define _GET32(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 4); }while(0)
#define _GET16(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 2); }while(0)



#define IOTA_MAX_MSG_SIZE    (31777)

#define DATA_SIZE            (800)
#define DLEN_SIZE              (4)
#define INDEX_SIZE            (32)
#define PUBK_SIZE             (32)
#define SIGN_SIZE             (64)
#define AUTH_SIZE             (64)

#define SEED_SIZE             (32)
#define PRIK_SIZE             (64)
#define PSK_SIZE              (32)
#define NONCE_SIZE            (24)
#define ENCMAC_SIZE           (16)
#define WAM_TAG_SIZE          (32)

#define BLAKE2B_HASH_SIZE     (32)

#define WAM_MSG_HEADER_SIZE       (INDEX_SIZE + PUBK_SIZE + SIGN_SIZE + AUTH_SIZE + DLEN_SIZE)
#define WAM_MSG_PLAIN_SIZE        (WAM_MSG_HEADER_SIZE + DATA_SIZE)
#define WAM_MSG_CIPH_SIZE         (WAM_MSG_PLAIN_SIZE + ENCMAC_SIZE)
#define WAM_MSG_SIZE              (WAM_MSG_CIPH_SIZE + NONCE_SIZE + WAM_TAG_SIZE)

#define INDEX_HEX_SIZE           (1 + 2 * INDEX_SIZE)
#define MSGID_HEX_SIZE           (64)
#define ENDPTNAME_SIZE           (64)
#define WAM_MSG_HEX_SIZE         (1 + 2 * WAM_MSG_SIZE)



enum {
	WAM_OK = 0,
    WAM_BROKEN_MESSAGE = 0x33,
	WAM_NOT_FOUND = 0x44,
	WAM_BUFF_FULL = 0x55,
	WAM_NO_MESSAGES = 0xE3,

	WAM_ERR_CH_INIT = 0xF1,
	WAM_ERR_NULL = 0xF2,
	WAM_ERR_SIZE_EXCEEDED = 0xF3,
	WAM_ERR_MAX_RETRY_EXCEEDED = 0xF4,
	WAM_ERR_SEND = 0xF5,
	WAM_ERR_SEND_API = 0xF6,
	WAM_ERR_RECV = 0xF7,
	WAM_ERR_RECV_API = 0xF8,
	WAM_ERR_RECV_MANYMSG = 0xF9,
	WAM_ERR_CRYPTO_ENC = 0xFA,
	WAM_ERR_CRYPTO_DEC = 0xFB,
	WAM_ERR_CRYPTO_MAC = 0xFC,
	WAM_ERR_CRYPTO_VERSIGN = 0xFD,
	WAM_ERR_CRYPTO_VERAUTHSIGN = 0xFE,
	WAM_ERR_CRYPTO_OWNERSHIP = 0xFF,
};



enum {
	WAM_OFFSET_DLEN = 0,
	WAM_OFFSET_PUBK = 4,
	WAM_OFFSET_NIDX = 36,
	WAM_OFFSET_AUTH = 68,
	WAM_OFFSET_SIGN = 132,
	WAM_OFFSET_DATA = 196,
};



#define WAM_PSK "AC88DFA4DEAAE33E0135DFF4A6BB678FA7FFDC10869ADC6E6D38DDCBC90CAC88"
#define WAM_MAX_RETRY     (5)

#define DEVNET00_HOSTNAME     "api.lb-0.h.chrysalis-devnet.iota.cafe\0"
#define DEVNET00_PORT         (443)
#define DEVNET00_USETLS       (true)

#define DEVNET01_HOSTNAME     "api.lb-1.h.chrysalis-devnet.iota.cafe\0"
#define DEVNET01_PORT         (443)
#define DEVNET01_USETLS       (true)

#define MAINNET00_HOSTNAME    "chrysalis-nodes.iota.org\0"
#define MAINNET00_PORT        (443)
#define MAINNET00_USETLS      (true)

#define MAINNET01_HOSTNAME    "chrysalis-nodes.iota.cafe\0"
#define MAINNET01_PORT        (443)
#define MAINNET01_USETLS      (true)



typedef struct IOTA_Endpoint_t {
	char hostname[ENDPTNAME_SIZE];
	uint16_t port;
	bool tls;
} IOTA_Endpoint;

typedef struct IOTA_index_t {
	uint8_t index[INDEX_SIZE];
	uint8_t berry[SEED_SIZE];
	iota_keypair_t keys;
} IOTA_Index;

typedef enum {AUTHS_KEY, AUTHS_NONE} AuthType;

typedef struct WAM_AuthCtx_t {
	uint8_t* data;
	uint16_t data_len;
	AuthType type;
} WAM_AuthCtx;

typedef struct WAM_Key_t {
	uint8_t *data;
	uint16_t data_len;
} WAM_Key;

typedef struct WAM_channel_t {
	uint16_t id;
	
	IOTA_Endpoint* node;

	IOTA_Index start_index;
	IOTA_Index current_index;
	IOTA_Index next_index;
	
	uint8_t read_idx[INDEX_SIZE];

	WAM_Key *PSK;
	WAM_AuthCtx *auth;
    
	uint16_t sent_msg;
	uint16_t recv_msg;
	uint16_t sent_bytes;
	uint32_t recv_bytes;

    uint8_t buff_hex_data[IOTA_MAX_MSG_SIZE];
    uint8_t buff_hex_index[INDEX_HEX_SIZE];
} WAM_channel;



#endif