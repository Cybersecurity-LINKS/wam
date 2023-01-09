// Copyright (c) 2023, LINKS Foundation
// SPDX-License-Identifier: Apache-2.0
// All Rights Reserved. See LICENSE for license details.



#ifndef WAM_H
#define WAM_H



#include <stdint.h>
#include "WAM_def.h"



uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint, WAM_Key* PSK, WAM_AuthCtx* auth);
uint8_t WAM_write(WAM_channel* channel, uint8_t* inData, uint32_t inDataSize, bool finalize);
uint8_t WAM_read(WAM_channel* channel, uint8_t* outData, uint32_t *outDataSize);
uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin);



#endif