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



#ifndef WAM_H
#define WAM_H



#include <stdint.h>
#include "WAM_def.h"



uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint, WAM_Key* PSK, WAM_AuthCtx* auth);
uint8_t WAM_write(WAM_channel* channel, uint8_t* inData, uint32_t inDataSize, bool finalize);
uint8_t WAM_read(WAM_channel* channel, uint8_t* outData, uint32_t *outDataSize);
uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin);



#endif
