/*
 * SipHeader.h
 *
 *  Created on: June 1, 2020
 *      Author: demir
 */
#ifndef _SIP_UTILITY_H_
#define _SIP_UTILITY_H_
 //---------------------------------------------------------------------------
#include "SipMessage.h"

//static int ParseParamPart(int currState, char ch, param_pos_t* current_param);

const char* parse_param_part(const char* buf, uint32_t pos, uint32_t buflen, param_pos_t* cparam, uint32_t maxnum_of_params, uint32_t* num_of_params, int* parse_error, int multihdr_allowed);

int _strnicmp_(const char* s1, const char* s2, size_t n);

//const char* parse_name_addr_part(const char* buf, size_t pos, size_t buflen, str_pos_t* displayName, str_pos_t* url_str);
const char* parse_name_addr_part(const char* buf, uint32_t pos, uint32_t buflen, str_pos_t* displayName, str_pos_t* url_str, int* parse_error, int multihdr_allowed);

//---------------------------------------------------------------------------
#endif // _SIP_UTILITY_H_