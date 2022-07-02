/*
 * MaxForwardsHeader.h
 *
 *  Created on: Nov 11, 2021
 *      Author: cicerali
 */

#include "MaxForwardsHeader.h"

 /* The Max-Forwards header field must be used with any SIP method to
	limit the number of proxies or gateways that can forward the request
	to the next downstream server.  This can also be useful when the
	client is attempting to trace a request chain that appears to be
	failing or looping in mid-chain.

	The Max-Forwards value is an integer in the range 0-255 indicating
	the remaining number of times this request message is allowed to be
	forwarded.  This count is decremented by each server that forwards
	the request.  The recommended initial value is 70.

	Example:
	   Max-Forwards: 6

	Max-Forwards  =  "Max-Forwards" HCOLON 1*DIGIT

 */

enum class MaxForwardsParsingState
{
	s_hdr_dead = 1,
	s_hdr_spaces_before_value,
	s_hdr_number,
	s_hdr_number_ws
};

/* NOTE: The approach here considers the variable part of a header has already been
		 parsed/extracted before during general message parsing. Therefore, parsing
		 does not consider folding i.e. when it encounters CRLFs it does not consider
		 the end of header, it considers that the folding behavior has already been
		 handled previously. */
MaxForwardsParsingState parse_header_char(MaxForwardsParsingState s, const char ch)
{
	switch (s)
	{
	case MaxForwardsParsingState::s_hdr_spaces_before_value:
		if (IS_DIGIT(ch))
		{
			return MaxForwardsParsingState::s_hdr_number;
		}
		break;

	case MaxForwardsParsingState::s_hdr_number:
		if (IS_DIGIT(ch))
		{
			return MaxForwardsParsingState::s_hdr_number;
		}
		if (IS_WSP(ch))
		{
			return MaxForwardsParsingState::s_hdr_number_ws;
		}
		break;

	case MaxForwardsParsingState::s_hdr_number_ws:
		if (IS_WSP(ch))
		{
			return MaxForwardsParsingState::s_hdr_number_ws;
		}
		break;
	}

	return MaxForwardsParsingState::s_hdr_dead;
}

const char* MaxForwardsHeader::ParseHeader(const char* buf, uint32_t pos, uint32_t buflen)
{
	MaxForwardsParsingState s = MaxForwardsParsingState::s_hdr_spaces_before_value;
	MaxForwardsParsingState prev_s = s;
	const char* maxforwards_mark = NULL;

	const char* p;

	if (buflen == 0)
	{
		this->parsing_stat = PARSING_FAILED_NO_DATA;
		return buf;
	}

	this->rawdata._data = (unsigned char*)buf;
	this->rawdata._length = buflen;
	this->rawdata._pos = pos;

	for (p = buf + pos; p < buf + buflen; p++)
	{
		s = parse_header_char(s, *p);

		switch (s)
		{

		case MaxForwardsParsingState::s_hdr_dead:
			this->parsing_stat = PARSING_FAILED_STATE_DEAD;
			return p;

		case MaxForwardsParsingState::s_hdr_number:
			if (prev_s == MaxForwardsParsingState::s_hdr_spaces_before_value)
			{
				char ch = *p;
				this->maxForwards = ch - '0';
				maxforwards_mark = p;
			}
			else
			{
				char ch = *p;
				uint16_t t;
				t = this->maxForwards;
				t *= 10;
				t += ch - '0';
				if (t > UINT8_MAX)
				{
					this->parsing_stat = PARSING_FAILED_MAX_RANGE;
					return p;
				}
				this->maxForwards = t;
			}
			break;

		case MaxForwardsParsingState::s_hdr_number_ws:
			if (prev_s == MaxForwardsParsingState::s_hdr_number)
			{
				this->number.start = (uint32_t)(maxforwards_mark - buf);
				this->number.length = (uint32_t)(p - maxforwards_mark);
			}
			break;
		}
		prev_s = s;
	}

	/* completed the buffer processing. Check for the last state to complete the job */
	/* be pesimistic and set parsing success */
	this->parsing_stat = PARSED_SUCCESSFULLY;
	if (s == MaxForwardsParsingState::s_hdr_number)
	{
		this->number.start = (uint32_t)(maxforwards_mark - buf);
		this->number.length = (uint32_t)(p - maxforwards_mark);
		return p;
	}
	else if (s == MaxForwardsParsingState::s_hdr_number_ws)
	{
		/* ended after collecting method */
		return p;
	}

	this->parsing_stat = PARSING_FAILED_STATE_UNHANDLED; /* Un-handled success state flow. */
	return p; /* TODO: Provide meaningful error to upper layer */
}

std::string MaxForwardsHeader::GetHeaderValue()
{
	if (!(this->rawdata._length) || !(this->number.length))
	{
		return "";
	}
	return std::string((const char*)this->rawdata._data + this->number.start, this->number.length);
}

int MaxForwardsHeader::GetHeaderValue(std::string& value)
{
	if (!(this->rawdata._length) || !(this->number.length))
	{
		return 1;
	}
	size_t length = (size_t)this->number.length;
	value.reserve(length);
	value.append((const char*)this->rawdata._data + this->number.start, this->number.length);
	return 0;
}

int MaxForwardsHeader::GetHeaderValue(RawData& value)
{
	if (!this->rawdata._length)
	{
		return 1;
	}
	value._data = this->rawdata._data;
	value._length = this->rawdata._length;
	value._pos = this->rawdata._pos;

	return 0;
}

uint16_t MaxForwardsHeader::GetMaxForwards()
{
	return this->maxForwards;
}

void MaxForwardsHeader::PrintOut(std::ostringstream& buf)
{
	buf << "-------- Max-Forwards Header DUMP [parsing-stat=" << this->parsing_stat << "-" << SipHeader::GetParsingStatInText(this->parsing_stat) << "] ----------\n";
	if (this->parsing_stat != PARSED_SUCCESSFULLY)
	{
		buf << std::string((const char*)this->rawdata._data, this->rawdata._length) << std::endl;
		return;
	}
	buf << "number : " << std::string((const char*)this->rawdata._data + this->number.start, this->number.length) << std::endl;
	buf << "--- calculated -------\n";
	buf << "number : " << this->maxForwards << std::endl;
	buf << "----------------\n";
	buf << "Max-Forwards: " << std::string((const char*)this->rawdata._data + this->rawdata._pos, this->rawdata._length - this->rawdata._pos) << std::endl;
	buf << "---------------------------------------\n";
}

bool MaxForwardsHeader::operator==(const MaxForwardsHeader& other)
{
	return this->parsing_stat == PARSED_SUCCESSFULLY && other.parsing_stat == PARSED_SUCCESSFULLY && this->maxForwards == other.maxForwards;
}

bool MaxForwardsHeader::operator!=(const MaxForwardsHeader& other)
{
	return !(operator==(other));
}

std::ostream& operator<<(std::ostream& out, const MaxForwardsHeader& header)
{
	out << "Max-Forwards: " << header.maxForwards;
	return out;
}
