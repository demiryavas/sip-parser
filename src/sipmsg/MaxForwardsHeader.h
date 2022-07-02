/*
 * MaxForwardsHeader.h
 *
 *  Created on: Nov 11, 2021
 *      Author: cicerali
 */

#ifndef _MAX_FORWARDS_HEADER_H_
#define _MAX_FORWARDS_HEADER_H_
 //---------------------------------------------------------------------------

#include "SipMessage.h"
#include "SipHeader.h"

class MaxForwardsHeader : public SipHeader
{
public:
	MaxForwardsHeader() :number({ 0, 0 }), maxForwards(0) {}

	/* Parsing utility */
	const char* ParseHeader(const char* buf, uint32_t pos, uint32_t buflen);

	/* both provide the value part, which can be re-formatted if the header has
   subparts or represents a multiple-header */
	std::string GetHeaderValue();
	int GetHeaderValue(std::string& value);

	/* provides the pointer to value part of the header in question.
	   No any additional copy applied. */
	int GetHeaderValue(RawData& value);

	uint16_t GetMaxForwards();

	void PrintOut(std::ostringstream& buf);

	bool operator==(const MaxForwardsHeader& other);
	bool operator!=(const MaxForwardsHeader& other);
	friend std::ostream& operator<< (std::ostream& out, const MaxForwardsHeader& max);
private:
	str_pos_t number;
	/* storing it in uint16_t because uint8_t may not give the desired output with cout or ostringstream */
	uint16_t maxForwards;
};

//---------------------------------------------------------------------------
#endif /* _MAX_FORWARDS_HEADER_H_ */