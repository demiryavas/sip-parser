

#include "SipMessage.h"
#include "sipparser.h"
#include "SipUri.h"
#include "CSeqHeader.h"
#include "MaxForwardsHeader.h"
#include "CallIdHeader.h"
#include "ViaHeader.h"
#include "FromHeader.h"
#include "ToHeader.h"
#include "SubjectHeader.h"
#include "ContentTypeHeader.h"
#include "ContactHeader.h"
#include "AcceptHeader.h"
#include "AcceptEncodingHeader.h"
#include "AcceptLanguageHeader.h"
#include "AllowHeader.h"
#include "MessageProcessor.h"

#include <stdio.h>

#include <iostream>
#include <sstream>

#include <cmath>

#define SIP_DETAILED_DEBUG

MessageProcessor* msgProcessor = NULL;

sip_parser* test_parser = NULL;

sip_parser_settings settings;

std::list<SipMessage*> sipMsgList;


/* Message handler callback to be invoked when a complete message received during parsing */
int HandleParsedMessage(SipMessage* msg)
{
	/* As tester behavior, save the received message into the list */
	sipMsgList.push_back(msg);
	std::cout << "\n............................. <HANDLE Parsed MESSAGE> ......................\n";
	std::cout << "HandleParsedMessage: Received a new message. Message count in list: "
		<< sipMsgList.size() << std::endl;
	std::ostringstream buff;
	msg->PrintOut(buff);
	std::cout << buff.str() << std::endl;
	std::cout << "\n............................. >HANDLE PARSED MESSAGE< ......................\n";

	return 0;
}

void TestForURI()
{
	//const char* data = "INVITE sip:alice@atlanta.com";
	//const char* data = "sip:alice@atlanta.com";
	//const char* data = "sip:alice:secretword@atlanta.com;transport=tcp";
	//const char* data = "INVITE sip:alice:secretword@atlanta.com;transport=tcp";
	//const char* data = "sips:alice@atlanta.com?subject=project%20x&priority=urgent";
	//const char* data = "sip:+12125551212:1234@gateway.com;user=phone";
	//const char* data = "sips:1212@gateway.com";
	//const char* data = "sip:alice@192.0.2.4";
	//const char* data = "sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com";
	const char* data = "INVITE sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com";
	//const char* data = "sip:alice;day=tuesday@atlanta.com";
	/* invalid URI examples */
	//const char* data = "sip:user:password:somethingelse@outlook.com";
	//const char* data = "sipps:user@outlook.com;parameters?headers";
	size_t length = strlen(data);

	SipUri uri;
	int result = uri.ParseUri(data, 7, length);
	std::cout << "Parsing result: " << result << std::endl;
	std::ostringstream buff;
	uri.PrintOut(buff);
	std::cout << buff.str();
}

int PartialReceiveEmulation(char* data, long length, long partition)
{
	int part_count = 0;
	size_t nparsed = 0;

	if (partition > length)
	{
		partition = length;
	}
	part_count = ceil(double(length) / double(partition));
	for (int i = 0; i < part_count; i++)
	{
		/* Try to determine if we are at last partition which can be less than the partition-length */
		long upto = (((i * partition) + partition) > length) ? (length - (i * partition)) : partition;
		nparsed += msgProcessor->MessageReceived((unsigned char*)data + (i * partition), upto);
	}
	return nparsed;
}

int DatagramEmulation(char* data, long length)
{
	return msgProcessor->MessageReceived((unsigned char*)data, length);
}


void TestForContentLengthHeader(SipMessage* currentmsg)
{
	std::cout << "----- Header Test ------ Content-Length -------\n";
	std::string hdr = currentmsg->GetHeaderValue((unsigned char*)"Content-Length");
	std::cout << hdr << std::endl;
}

void TestForContentTypeHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"Content-Type", 12);

	std::cout << "----- Header Test ------ Content-Type -------\n";
	std::cout << "-- Message has " << count << " Content-Type header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Content-Type", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		ContentTypeHeader ctype;
		const char* p = ctype.ParseHeader((const char*)rd._data, 0, rd._length);
		if (ctype.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(ctype.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		ctype.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string ctypes = ctype.GetHeaderValue();
		std::cout << ctypes << std::endl;
	}
}

void TestForAcceptHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"Accept", 6);

	std::cout << "----- Header Test ------ Accept -------\n";
	std::cout << "-- Message has " << count << " Accept header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Accept", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		AcceptHeader accpt;
		const char* p = accpt.ParseHeader((const char*)rd._data, 0, rd._length);
		if (accpt.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(accpt.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		accpt.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string accpts = accpt.GetHeaderValue();
		std::cout << accpts << std::endl;
	}
}

void TestForAcceptEncodingHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"Accept-Encoding", 15);

	std::cout << "----- Header Test ------ Accept-Encoding -------\n";
	std::cout << "-- Message has " << count << " Accept-Encoding header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Accept-Encoding", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		AcceptEncodingHeader accpt;
		const char* p = accpt.ParseHeader((const char*)rd._data, 0, rd._length);
		if (accpt.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(accpt.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		accpt.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string accpts = accpt.GetHeaderValue();
		std::cout << accpts << std::endl;
	}
}

void TestForAcceptLanguageHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"Accept-Language", 15);

	std::cout << "----- Header Test ------ Accept-Language -------\n";
	std::cout << "-- Message has " << count << " Accept-Language header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Accept-Language", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		AcceptLanguageHeader accpt;
		const char* p = accpt.ParseHeader((const char*)rd._data, 0, rd._length);
		if (accpt.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(accpt.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		accpt.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string accpts = accpt.GetHeaderValue();
		std::cout << accpts << std::endl;
	}
}

void TestForAllowHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"Allow", 5);

	std::cout << "----- Header Test ------ Allow -------\n";
	std::cout << "-- Message has " << count << " Allow header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Allow", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		AllowHeader alw;
		const char* p = alw.ParseHeader((const char*)rd._data, 0, rd._length);
		if (alw.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(alw.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		alw.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string allows = alw.GetHeaderValue();
		std::cout << allows << std::endl;
	}
}

void TestForCallIDHeader(SipMessage* currentmsg)
{
	std::cout << "----- Header Test ------ Call-ID -------\n";
	RawData rd;
	std::ostringstream msgbuf;
	currentmsg->GetHeaderValue((unsigned char*)"Call-ID", rd);
	std::cout << std::string((char*)rd._data, rd._length) << std::endl;
	std::cout << "------ After parsing ----------\n";
	CallIdHeader callid;
	callid.ParseHeader((const char*)rd._data, 0, rd._length);
	msgbuf.clear();
	msgbuf.str("");
	callid.PrintOut(msgbuf);
	std::cout << msgbuf.str() << std::endl;
	std::string cid = callid.GetHeaderValue();
	std::cout << cid << std::endl;
}

void TestForCSeqHeader(SipMessage* currentmsg)
{
	std::cout << "----- Header Test ------ CSeq -------\n";
	RawData rd;
	std::ostringstream msgbuf;
	currentmsg->GetHeaderValue((unsigned char*)"CSeq", rd);
	std::cout << std::string((char*)rd._data, rd._length) << std::endl;
	std::cout << "------ After parsing ----------\n";
	CSeqHeader cseq;
	const char* p = cseq.ParseHeader((const char*)rd._data, 0, rd._length);
	if (cseq.parsing_stat != PARSED_SUCCESSFULLY)
	{
		int len = rd._length - (p - (const char*)rd._data);
		fprintf(stderr, "CSeq Header parsing failed with reason %d at position--> %.*s \n", cseq.parsing_stat, len, p);
		return;
	}
	msgbuf.clear();
	msgbuf.str("");
	cseq.PrintOut(msgbuf);
	std::cout << msgbuf.str() << std::endl;
	std::string cs = cseq.GetHeaderValue();
	std::cout << cs << std::endl;
}

void TestForMaxForwardsHeader(SipMessage* currentmsg)
{
	std::cout << "----- Header Test ------ Max-Forwards -------\n";
	RawData rd;
	std::ostringstream msgbuf;
	currentmsg->GetHeaderValue((unsigned char*)"Max-Forwards", rd);
	std::cout << std::string((char*)rd._data, rd._length) << std::endl;
	std::cout << "------ After parsing ----------\n";
	MaxForwardsHeader maxForwards;
	const char* p = maxForwards.ParseHeader((const char*)rd._data, 0, rd._length);
	if (maxForwards.parsing_stat != PARSED_SUCCESSFULLY)
	{
		std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(maxForwards.parsing_stat)
			<< " at pos:  '"
			<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
		return;
	}
	msgbuf.clear();
	msgbuf.str("");
	maxForwards.PrintOut(msgbuf);
	std::cout << msgbuf.str() << std::endl;
	std::string cs = maxForwards.GetHeaderValue();
	std::cout << cs << std::endl;
}


void TestForViaHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"v", 1);

	std::cout << "----- Header Test ------ Via -------\n";
	std::cout << "-- Message has " << count << " Via header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Via", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "[" << i << "]------After parsing----------\n";
		ViaHeader vhdr;
		const char* p = vhdr.ParseHeader((const char*)rd._data, 0, rd._length);
		//if (vhdr.ParseHeader((const char*)rd._data, 0, rd._length) != 0)
		if (vhdr.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(vhdr.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		vhdr.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string conts = vhdr.GetHeaderValue();
		std::cout << conts << std::endl;
	}
}

void TestForContactHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"m", 1);

	std::cout << "----- Header Test ------ Contact -------\n";
	std::cout << "-- Message has " << count << " contact header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Contact", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "[" << i << "]------After parsing----------\n";
		ContactHeader cont;
		const char* p = cont.ParseHeader((const char*)rd._data, 0, rd._length);
		//if (cont.ParseHeader((const char*)rd._data, 0, rd._length) != 0)
		if (cont.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(cont.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		cont.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string conts = cont.GetHeaderValue();
		std::cout << conts << std::endl;
	}
}

void TestForFromHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"from", 1);

	std::cout << "----- Header Test ------ From -------\n";
	std::cout << "-- Message has " << count << " From header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"From", rd);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		FromHeader from;
		const char* p = from.ParseHeader((const char*)rd._data, 0, rd._length);
		if (from.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(from.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		from.ParseUrlPart();
		msgbuf.clear();
		msgbuf.str("");
		from.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string froms = from.GetHeaderValue();
		std::cout << froms << std::endl;
	}
}

void TestForToHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"To", 1);

	std::cout << "----- Header Test ------ To -------\n";
	std::cout << "-- Message has " << count << " To header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"To", rd);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		ToHeader to;
		const char* p = to.ParseHeader((const char*)rd._data, 0, rd._length);
		if (to.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(to.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		to.ParseUrlPart();
		msgbuf.clear();
		msgbuf.str("");
		to.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string tos = to.GetHeaderValue();
		std::cout << tos << std::endl;
	}
}

void TestForSubjectHeader(SipMessage* currentmsg)
{
	RawData rd;
	std::ostringstream msgbuf;
	int count = currentmsg->GetHeaderCount((unsigned char*)"Subject", 1);

	std::cout << "----- Header Test ------ Subject -------\n";
	std::cout << "-- Message has " << count << " Subject header\n";
	for (int i = 0; i < count; i++)
	{
		currentmsg->GetHeaderValue((unsigned char*)"Subject", rd, i);
		std::cout << std::string((char*)rd._data, rd._length) << std::endl;
		std::cout << "------ After parsing ----------\n";
		SubjectHeader subj;
		const char* p = subj.ParseHeader((const char*)rd._data, 0, rd._length);
		if (subj.parsing_stat != PARSED_SUCCESSFULLY)
		{
			std::cerr << "Parsing error: " << SipHeader::GetParsingStatInText(subj.parsing_stat)
				<< " at pos:  '"
				<< std::string(p, (rd._length - (p - (const char*)rd._data))) << "'\n";
			continue;
		}
		msgbuf.clear();
		msgbuf.str("");
		subj.PrintOut(msgbuf);
		std::cout << msgbuf.str() << std::endl;
		std::string subjs = subj.GetHeaderValue();
		std::cout << subjs << std::endl;
	}
}

void BodyTest(SipMessage* currentmsg)
{
	std::cout << "----- Body Test ------ approach 1 ------\n";
	RawData* rwd = currentmsg->GetBody();
	std::ostringstream msgbuf;
	SipMessage::PrintoutData(msgbuf, rwd->_data, rwd->_length);
	std::cout << msgbuf.str() << std::endl;

	std::cout << "----- Body Test ------ approach 2 ------\n";
	RawData rwd2;
	currentmsg->GetBody(rwd2);
	msgbuf.clear();
	msgbuf.str("");
	SipMessage::PrintoutData(msgbuf, rwd2._data, rwd2._length);
	std::cout << msgbuf.str() << std::endl;
}

void usage(const char* name) {
	fprintf(stderr,
		//"Usage: %s $type $filename\n"
		"Usage: %s $filename [-t (type) r/b/q] [-p (process) s/d] \n"
		"    where 'type' can be one of {r,b,q}\n"
		"          parses message as a Response, reQuest, or Both\n"
		"    where 'process' can be one of {s,d}\n",
		"          's' is for streamed messages, 'd' is for datagram\n",
		name);
	exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
	enum sip_parser_type file_type;
	size_t nparsed = 0;
	char* data = NULL;
	long file_length = 0;
	//long ll = 0;
	SipMessage* currentmsg = NULL;
	std::ostringstream msgbuf;
	int pos = 0;
	int processing_type = 0; /* 0 : datagram, 1 : streaming */

	TestForURI();

	if (argc <= 1) {
		usage(argv[0]);
	}

	//for (pos = 2; pos < argc; pos++) {
	pos = 2;
	while (pos < argc)
	{
		std::cout << argv[pos] << std::endl;
		if (0 == strncmp(argv[pos], "-t", 2))
		{
			pos++;
			char ch = argv[pos][0];
			switch (ch)
			{
			case 'r':
				file_type = SIP_RESPONSE;
				break;

			case 'q':
				file_type = SIP_REQUEST;
				break;

			case 'b':
				file_type = SIP_BOTH;
				break;

			default:
				usage(argv[0]);
			}
		}
		else if (0 == strncmp(argv[pos], "-p", 2))
		{
			pos++;
			char ch = argv[pos][0];
			switch (ch)
			{
			case 's':
				processing_type = 1;
				break;

			case 'q':
				processing_type = 0;
				break;

			default:
				usage(argv[0]);
			}
		}
		pos++;
	}

	char* filename = argv[1];
	FILE* file = fopen(filename, "rb");
	if (file == NULL) {
		perror("fopen");
		//fclose(file);
		return EXIT_FAILURE;
	}

	fseek(file, 0, SEEK_END);
	file_length = ftell(file);
	if (file_length == -1) {
		perror("ftell");
		fclose(file);
		return EXIT_FAILURE;
	}
	fseek(file, 0, SEEK_SET);

	data = (char*)malloc(file_length);
	if (fread(data, 1, file_length, file) != (size_t)file_length) {
		fprintf(stderr, "couldn't read entire file\n");
		free(data);
		fclose(file);
		return EXIT_FAILURE;
	}

	/* Note that, under normal condition msgProcessor instance shall be connection-based,
	   which could be through TCP or UDP */
	msgProcessor = new MessageProcessor(&HandleParsedMessage);
	//msgProcessor->Initialize();

#if 0
	memset(&settings, 0, sizeof(settings));
	settings.on_message_begin = on_message_begin;
	settings.on_url = on_url;
	settings.on_status = on_response_status;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;
	settings.on_headers_complete = on_headers_complete;
	settings.on_body = on_body;
	settings.on_message_complete = on_message_complete;
#endif

	/* TODO: parser-type should be passed as a parameter or parser should be initialized here. */
	if (processing_type == 1)
	{
		nparsed = PartialReceiveEmulation(data, file_length, 10);
	}
	else
	{
		nparsed = DatagramEmulation(data, file_length);
	}

	free(data);

	if (nparsed != (size_t)file_length) {
		fprintf(stderr,
			"Error: %s (%s)\n",
			//sip_errno_description(SIP_PARSER_ERRNO(&parser)),
			sip_errno_description(SIP_PARSER_ERRNO(test_parser)),
			//sip_errno_name(SIP_PARSER_ERRNO(&parser)));
			sip_errno_name(SIP_PARSER_ERRNO(test_parser)));
		//goto fail;
		fclose(file);
		return EXIT_FAILURE;
	}

	currentmsg = sipMsgList.back();
	if (!currentmsg)
	{
		std::cerr << "Problem with having a parsed message...\n";
		return EXIT_FAILURE;
	}
	currentmsg->PrintOut(msgbuf);
	std::cout << msgbuf.str();

	//  std::cout << "----- Header Test ------ Content-Length -------\n";
	//  std::string hdr = currentmsg->GetHeaderValue((unsigned char*)"Content-Length");
	//  std::cout << hdr << std::endl;

	TestForContentLengthHeader(currentmsg);

	//  std::cout << "----- Header Test ------ Content-Type -------\n";
	//  currentmsg->GetHeaderValue((unsigned char*)"Content-Type", hdr);
	//  std::cout << hdr << std::endl;

	TestForContentTypeHeader(currentmsg);

	TestForAcceptHeader(currentmsg);

	TestForAcceptEncodingHeader(currentmsg);
	TestForAcceptLanguageHeader(currentmsg);

	TestForAllowHeader(currentmsg);

	//  std::cout << "----- Header Test ------ Call-ID -------\n";
	//  RawData rd;
	//  currentmsg->GetHeaderValue((unsigned char*)"Call-ID", rd);
	//  std::cout << std::string((char*)rd._data, rd._length) << std::endl;
	//  std::cout << "------ After parsing ----------\n";
	//  CallIdHeader callid;
	//  callid.ParseHeader((const char*)rd._data, 0, rd._length);
	//  msgbuf.clear();
	//  msgbuf.str("");
	//  callid.PrintOut(msgbuf);
	//  std::cout << msgbuf.str() << std::endl;

	TestForCallIDHeader(currentmsg);

	//  std::cout << "----- Header Test ------ CSeq -------\n";
	//  currentmsg->GetHeaderValue((unsigned char*)"CSeq", rd);
	//  std::cout << std::string((char*)rd._data, rd._length) << std::endl;
	//  std::cout << "------ After parsing ----------\n";
	//  CSeqHeader cseq;
	//  cseq.ParseHeader((const char*)rd._data, 0, rd._length);
	//  msgbuf.clear();
	//  msgbuf.str("");
	//  cseq.PrintOut(msgbuf);
	//  std::cout << msgbuf.str() << std::endl;
	//  std::string cs = cseq.GetHeaderValue();
	//  std::cout << cs << std::endl;

	TestForCSeqHeader(currentmsg);

	TestForMaxForwardsHeader(currentmsg);

	std::cout << "Number of Via headers with long-form: " << currentmsg->GetHeaderCount((unsigned char*)"Via") << std::endl;
	std::cout << "Number of Via headers with short-form: " << currentmsg->GetHeaderCount((unsigned char*)"v") << std::endl;

	TestForViaHeader(currentmsg);

	TestForFromHeader(currentmsg);

	TestForToHeader(currentmsg);

	TestForSubjectHeader(currentmsg);

	TestForContactHeader(currentmsg);

	BodyTest(currentmsg);

	std::cout << "......... REQ URI ...............\n";
	RawData rd1;
	currentmsg->GetRequestUrl(rd1);
	if (rd1._data)
	{
		std::cout << std::string((const char*)rd1._data, rd1._length);

		SipUri uri;
		uri.ParseUri((const char*)rd1._data, 0, rd1._length);
	}

	std::cout << SipMessage::GetLongHeaderName('x') << std::endl;
	std::cout << SipMessage::GetLongHeaderName('l') << std::endl;

	std::cout << SipMessage::GetShortHeaderName("Referred-By") << std::endl;
	std::cout << SipMessage::GetShortHeaderName("Identity") << std::endl;

	/* GetHeaderValue variant tests based on To header */
	std::cout << "(1)Header value of To: " << currentmsg->GetHeaderValue((unsigned char*)"To") << std::endl;
	std::cout << "(2)Header value of To: " << currentmsg->GetHeaderValue((unsigned char*)"To", 2, 0) << std::endl;
	std::string value;
	currentmsg->GetHeaderValue((unsigned char*)"To", value);
	std::cout << "(3)Header value of To: " << value << std::endl;
	value = "";
	currentmsg->GetHeaderValue((unsigned char*)"to", 2, value);
	std::cout << "(4)Header value of To: " << value << std::endl;
	RawData rvalue;
	//std::string GetHeaderValue(sip_method method);
	/* provides the pointer to value part of the header in question. No any additional copy applied. */
	currentmsg->GetHeaderValue((unsigned char*)"to", rvalue);
	std::cout << "(5)Header value of To: " << std::string((const char*)rvalue._data, rvalue._length) << std::endl;
	rvalue._data = NULL;
	rvalue._length = 0;
	currentmsg->GetHeaderValue((unsigned char*)"To", 2, rvalue);
	std::cout << "(6)Header value of To: " << std::string((const char*)rvalue._data, rvalue._length) << std::endl;

	/* GetHeaderValue for 't' */
	std::cout << "(1s)Header value of To: " << currentmsg->GetHeaderValue((unsigned char*)"t") << std::endl;
	std::cout << "(2s)Header value of To: " << currentmsg->GetHeaderValue((unsigned char*)"T", 1, 0) << std::endl;
	//std::string value;
	value = "";
	currentmsg->GetHeaderValue((unsigned char*)"T", value);
	std::cout << "(3s)Header value of To: " << value << std::endl;
	value = "";
	currentmsg->GetHeaderValue((unsigned char*)"t", 1, value);
	std::cout << "(4s)Header value of To: " << value << std::endl;
	//RawData rvalue;
	rvalue._data = NULL;
	rvalue._length = 0;
	//std::string GetHeaderValue(sip_method method);
	/* provides the pointer to value part of the header in question. No any additional copy applied. */
	currentmsg->GetHeaderValue((unsigned char*)"t", rvalue);
	std::cout << "(5s)Header value of To: " << std::string((const char*)rvalue._data, rvalue._length) << std::endl;
	rvalue._data = NULL;
	rvalue._length = 0;
	currentmsg->GetHeaderValue((unsigned char*)"T", 1, rvalue);
	std::cout << "(6s)Header value of To: " << std::string((const char*)rvalue._data, rvalue._length) << std::endl;

	std::list<std::string> strlist;
	currentmsg->GetHeaderValuesInList((unsigned char*)"Via", strlist);
	std::cout << "Values for Via Header in size --> " << strlist.size() << std::endl;
	for (std::string s : strlist)
	{
		std::cout << s << std::endl;
	}

	return EXIT_SUCCESS;
}
