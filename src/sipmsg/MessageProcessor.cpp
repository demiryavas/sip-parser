#include "sipparser.h"
#include "SipMessage.h"

#include "MessageProcessor.h"

#include <iostream>
#include <sstream>

/* Message handler callback is to be invoked when a complete message received during parsing */
void HandleReceivedMessage(SipMessage* msg, void* owner)
{
	/* As tester behavior, save the received message into the list */
	//sipMsgList.push_back(msg);
	std::cout << "\n............................. <HANDLE RECEIVED MESSAGE> ......................\n";
	std::cout << "HandleReceivedMessge: Received a new message." /* << " Message count in list : "
						<< sipMsgList.size()*/ << std::endl;
	std::ostringstream buff;
	msg->PrintOut(buff);
	std::cout << buff.str() << std::endl;

	MessageProcessor* msgproc = reinterpret_cast<MessageProcessor*>(owner);
	if ((msgproc) && (msgproc->callback))
	{
		std::cout << "HandleReceivedMessge: Calling callback\n";
		msgproc->callback(msg);
	}
  std::cout << "\n............................. >HANDLE RECEIVED MESSAGE< ......................\n";

}


int on_message_begin(sip_parser* p) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* Message BEGIN ******************\n";
	buff << "Method: " << p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;
	sipmsg->message_begin_cb_called = 1;
	/* when parsing data consists of two messages, 'bias' determines the actual position */
	sipmsg->message_begin_pos = (*p->position) - p->parsing_data + sipmsg->bias;

#ifdef SIP_DETAILED_DEBUG
	std::cout << "Message begin POS: " << sipmsg->message_begin_pos << std::endl;
#endif

	sipmsg->type = (sip_parser_type)p->type;
#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif

	return 0;
}

int on_url(sip_parser* p, const char* at, size_t length) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* REQUEST URL ******************\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << (uint32_t)p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
	buff << "Received chars\n";

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;

	for (size_t i = 0; i < length; i++)
	{
		buff << at[i];
	}
	buff << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;
	/* keep current-parse position same with parser's position */
	if (sipmsg->request_url.start == 0)
	{
		sipmsg->request_url.start = (at - p->parsing_data) + sipmsg->bias;
	}
	sipmsg->request_url.length += length;

	/* Message is a request message and 'method' information shall be
	 * determined at this step
	 */
	sipmsg->method = (sip_method)p->method;
	sipmsg->type = SIP_REQUEST;

#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif
	return 0;
}

int on_response_status(sip_parser* p, const char* buf, size_t len)
{
#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* RESPONSE STATUS ******************\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
	std::cout << buff.str();
#endif
	SipMessage* sipmsg = (SipMessage*)p->currmsg;
	sipmsg->type = SIP_RESPONSE;
	/* keep current-parse position same with parser's position */
	if (sipmsg->response_status.start == 0)
	{
		sipmsg->response_status.start = (buf - p->parsing_data) + sipmsg->bias;
	}
	sipmsg->response_status.length += len;
	sipmsg->status_cb_called = 1;

#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif
	return 0;
}

int on_header_field(sip_parser* p, const char* at, size_t length) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* HEADER FIELD ******************\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
	buff << "Received chars\n";

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;

	for (size_t i = 0; i < length; i++)
	{
		//buff << (at[i] == ' ') ? (char)'.' : (char)at[i];
		if (at[i] == ' ')
			buff << '.';
		else
			buff << at[i];
	}
	buff << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;
	if (sipmsg->num_headers == 0)
	{
		/* first header encountered, which means also we have
		 * sip version info at parser
		 */
		sipmsg->sip_major = p->sip_major;
		sipmsg->sip_minor = p->sip_minor;
	}
	if (sipmsg->last_header_element != FIELD)
	{
		sipmsg->num_headers++;
	}
	header_pos_t* currpos = &sipmsg->headers[sipmsg->num_headers - 1];

	/* keep current-parse position same with parser's position */
	if (currpos->fieldpos.start == 0)
	{
		currpos->fieldpos.start = (at - p->parsing_data) + sipmsg->bias;
	}

	currpos->fieldpos.length += length;
#if SIP_PARSER_STRICT
	//currpos->fieldpos.length += length;
#else
	//currpos->fieldpos.length += length;

	/* we need to eliminate spaces between header-name and ":" */
	//while (*(at + currpos->fieldpos.length - 1) == ' ')
	while ((length > 0) && (*(at + length - 1) == ' '))
	{
		currpos->fieldpos.length--;
		length--;
	}
#endif

	sipmsg->last_header_element = FIELD;

#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif

	return 0;
}

int on_header_value(sip_parser* p, const char* at, size_t length) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* HEADER VALUE ******************\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
	buff << "Received chars\n";
#endif
	/* when the 'data' of parser is completed but message needs more data from
		 network for completion, the 'position' of parser may point out of the
		 data, so may need correction */
	unsigned char* corrPos = (unsigned char*)*p->position;
	if (corrPos >= (unsigned char*)(p->parsing_data + p->parsing_len))
	{
		corrPos--;
	}
#ifdef SIP_DETAILED_DEBUG
	buff << "Current position=" << std::hex << (uint64_t)*p->position
		<< " corrected position=" << std::hex << (uint64_t)corrPos << std::dec << std::endl;

	for (size_t i = 0; i < length; i++)
	{
		buff << at[i];
	}
	buff << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;

	/* keep current-parse position same with parser's position */
	bool possibleFolding = true;

	header_pos_t* currpos = &sipmsg->headers[sipmsg->num_headers - 1];

	if (currpos->valuepos.start == 0)
	{
		currpos->valuepos.start = (at - p->parsing_data) + sipmsg->bias;
		possibleFolding = false;
	}

	/* in the case of folding, parser skips spaces in the new line before providing
		 header value; so, we need to take it into account to keep data position in data space. */
	if (possibleFolding)
	{
		char* hstart = &sipmsg->v1[0];

		uint32_t tlength = (at - (hstart + currpos->valuepos.start + currpos->valuepos.length));
		currpos->valuepos.length += tlength;
	}
	currpos->valuepos.length += length;

	sipmsg->last_header_element = VALUE;

#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif

	return 0;
}

int on_headers_complete(sip_parser* p) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* HEADERS COMPLETE ******************\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;
	sipmsg->method = (sip_method)p->method;
	sipmsg->status_code = p->status_code;
	sipmsg->sip_major = p->sip_major;
	sipmsg->sip_minor = p->sip_minor;
	sipmsg->headers_complete_cb_called = 1 /*TRUE*/;

	/* keep current-parse position same with parser's position */
	sipmsg->headers_complete_pos = (*p->position - p->parsing_data) + sipmsg->bias;
	sipmsg->should_keep_alive = sip_should_keep_alive(p);

#ifdef SIP_DETAILED_DEBUG
	std::cout << "Headers complete POS: " << sipmsg->headers_complete_pos << std::endl;
	std::cout << "---------------------------------------------------------\n";
#endif

	return 0;
}

int on_message_complete(sip_parser* p) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* MESSAGE COMPLETE ******************\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;

	/* keep current-parse position same with parser's position */
	sipmsg->message_complete_cb_called = 1;
	sipmsg->message_complete_pos = (*p->position - p->parsing_data) + sipmsg->bias;

	/* Possibly we have a new mesage appended to this message. We need
		 re-initialize the parser for some points */
	p->type = SIP_BOTH;
	const char* new_data = (*p->position) + 1;
	if (new_data < p->parsing_data + p->parsing_len)
	{
		p->currmsg = new SipMessage();

		/* Set raw data  if remaining in the buffer */
		size_t tsize = (p->parsing_data + p->parsing_len) - new_data;
		((SipMessage*)p->currmsg)->v1.resize(tsize);
		memcpy(&((SipMessage*)p->currmsg)->v1[0], new_data, tsize);
		/* Bias will be negative value */
		((SipMessage*)p->currmsg)->bias = p->parsing_data - new_data;
	}
	else
	{
		p->currmsg = NULL;
	}

	/* call message-handler for a received complete SIP message */
	HandleReceivedMessage(sipmsg, p->data);

#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif

	return 0;
}

int on_body(sip_parser* p, const char* at, size_t length) {

#ifdef SIP_DETAILED_DEBUG
	std::ostringstream buff;
	buff << "************* ---- BODY ---- ******************\n";
	buff << "body_cb callback is called with settings:\n";
	buff << "Method: " << (uint32_t)p->method << std::endl;
	buff << "Type: " << (uint32_t)p->type << std::endl;
	buff << "Flags: " << (uint32_t)p->flags << std::endl;
	buff << "State: " << (uint32_t)p->state << std::endl;
	buff << "Header-state: " << (uint32_t)p->header_state << std::endl;
	buff << "Index: " << (uint32_t)p->index << std::endl;
	buff << "Nread: " << p->nread << std::endl;
	buff << "Content-Length: " << p->content_length << std::endl;
	buff << "Major version: " << (uint32_t)p->sip_major << std::endl;
	buff << "Minor version: " << (uint32_t)p->sip_minor << std::endl;
	buff << "Status-Code: " << (uint32_t)p->status_code << std::endl;
	buff << "ErrNo: " << (uint32_t)p->sip_errno << std::endl;
	buff << "Upgrade: " << (uint32_t)p->upgrade << std::endl;
	buff << "Received chars\n";

	buff << "Current position=" << std::hex << (uint64_t)*p->position << std::dec << std::endl;

	for (size_t i = 0; i < length; i++)
	{
		buff << at[i];
	}
	buff << std::endl;
	std::cout << buff.str();
#endif

	SipMessage* sipmsg = (SipMessage*)p->currmsg;

	if (sipmsg->msg_body.start == 0)
	{
		sipmsg->msg_body.start = (at - p->parsing_data) + sipmsg->bias;
	}
	sipmsg->msg_body.length += length;

	sipmsg->body_is_final = sip_body_is_final(p);

#ifdef SIP_DETAILED_DEBUG
	std::cout << "---------------------------------------------------------\n";
#endif

	return 0;
}


/* returns number of bystes processed */
int MessageProcessor::MessageReceived(unsigned char* msg, long msgsize)
{
	SipMessage* currmsg = NULL;
	uint32_t new_datapos = 0;

	if (msgsize <= 0)
	{
		return 0;
	}

	std::cout << "MessageReceived: Received message part with length " << msgsize << std::endl;
	printf("Message:\n %.*s \n", msgsize, msg);
	if (this->parser == NULL)
	{
		/* everything just starts */
		std::cout << "MessageReceived: Creating the parser...\n";
		this->parser = new sip_parser;
		//this->parser->data = NULL;
		this->parser->data = (void*)this;
		sip_parser_init(this->parser, SIP_BOTH);
		currmsg = new SipMessage();
		this->parser->currmsg = currmsg;
		new_datapos = 0;
	}
	else
	{
		/* probably we have just completed parsing of a message */
		if (this->parser->currmsg == NULL)
		{
			std::cout << "MessageReceived: Creating a new SipMessage instance in internal step...\n";
			currmsg = new SipMessage();
			this->parser->currmsg = currmsg;
			new_datapos = currmsg->v1.size();
		}
		else
		{
			/* continue with the existing (incomplete) message instance */
			std::cout << "MessageReceived: Continue with exiting SipMessage instance while collecting body...\n";
			currmsg = (SipMessage*)this->parser->currmsg;
			/* determine the new position as end of the current raw message block,
				 so that we will append it */
			new_datapos = currmsg->v1.size();
		}
	}
	size_t prevsize = currmsg->v1.size();
	currmsg->v1.resize(prevsize + msgsize);
	memcpy(&currmsg->v1[prevsize], msg, msgsize);

	int nparsed = 0;
	nparsed = sip_parser_execute(this->parser, &settings, &currmsg->v1[new_datapos], msgsize);
	if ((nparsed != msgsize) || (this->parser->sip_errno != SPE_OK))
	{
		std::cerr << "MessageReceived: Someting wrong with parsing, received msg-length="
			<< msgsize << " while " << nparsed << " of them is parsed!. Error-No:"
			<< this->parser->sip_errno << " - " << sip_errno_name((sip_errno)this->parser->sip_errno)
			<< " - " << sip_errno_description((sip_errno)this->parser->sip_errno) << "\n";
		this->parser->sip_errno = SPE_OK;
		delete this->parser->currmsg;
		this->parser->currmsg = NULL;
		return nparsed;
	}
	/* Success path. Collect un-reported part of data message, if there are */
	currmsg = (SipMessage*)this->parser->currmsg;

	if (currmsg)
	{
		currmsg->bias += msgsize;
	}
	std::cout << "MessageReceived: Processed of " << nparsed << " SIP message with length " << msgsize << std::endl;

	return nparsed;
}

void MessageProcessor::Initialize(void)
{
	memset(&this->settings, 0, sizeof(settings));
	this->settings.on_message_begin = on_message_begin;
	this->settings.on_url = on_url;
	this->settings.on_status = on_response_status;
	this->settings.on_header_field = on_header_field;
	this->settings.on_header_value = on_header_value;
	this->settings.on_headers_complete = on_headers_complete;
	this->settings.on_body = on_body;
	this->settings.on_message_complete = on_message_complete;
}
