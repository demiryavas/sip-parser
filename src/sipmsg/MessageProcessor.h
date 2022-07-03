
/*
 * MessageProcessor.h
 *
 *  Created on: May 1, 2022
 *      Author: demir
 */
#ifndef _MESSAGE_PROCESSOR_H_
#define _MESSAGE_PROCESSOR_H_
 //---------------------------------------------------------------------------------------

#include "sipparser.h"
#include "SipMessage.h"

/** It is purposed for SIP message processing for both directions, receiving and sending.
    On receiving directions it accepts a byte-stream, possible received from network and
    invokes sip-parser to obtain SipMessage instance(s). A node or a connection may have
    one instance of MessageProcessor to handle all messaging through a connection or relation.
    This might be important especially in the case of connection is provided through TCP,
    because of streamed message structure.

    For sending direction it provides an interface for building a SipMessage instance based
    on provided summarized/predefined and dynamic data
 */

/* Note that there will be a little bit complex mechanism to handle error
   cases too. Keep simple at the moment to report complete messages. */
typedef int (*msgproc_cb) (SipMessage*);

class MessageProcessor
{
public:
  MessageProcessor()
    : parser(NULL), settings(), current_message(NULL), callback(NULL)
  {
    Initialize();
  }

  MessageProcessor(msgproc_cb cb)
    : parser(NULL), settings(), current_message(NULL), callback(cb)
  {
    Initialize();
  }

  ~MessageProcessor() {}

  void Initialize(void);

  int MessageReceived(unsigned char* msg, long msgsize);

//private:
  sip_parser* parser;

  sip_parser_settings settings;

  /* To be used to save the last obtained SipMessage instance to report (or return) upper layer.
     This approach will be modified later to use an event-driven mechanism. */
  SipMessage* current_message;

  msgproc_cb callback;
};
//---------------------------------------------------------------------------------------
#endif // _MESSAGE_PROCESSOR_H_
