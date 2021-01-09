SIP PARSER
==========
The project consists of another SIP protocol parser approach based on the approach used in a stateful HTTP parser 
http_parser.c (Although, the code shared in https://github.com/nodejs/http-parser is used, there some other points 
on the Web providing same code). 

Although the protocol context of SIP and HTTP are different, basically, message formats of SIP and HTTP are similar. 
Besides, their protocol contexts are different (i.e. method names, header names, URI format, etc.). 

Basic rules of referenced http-parser project are provided in sip-parser project as included below:

This is written in C. It parses both requests and responses. 
The parser is designed to be used in performance SIP applications. 
It does not make any syscalls nor allocations, it does not
buffer data, it can be interrupted at anytime. Depending on your
architecture, it only requires about 40 bytes of data per message
stream.

Features:

  * No dependencies
  * Defends against buffer overflow attacks.

The parser extracts the following information from SIP messages:

  * Header fields and values
  * Content-Length
  * Request method
  * Response status code
  * SIP version
  * Request URL
  * Message body
  
Not supported:
  * Detailed parsing of SIP request URL (in contrast to http-parser. This is a TODO)
  * Detailed parsing of header values
  * Parsing of SDP (Session Description Protocol) which is generally used in SIP body as an embedded protocol
  * Parsing multipart message bodies (TODO: support draft parsing to provide boundaries of multipart bodies)

Further, the approach implements "minimal/zero-copy" and "lazy header parsing" methods in order to improve parsing 
performance. In addition, the project consists of osipparser2 (https://directory.fsf.org/wiki/Osip) to be able to 
compare performance of the new approach.

The program is tested in Linux and Windows OSs. For Windows, project shall be open by clicking the file 
"solution/sip_parser.sln", which is currently created by Visual Studio 2019.
