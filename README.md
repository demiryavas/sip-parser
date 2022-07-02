SIP PARSER
==========
SIP parser including detailed header parsing

The project consists of another SIP protocol parser approach based on the approach used in a stateful HTTP parser http_parser.c (https://github.com/nodejs/http-parser). Further, the approach implements "minimal/zero-copy" and "lazy header parsing" methods in order to improve parsing performance. In addition, the project consists of osipparser2 (https://directory.fsf.org/wiki/Osip) to be able to compare performance of the new approach.

The program is written in C/C++ and tested with Windows OS only. Project shall be open by clicking the file "solution/sip_parser.sln", which is currently created by Visual Studio 2019. The "solution" consists of the following projects:

- api:         not a project but a directory consisting of headers of osip2 and osipparser2
- benchmark:   project used for benchmarking. Comment-out/in "#define OSIP_TEST" to test 
               for either osip or new-sip
- osip2:       osip project to obtain osip2.lib
- osipparser2: osipparser project to obtain osipparser2.lib
- osiptest:    derived project for "torture.c" of osip for individual parsing tests
- osipuritest: project to test osip's URI parsing performance
- sipmsg:      C++ code including SipMessage and header parsing implementations of new-sip 
               parsing approach
- sipparser:   new SIP parsing approach derived from http_parser.c and modified for SIP protocol
- siptest:     project to test new-sip parser
- sip_parser_test: to tests only sipparser.c directly

TODOs:
------
1) Header parsing implementation is not completed, i.e. not implemented for all known SIP headers. 
   There is need to complete these. To keep performance improvement of the approach, implementations 
   for header parsing shall follow stateful, "zero-copy" approach used in existing ones

2) Although "lazy header parsing" approach (i.e. parse headers when needed to extract header parameters) 
   is considered, for some headers (for example, for mandatory headers). header parsing may be 
   integrated with SIP message parsing

------
For further discussions and help please contact with e-mail address "demir.yavas@orioninc.com"
