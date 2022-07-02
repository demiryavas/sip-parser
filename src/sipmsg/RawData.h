/*
 * RawData.h
 *
 *  Created on: Apr 13, 2020
 *      Author: demir
 */

#ifndef RAWDATA_H_
#define RAWDATA_H_
//--------------------------------------------------------------------------
#include <string.h>     // memset

class RawData
{
public:
  RawData()
    : _data(NULL), _length(0), _pos(0)
  {}

  RawData(unsigned char* data, unsigned int length)
    : _data(data), _length(length), _pos(0)
  {}

  ~RawData()
  {
    if (_data != NULL)
    {
      /* TODO: To be activated when data relationship is clear 
      ::memset((void*)_data, 0, _length);
      delete[] _data; */
      _data = NULL;
      _length = 0;
      _pos = 0;
    }
  }

  //const unsigned char* _data;
  unsigned char* _data;
  unsigned int _length;
  unsigned int _pos;
};

//--------------------------------------------------------------------------
#endif /* RAWDATA_H_ */
