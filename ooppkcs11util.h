/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef _ooppkcs11util_h_
#define _ooppkcs11util_h_

#include <assert.h>
#include <iostream>
#include <string>

#include <pkcs11t.h>

void readFunctionName(std::string& result, int fd);
void writeFunctionName(std::string& name, int fd);

template<typename T>
void
write(T& val, int fd)
{
  ssize_t written = write(fd, &val, sizeof(T));
  assert(written == sizeof(T));
}

template<typename T>
void
read(T& val, int fd)
{
  ssize_t bytesRead = read(fd, &val, sizeof(T));
  assert(bytesRead == sizeof(T));
}

template<typename T>
void
writeArray(T* base, CK_ULONG ulCount, int fd)
{
  write<CK_ULONG>(ulCount, fd);
  if (ulCount > 0) {
    ssize_t written = write(fd, base, ulCount * sizeof(T));
    std::cerr << "writeArray thinks it wrote " << written << " bytes ";
    std::cerr << "(should have written " << ulCount << " bytes) ";
    std::cerr << "(T is " << sizeof(T) << " bytes)" << std::endl;
    assert(written == ulCount * sizeof(T));
  }
}

template<typename T>
void
readArray(T* base, CK_ULONG ulCount, int fd)
{
  CK_ULONG readCount;
  read<CK_ULONG>(readCount, fd);
  assert(readCount == ulCount);
  if (readCount > 0) {
    ssize_t bytesRead = read(fd, base, ulCount * sizeof(T));
    std::cerr << "readArray thinks it read " << bytesRead << " bytes ";
    std::cerr << "(should have read " << ulCount << " bytes) ";
    std::cerr << "(T is " << sizeof(T) << " bytes)" << std::endl;
    if (bytesRead == -1) {
      perror("read");
    }
    assert(bytesRead == ulCount * sizeof(T));
  }
}

#endif // _ooppkcs11util_h_
