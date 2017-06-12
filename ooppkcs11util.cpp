/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <cstdint>
#include <unistd.h>

#include "ooppkcs11util.h"

void
readFunctionName(std::string& result, int fd)
{
  uint8_t nameLength;
  read(fd, &nameLength, 1); // todo: check read
  char buf[256];
  read(fd, buf, nameLength); // todo: check read
  result.assign(buf, nameLength);
}

void
writeFunctionName(std::string& name, int fd)
{
  uint8_t nameLength = name.length(); // todo: assert < 256
  write(fd, &nameLength, 1); // todo: check write
  write(fd, name.data(), nameLength); // todo: check write
}

void
readData(std::string& result, int fd)
{
  uint16_t dataLength;
  read(fd, &dataLength, 2); // todo: check read
  result.clear();
  char buf[2048];
  uint16_t bytesRemaining = dataLength;
  while (bytesRemaining > 0) {
    uint16_t chunkLength = bytesRemaining > sizeof(buf)
                         ? sizeof(buf) : bytesRemaining;
    uint16_t bytesRead = read(fd, buf, chunkLength); // todo: check read
    result.append(buf, bytesRead);
    bytesRemaining -= bytesRead;
  }
}

void
writeData(std::string& data, int fd)
{
  uint16_t dataLength = data.length(); // todo: assert < 16k
  write(fd, &dataLength, 2); // todo: check write
  write(fd, data.data(), dataLength); // todo: check write
}
