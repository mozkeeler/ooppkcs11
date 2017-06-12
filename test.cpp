/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>
#include <unistd.h>

#include "nss.h"
#include "prerror.h"
#include "secmod.h"

int main(int argc, char* argv[])
{
  if (NSS_InitReadWrite(".") != SECSuccess) {
    std::cout << "(test) NSS_Init failed: " << PR_ErrorToString(PR_GetError(), 0);
    std::cout << std::endl;
    return 1;
  }

  char buf[64];
  if (snprintf(buf, sizeof(buf), "%s",
               "/usr/lib64/nss/libnssckbi.so") >= sizeof(buf)) {
    std::cout << "(test) not enough buffer space?" << std::endl;
    return 1;
  }
  char pathBuf[2048];
  if (!getcwd(pathBuf, sizeof(pathBuf))) {
    std::cout << "(test) couldn't getcwd?" << std::endl;
    return 1;
  }
  int unused;
  SECMOD_DeleteModule("Some Module", &unused);

  // NB: this can fail
  snprintf(pathBuf + strlen(pathBuf), sizeof(pathBuf) - strlen(pathBuf),
           "/libooppkcs11.so");
  if (SECMOD_AddNewModuleEx("Some Module", pathBuf, 0, 0, buf, nullptr)
        != SECSuccess) {
    std::cout << "(test) SECMOD_AddNewModuleEx failed: ";
    std::cout << PR_ErrorToString(PR_GetError(), 0) << std::endl;
    return 1;
  }

  if (NSS_Shutdown() != SECSuccess) {
    std::cout << "NSS_Shutdown failed: " << PR_ErrorToString(PR_GetError(), 0);
    std::cout << std::endl;
    return 1;
  }
  return 0;
}
