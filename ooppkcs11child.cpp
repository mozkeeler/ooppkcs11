/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>

#include "pkcs11.h"

#include "ooppkcs11util.h"

int
main(int argc, char* argv[])
{
  CK_RV rv;
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <PKCS#11 library path>" << std::endl;
    rv = CKR_FUNCTION_FAILED;
    write<CK_RV>(rv, STDOUT_FILENO);
    return 1;
  }

  void* lib = dlopen(argv[1], RTLD_NOW);
  if (!lib) {
    perror("dlopen");
    rv = CKR_FUNCTION_FAILED;
    write<CK_RV>(rv, STDOUT_FILENO);
    return 1;
  }

  CK_RV (*getFunctionList)(CK_FUNCTION_LIST_PTR_PTR) =
    (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(lib, "C_GetFunctionList");
  if (!getFunctionList) {
    perror("dlsym");
    rv = CKR_FUNCTION_FAILED;
    write<CK_RV>(rv, STDOUT_FILENO);
    return 1;
  }

  CK_FUNCTION_LIST_PTR functionListPtr;
  rv = getFunctionList(&functionListPtr);
  if (rv != CKR_OK) {
    std::cerr << "C_GetFunctionList failed" << std::endl;
    write<CK_RV>(rv, STDOUT_FILENO);
    return 1;
  }

  rv = functionListPtr->C_Initialize(nullptr);
  if (rv != CKR_OK) {
    std::cerr << "C_Initialize failed" << std::endl;
    write<CK_RV>(rv, STDOUT_FILENO);
    return 1;
  }

  rv = CKR_OK;
  write<CK_RV>(rv, STDOUT_FILENO);

  fd_set rfds;
  struct timeval tv;
  while (true) {
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    int retval = select(1, &rfds, nullptr, nullptr, &tv);
    if (retval == -1) {
      perror("select");
      break;
    }
    if (retval == 0) { // timed out - just loop.
      continue;
    }

    std::string functionName;
    readFunctionName(functionName, STDIN_FILENO);
    std::cerr << functionName << std::endl;
    if (functionName == "C_Finalize") {
      rv = functionListPtr->C_Finalize(nullptr);
      write<CK_RV>(rv, STDOUT_FILENO);
      break;
    } else if (functionName == "C_GetInfo") {
      CK_INFO info;
      memset(&info, 0, sizeof(info));
      rv = functionListPtr->C_GetInfo(&info);
      write<CK_RV>(rv, STDOUT_FILENO);
      if (rv == CKR_OK) {
        write<CK_INFO>(info, STDOUT_FILENO);
      }
    } else if (functionName == "C_GetSlotList") {
      CK_BBOOL limitToTokensPresent;
      read<CK_BBOOL>(limitToTokensPresent, STDIN_FILENO);
      bool doit;
      read<bool>(doit, STDIN_FILENO);
      if (doit) {
        CK_ULONG ulCount;
        read<CK_ULONG>(ulCount, STDIN_FILENO);
        std::unique_ptr<CK_SLOT_ID[]> pSlotList(new CK_SLOT_ID[ulCount]);
        rv = functionListPtr->C_GetSlotList(limitToTokensPresent,
                                            pSlotList.get(), &ulCount);
        write<CK_RV>(rv, STDOUT_FILENO);
        if (rv == CKR_OK) {
          writeArray<CK_SLOT_ID>(pSlotList.get(), ulCount, STDOUT_FILENO);
        }
      } else {
        CK_ULONG ulCount;
        rv = functionListPtr->C_GetSlotList(limitToTokensPresent, nullptr,
                                            &ulCount);
        write<CK_RV>(rv, STDOUT_FILENO);
        if (rv == CKR_OK) {
          write<CK_ULONG>(ulCount, STDOUT_FILENO);
        }
      }
    } else if (functionName == "C_GetSlotInfo") {
      CK_SLOT_ID slotID;
      read<CK_SLOT_ID>(slotID, STDIN_FILENO);
      CK_SLOT_INFO info;
      memset(&info, 0, sizeof(info));
      rv = functionListPtr->C_GetSlotInfo(slotID, &info);
      write<CK_RV>(rv, STDOUT_FILENO);
      if (rv == CKR_OK) {
        write<CK_SLOT_INFO>(info, STDOUT_FILENO);
      }
    } else if (functionName == "C_GetTokenInfo") {
      CK_SLOT_ID slotID;
      read<CK_SLOT_ID>(slotID, STDIN_FILENO);
      CK_TOKEN_INFO info;
      memset(&info, 0, sizeof(info));
      rv = functionListPtr->C_GetTokenInfo(slotID, &info);
      write<CK_RV>(rv, STDOUT_FILENO);
      if (rv == CKR_OK) {
        write<CK_TOKEN_INFO>(info, STDOUT_FILENO);
      }
    } else if (functionName == "C_GetMechanismList") {
      CK_SLOT_ID slotID;
      read<CK_SLOT_ID>(slotID, STDIN_FILENO);
      bool doit;
      read<bool>(doit, STDIN_FILENO);
      if (doit) {
        CK_ULONG ulCount;
        read<CK_ULONG>(ulCount, STDIN_FILENO);
        std::unique_ptr<CK_MECHANISM_TYPE[]> pMechanismList(
          new CK_MECHANISM_TYPE[ulCount]);
        rv = functionListPtr->C_GetMechanismList(slotID, pMechanismList.get(),
                                                 &ulCount);
        write<CK_RV>(rv, STDOUT_FILENO);
        if (rv == CKR_OK) {
          writeArray<CK_MECHANISM_TYPE>(pMechanismList.get(), ulCount,
                                        STDOUT_FILENO);
        }
      } else {
        CK_ULONG ulCount;
        rv = functionListPtr->C_GetMechanismList(slotID, nullptr, &ulCount);
        write<CK_RV>(rv, STDOUT_FILENO);
        if (rv == CKR_OK) {
          write<CK_ULONG>(ulCount, STDOUT_FILENO);
        }
      }
    } else if (functionName == "C_OpenSession") {
      CK_SLOT_ID slotID;
      read<CK_SLOT_ID>(slotID, STDIN_FILENO);
      CK_FLAGS flags;
      read<CK_FLAGS>(flags, STDIN_FILENO);
      CK_SESSION_HANDLE hSession;
      rv = functionListPtr->C_OpenSession(slotID, flags, nullptr, nullptr,
                                          &hSession);
      write<CK_RV>(rv, STDOUT_FILENO);
      if (rv == CKR_OK) {
        write<CK_SESSION_HANDLE>(hSession, STDOUT_FILENO);
      }
    } else if (functionName == "C_CloseAllSessions") {
      CK_SLOT_ID slotID;
      read<CK_SLOT_ID>(slotID, STDIN_FILENO);
      rv = functionListPtr->C_CloseAllSessions(slotID);
      write<CK_RV>(rv, STDOUT_FILENO);
    } else if (functionName == "C_FindObjectsInit") {
      CK_SESSION_HANDLE hSession;
      read<CK_SESSION_HANDLE>(hSession, STDIN_FILENO);
      CK_ULONG ulCount;
      read<CK_ULONG>(ulCount, STDIN_FILENO);
      std::cerr << "ulCount: " << ulCount << std::endl;
      std::unique_ptr<CK_ATTRIBUTE[]> pTemplate(new CK_ATTRIBUTE[ulCount]);
      // Unfortunately since CK_ATTRIBUTE has a nested pointer, this isn't as
      // simple as copying an array.
      // typedef struct CK_ATTRIBUTE {
      //   CK_ATTRIBUTE_TYPE type;
      //   CK_VOID_PTR pValue;
      //   CK_ULONG ulValueLen;
      // } CK_ATTRIBUTE;
      for (CK_ULONG i = 0; i < ulCount; i++) {
        read<CK_ATTRIBUTE_TYPE>(pTemplate.get()[i].type, STDIN_FILENO);
        std::cerr << "pTemplate.get()[i].type: " << pTemplate.get()[i].type << std::endl;
        read<CK_ULONG>(pTemplate.get()[i].ulValueLen, STDIN_FILENO);
        std::cerr << "pTemplate.get()[i].ulValueLen: " << pTemplate.get()[i].ulValueLen << std::endl;
        pTemplate.get()[i].pValue = new CK_BYTE[pTemplate.get()[i].ulValueLen];
        readArray<CK_BYTE>(
          reinterpret_cast<CK_BYTE_PTR>(pTemplate.get()[i].pValue),
          pTemplate.get()[i].ulValueLen, STDIN_FILENO);
      }
      rv = functionListPtr->C_FindObjectsInit(hSession, pTemplate.get(),
                                              ulCount);
      for (CK_ULONG i = 0; i < ulCount; i++) {
        delete[] reinterpret_cast<CK_BYTE_PTR>(pTemplate.get()[i].pValue);
      }
      write<CK_RV>(rv, STDOUT_FILENO);
    } else if (functionName == "C_FindObjects") {
      CK_SESSION_HANDLE hSession;
      read<CK_SESSION_HANDLE>(hSession, STDIN_FILENO);
      CK_ULONG ulMaxObjectCount;
      read<CK_ULONG>(ulMaxObjectCount, STDIN_FILENO);
      std::unique_ptr<CK_OBJECT_HANDLE[]> phObject(
        new CK_OBJECT_HANDLE[ulMaxObjectCount]);
      CK_ULONG ulObjectCount;
      rv = functionListPtr->C_FindObjects(hSession, phObject.get(),
                                          ulMaxObjectCount, &ulObjectCount);
      write<CK_RV>(rv, STDOUT_FILENO);
      if (rv == CKR_OK) {
        write<CK_ULONG>(ulObjectCount, STDOUT_FILENO);
        writeArray<CK_OBJECT_HANDLE>(phObject.get(), ulObjectCount,
                                     STDOUT_FILENO);
      }
    } else if (functionName == "C_FindObjectsFinal") {
      CK_SESSION_HANDLE hSession;
      read<CK_SESSION_HANDLE>(hSession, STDIN_FILENO);
      rv = functionListPtr->C_FindObjectsFinal(hSession);
      write<CK_RV>(rv, STDOUT_FILENO);
    } else {
      sleep(1); // for safety
    }
  }

  functionListPtr->C_Finalize(nullptr);
  dlclose(lib);

  return 0;
}
