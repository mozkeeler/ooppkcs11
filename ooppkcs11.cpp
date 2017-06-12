/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fcntl.h>
#include <iostream>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "nss.h"
#include "pkcs11.h"

#include "ooppkcs11util.h"

static bool sInitialized = false;
static pid_t sChildPID;
// read and write are from the parent's perspective
static int sReadPipe[2];
static int sWritePipe[2];

static bool sDebug = false;

CK_RV OOPPKCS11_C_Initialize(CK_VOID_PTR pInitArgs)
{
  std::cout << __func__ << std::endl;
  if (sInitialized) {
    return CKR_CRYPTOKI_ALREADY_INITIALIZED;
  }
  if (!pInitArgs) {
    return CKR_ARGUMENTS_BAD;
  }
  CK_C_INITIALIZE_ARGS_PTR args =
    static_cast<CK_C_INITIALIZE_ARGS_PTR>(pInitArgs);
  if (!args->LibraryParameters) {
    return CKR_ARGUMENTS_BAD;
  }
  // Perhaps due to some confusion, LibraryParameters is declared as a
  // CK_CHAR_PTR* (as in, a pointer to a pointer) when it is actually used as
  // a char* in NSS.
  const char* libraryPath =
    reinterpret_cast<const char*>(args->LibraryParameters);

  if (pipe(sReadPipe) != 0) {
    std::cerr << "pipe failed" << std::endl;
    return CKR_FUNCTION_FAILED;
  }
  if (pipe(sWritePipe) != 0) {
    std::cerr << "pipe failed" << std::endl;
    return CKR_FUNCTION_FAILED;
  }
  sChildPID = fork();
  if (sChildPID == -1) {
    return CKR_FUNCTION_FAILED;
  }
  if (sChildPID == 0) {
    if (dup2(sReadPipe[1], STDOUT_FILENO) == -1) {
      std::cerr << "dup2(sReadPipe, STDOUT_FILENO) failed" << std::endl;
      exit(1);
    }
    close(sReadPipe[0]);
    if (dup2(sWritePipe[0], STDIN_FILENO) == -1) {
      std::cerr << "dup2(sWritePipe, STDIN_FILENO) failed" << std::endl;
      exit(1);
    }
    close(sWritePipe[1]);
    if (sDebug) {
      char tmpl[64] = "/tmp/ooppkcs11.XXXXXX";
      int errFd = mkstemp(tmpl);
      if (errFd == -1) {
        std::cerr << "mkstemp(...) failed" << std::endl;
        exit(1);
      }
      if (dup2(errFd, STDERR_FILENO) == -1) {
        std::cerr << "dup2(errFd, STDERR_FILENO) failed" << std::endl;
        exit(1);
      }
      close(errFd);
    } else {
      int devNullFd = open("/dev/null", O_RDWR);
      if (dup2(devNullFd, STDERR_FILENO) == -1) {
        std::cerr << "dup2(devNullFd, STDERR_FILENO) failed" << std::endl;
        exit(1);
      }
      close(devNullFd);
    }
    if (execl("ooppkcs11child", "ooppkcs11child", libraryPath, nullptr) == -1) {
      std::cerr << "ooppkcs11child failed" << std::endl;
      abort();
    }
    exit(1);
  }

  close(sReadPipe[1]);
  close(sWritePipe[0]);

  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);

  sInitialized = true;
  return rv;
}

CK_RV OOPPKCS11_C_Finalize(CK_VOID_PTR)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_Finalize");
  writeFunctionName(functionName, sWritePipe[1]);

  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  int wstatus;
  waitpid(sChildPID, &wstatus, 0);
  return rv;
}

CK_RV OOPPKCS11_C_GetInfo(CK_INFO_PTR pInfo)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_GetInfo");
  writeFunctionName(functionName, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  if (rv == CKR_OK) {
    read<CK_INFO>(*pInfo, sReadPipe[0]);
  }
  return rv;
}

CK_RV OOPPKCS11_C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  std::cout << __func__ << std::endl;
  return C_GetFunctionList(ppFunctionList);
}

CK_RV OOPPKCS11_C_GetSlotList(CK_BBOOL limitToTokensPresent,
                              CK_SLOT_ID_PTR pSlotList,
                              CK_ULONG_PTR pulCount)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_GetSlotList");
  writeFunctionName(functionName, sWritePipe[1]);
  bool doit = pSlotList != nullptr;
  write<CK_BBOOL>(limitToTokensPresent, sWritePipe[1]);
  write<bool>(doit, sWritePipe[1]);
  CK_RV rv;
  if (doit) {
    write<CK_ULONG>(*pulCount, sWritePipe[1]);
    read<CK_RV>(rv, sReadPipe[0]);
    if (rv == CKR_OK) {
      readArray<CK_SLOT_ID>(pSlotList, *pulCount, sReadPipe[0]);
    }
  } else {
    read<CK_RV>(rv, sReadPipe[0]);
    if (rv == CKR_OK) {
      read<CK_ULONG>(*pulCount, sReadPipe[0]);
    }
  }
  return rv;
}

CK_RV OOPPKCS11_C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_GetSlotInfo");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SLOT_ID>(slotID, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  if (rv == CKR_OK) {
    read<CK_SLOT_INFO>(*pInfo, sReadPipe[0]);
  }
  return rv;
}

CK_RV OOPPKCS11_C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_GetTokenInfo");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SLOT_ID>(slotID, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  if (rv == CKR_OK) {
    read<CK_TOKEN_INFO>(*pInfo, sReadPipe[0]);
  }
  return rv;
}

CK_RV OOPPKCS11_C_GetMechanismList(CK_SLOT_ID slotID,
                                   CK_MECHANISM_TYPE_PTR pMechanismList,
                                   CK_ULONG_PTR pulCount)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_GetMechanismList");
  writeFunctionName(functionName, sWritePipe[1]);
  bool doit = pMechanismList != nullptr;
  write<CK_SLOT_ID>(slotID, sWritePipe[1]);
  write<bool>(doit, sWritePipe[1]);
  CK_RV rv;
  if (doit) {
    write<CK_ULONG>(*pulCount, sWritePipe[1]);
    read<CK_RV>(rv, sReadPipe[0]);
    if (rv == CKR_OK) {
      readArray<CK_MECHANISM_TYPE>(pMechanismList, *pulCount, sReadPipe[0]);
    }
  } else {
    read<CK_RV>(rv, sReadPipe[0]);
    if (rv == CKR_OK) {
      read<CK_ULONG>(*pulCount, sReadPipe[0]);
    }
  }
  return rv;
}

CK_RV OOPPKCS11_C_GetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE,
                                   CK_MECHANISM_INFO_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_OK;
}

CK_RV OOPPKCS11_C_InitToken(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG,
                            CK_UTF8CHAR_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_OK;
}

CK_RV OOPPKCS11_C_InitPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SetPIN(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG,
                         CK_UTF8CHAR_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR,
                              CK_NOTIFY, CK_SESSION_HANDLE_PTR phSession)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_OpenSession");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SLOT_ID>(slotID, sWritePipe[1]);
  write<CK_FLAGS>(flags, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  if (rv == CKR_OK) {
    read<CK_SESSION_HANDLE>(*phSession, sReadPipe[0]);
  }
  return rv;
}

CK_RV OOPPKCS11_C_CloseSession(CK_SESSION_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_OK;
}

CK_RV OOPPKCS11_C_CloseAllSessions(CK_SLOT_ID slotID)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_CloseAllSessions");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SLOT_ID>(slotID, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  return rv;
}

CK_RV OOPPKCS11_C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                 CK_SESSION_INFO_PTR pInfo)
{
  std::cout << __func__ << std::endl;
  return CKR_OK;
}

CK_RV OOPPKCS11_C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR,
                                    CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                    CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR,
                        CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Logout(CK_SESSION_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                          CK_OBJECT_HANDLE_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                             CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_GetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                    CK_ATTRIBUTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                                    CK_ATTRIBUTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_FindObjectsInit");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SESSION_HANDLE>(hSession, sWritePipe[1]);
  std::cerr << "ulCount: " << ulCount << std::endl;
  write<CK_ULONG>(ulCount, sWritePipe[1]);
  // Unfortunately since CK_ATTRIBUTE has a nested pointer, this isn't as
  // simple as copying an array.
  // typedef struct CK_ATTRIBUTE {
  //   CK_ATTRIBUTE_TYPE type;
  //   CK_VOID_PTR pValue;
  //   CK_ULONG ulValueLen;
  // } CK_ATTRIBUTE;
  for (CK_ULONG i = 0; i < ulCount; i++) {
    std::cerr << "pTemplate[i].type: " << pTemplate[i].type << std::endl;
    write<CK_ATTRIBUTE_TYPE>(pTemplate[i].type, sWritePipe[1]);
    std::cerr << "pTemplate[i].ulValueLen: " << pTemplate[i].ulValueLen << std::endl;
    write<CK_ULONG>(pTemplate[i].ulValueLen, sWritePipe[1]);
    writeArray<CK_BYTE>(reinterpret_cast<CK_BYTE_PTR>(pTemplate[i].pValue),
                        pTemplate[i].ulValueLen, sWritePipe[1]);
  }
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  return rv;
}

CK_RV OOPPKCS11_C_FindObjects(CK_SESSION_HANDLE hSession,
                              CK_OBJECT_HANDLE_PTR phObject,
                              CK_ULONG ulMaxObjectCount,
                              CK_ULONG_PTR pulObjectCount)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_FindObjects");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SESSION_HANDLE>(hSession, sWritePipe[1]);
  write<CK_ULONG>(ulMaxObjectCount, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  if (rv == CKR_OK) {
    read<CK_ULONG>(*pulObjectCount, sReadPipe[0]);
    readArray<CK_OBJECT_HANDLE>(phObject, *pulObjectCount, sReadPipe[0]);
  }
  return rv;
}

CK_RV OOPPKCS11_C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
  std::cout << __func__ << std::endl;

  std::string functionName("C_FindObjectsFinal");
  writeFunctionName(functionName, sWritePipe[1]);
  write<CK_SESSION_HANDLE>(hSession, sWritePipe[1]);
  CK_RV rv;
  read<CK_RV>(rv, sReadPipe[0]);
  return rv;
}

CK_RV OOPPKCS11_C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                              CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                          CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_EncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_EncryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                              CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                          CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DecryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DecryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DigestInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Digest(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DigestFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                           CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Sign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                       CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SignRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                  CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SignRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                              CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                             CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_Verify(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                         CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_VerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_VerifyFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_VerifyRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                    CK_OBJECT_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_VerifyRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DigestEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                      CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DecryptDigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                      CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SignEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                    CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DecryptVerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                      CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                              CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_GenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                             CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR,
                             CK_ULONG, CK_OBJECT_HANDLE_PTR,
                             CK_OBJECT_HANDLE_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                          CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                            CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG,
                            CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_DeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                            CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                            CK_OBJECT_HANDLE_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_SeedRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_GetFunctionStatus(CK_SESSION_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_CancelFunction(CK_SESSION_HANDLE)
{
  std::cout << __func__ << std::endl;
  return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV OOPPKCS11_C_WaitForSlotEvent(CK_FLAGS, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR)
{
  std::cout << __func__ << std::endl;
  return CKR_NO_EVENT;
}

static CK_FUNCTION_LIST FunctionList = {
  { 2, 2 },
  OOPPKCS11_C_Initialize,
  OOPPKCS11_C_Finalize,
  OOPPKCS11_C_GetInfo,
  OOPPKCS11_C_GetFunctionList,
  OOPPKCS11_C_GetSlotList,
  OOPPKCS11_C_GetSlotInfo,
  OOPPKCS11_C_GetTokenInfo,
  OOPPKCS11_C_GetMechanismList,
  OOPPKCS11_C_GetMechanismInfo,
  OOPPKCS11_C_InitToken,
  OOPPKCS11_C_InitPIN,
  OOPPKCS11_C_SetPIN,
  OOPPKCS11_C_OpenSession,
  OOPPKCS11_C_CloseSession,
  OOPPKCS11_C_CloseAllSessions,
  OOPPKCS11_C_GetSessionInfo,
  OOPPKCS11_C_GetOperationState,
  OOPPKCS11_C_SetOperationState,
  OOPPKCS11_C_Login,
  OOPPKCS11_C_Logout,
  OOPPKCS11_C_CreateObject,
  OOPPKCS11_C_CopyObject,
  OOPPKCS11_C_DestroyObject,
  OOPPKCS11_C_GetObjectSize,
  OOPPKCS11_C_GetAttributeValue,
  OOPPKCS11_C_SetAttributeValue,
  OOPPKCS11_C_FindObjectsInit,
  OOPPKCS11_C_FindObjects,
  OOPPKCS11_C_FindObjectsFinal,
  OOPPKCS11_C_EncryptInit,
  OOPPKCS11_C_Encrypt,
  OOPPKCS11_C_EncryptUpdate,
  OOPPKCS11_C_EncryptFinal,
  OOPPKCS11_C_DecryptInit,
  OOPPKCS11_C_Decrypt,
  OOPPKCS11_C_DecryptUpdate,
  OOPPKCS11_C_DecryptFinal,
  OOPPKCS11_C_DigestInit,
  OOPPKCS11_C_Digest,
  OOPPKCS11_C_DigestUpdate,
  OOPPKCS11_C_DigestKey,
  OOPPKCS11_C_DigestFinal,
  OOPPKCS11_C_SignInit,
  OOPPKCS11_C_Sign,
  OOPPKCS11_C_SignUpdate,
  OOPPKCS11_C_SignFinal,
  OOPPKCS11_C_SignRecoverInit,
  OOPPKCS11_C_SignRecover,
  OOPPKCS11_C_VerifyInit,
  OOPPKCS11_C_Verify,
  OOPPKCS11_C_VerifyUpdate,
  OOPPKCS11_C_VerifyFinal,
  OOPPKCS11_C_VerifyRecoverInit,
  OOPPKCS11_C_VerifyRecover,
  OOPPKCS11_C_DigestEncryptUpdate,
  OOPPKCS11_C_DecryptDigestUpdate,
  OOPPKCS11_C_SignEncryptUpdate,
  OOPPKCS11_C_DecryptVerifyUpdate,
  OOPPKCS11_C_GenerateKey,
  OOPPKCS11_C_GenerateKeyPair,
  OOPPKCS11_C_WrapKey,
  OOPPKCS11_C_UnwrapKey,
  OOPPKCS11_C_DeriveKey,
  OOPPKCS11_C_SeedRandom,
  OOPPKCS11_C_GenerateRandom,
  OOPPKCS11_C_GetFunctionStatus,
  OOPPKCS11_C_CancelFunction,
  OOPPKCS11_C_WaitForSlotEvent
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
  std::cout << __func__ << std::endl;
  *ppFunctionList = &FunctionList;
  return CKR_OK;
}
