/*
*******************************************************************************
*
* Copyright (C) 2017-2019 by CT Skysoft Info&Tech Co., Ltd. All rights reserved.
*
*******************************************************************************
*/
/******************************************************************************
* File Name     : askey_locker.h
*
* Module        : encryption/decryption
*
* Description   : encryption/decryption library V1.0
*
*******************************************************************************
*/
/******************************************************************************
  EDIT HISTORY FOR MODULE

  Please notice that the changes are listed in reverse chronological order.

  when       who        what, where, why
  --------   ---        ------------------------------------------------------
  2018/11/23  suvine    Created module 
  2018/12/04  suvine    Add use openssl api (openssl version 1.0.2h)
  *****************************************************************************
*/
#ifndef _ASKEY_LOCKER_H_
#define _ASKEY_LOCKER_H_

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
Function Name:           askey_init
Input Parameters:        null
Output Parameters:       null
Return Code:             
Description:             Initialization
****************************************************************************/
void askey_init(void);

/****************************************************************************
Function Name:           askey_enc_cmd
Input Parameters:        a c_string that contains the private key (Content in attachment: key) 
Output Parameters:       a c_string that contains the encrypted private key (Content in attachment: key.enc)
Return Code:             
Description:             use cmd method
****************************************************************************/
char *askey_enc_cmd( char* Key);

/****************************************************************************
Function Name:           askey_enc_path
Input Parameters:        a c_string that contains the private key path;
                         a c_string that contains the encrypted private key path(key.enc)
Output Parameters:       
Return Code:             success:0 failed:-1
Description:             use cmd method
****************************************************************************/
int askey_enc_path( char* key_path, char* enc_key_path);

/****************************************************************************
Function Name:           askey_dec_cmd
Input Parameters:        a c_string that contains the encrypted private key,  encrypted password
Output Parameters:       a c_string that contains the private key
Return Code:             
Description:             use cmd method
****************************************************************************/
char *askey_dec_cmd( char* eKey, char* pwd);

/****************************************************************************
Function Name:           get_pwd
Input Parameters:        a int that enc month(1~12)
Output Parameters:       a password c_string
Return Code:             success:0 failed:-1
Description:             get password from month
****************************************************************************/
int get_pwd(int month, char *password);

/****************************************************************************
Function Name:           askey_enc
Input Parameters:        (in)need encryption string data;(pwd)key password;
Output Parameters:       (out)encryped data;(out_len)encryped data length
Return Code:             success:0 failed:-1
Description:             askey aes-256 encryp;
                         use openssl api (openssl version 1.0.2h)
****************************************************************************/
int askey_enc(char* in, char* pwd, char* out, int *out_len);

/****************************************************************************
Function Name:           askey_dec
Input Parameters:        (in)need decryption data;
                         (in_len)need decryption data length
                         (pwd)key password;
Output Parameters:       (out)decryped data
Return Code:             success:0 failed:-1
Description:             askey aes-256 decryp;
                         use openssl api (openssl version 1.0.2h)
****************************************************************************/
int askey_dec(char* in, int in_len, char* pwd, char* out);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif 
