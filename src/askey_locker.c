/*
*******************************************************************************
*
* Copyright (C) 2017-2019 by CT Skysoft Info&Tech Co., Ltd. All rights reserved.
*
*******************************************************************************
*/
/******************************************************************************
* File Name     : askey_locker.c
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
  *****************************************************************************
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/aes.h>    //openssl head
#include "askey_locker.h"
 
#define FREE(ptr) do{     \
          if( (ptr) != NULL ) {    \
		    free( (ptr) ); \
			(ptr) = NULL;  \
		  }                \
		}while(0)          \
		
typedef struct{
  char** str;
  int count;
  int boundary;  // when strings_init, the total number of malloc regions 
}Strings;

static int Popen(char *cmd, Strings *ret)
{
  FILE *fp;
  char output[10240];
  int limit = 100;   // this limit the number of lines to return 
                    // from the system call
  char *cmd_return[limit];
  Strings result;
  result.count = 0;
  strcat(cmd, " 2>&1"); // redirect stderr to stdout

  /* Open the command for reading. */
  fp = popen(cmd, "r");
  if (fp == NULL)
  {
	printf("Failed to run command: %s\n", cmd);
	exit(-1);
  }
  /* Read the output one line at a time - output it. 
   * and then save it to the cmd_return buffer     */
  while (fgets(output, sizeof(output)-1, fp) != NULL)
  {
    if ( result.count < limit )
    {
      int size = strlen(output);
	  cmd_return[result.count] = malloc(sizeof(char*) * (size+1) );
	  strcpy( cmd_return[result.count], output );
	  result.count++;
	}
    else
    {
	  printf("Return more than %d lines\n", limit);
      break;
    }
  }
  result.str = malloc(sizeof(char*) * (result.count));  
  result.boundary = result.count;

  int i;

  // copy cmd_return buffer to Strings result
  for( i = 0; i < result.count; i++)
  {
    result.str[i] = malloc(sizeof(char*) * (strlen(cmd_return[i])+1) );
    strcpy( result.str[i], cmd_return[i] );
    FREE( cmd_return[i] );
  }

  *ret = result;

  /* close */
  pclose(fp);
  return 1;
}

static void strings_remove(Strings strs)
{
  if (strs.str)
  {
      int i;
      for (i = 0; i < strs.count; i++)
	  {
          free(strs.str[i]);
	  }
      free(strs.str);
  }
}

static char pwd[12][20];

void askey_init(void)// init password
{
    int i;
    char mod[12][12] = {
    "aaron",
    "bihah",
    "candace",
    "diana",
    "esther",
    "frank",
    "greg",
    "huldah", 
    "israel",
    "julia",
    "king",
    "lois"
    };
    
    for(i = 0; i < 12; i++)
    {
        sprintf(pwd[i]  , "%s_%d_%s", mod[sizeof(mod)/sizeof(mod[0])-(i+1)], i+1, mod[i]);
    }
    //debug
    //for(i = 0; i < 12; i++)
    //    printf("pwd[%d]: %s\n", i+1, pwd[i]);
}

int get_pwd(int month, char *password)
{
    if ( month > 12 || month <= 0 || NULL == password )
    {
        printf(" Invalid argument !\n");
        return -1;
    }
    strcpy(password, pwd[month-1]);
    return 0;
}

char *askey_enc_cmd( char* Key)
{
    char cmd[10240] = {0};
    Strings result;
    int i;
    
	time_t theTime = time(NULL);
    struct tm *aTime = localtime(&theTime);
    int month = aTime->tm_mon;    

    if(NULL == Key)
        return NULL;
    
	sprintf(cmd, "echo \"%s\" | openssl enc -aes-256-cbc -a -k %s", Key, pwd[month]);
    //printf("cmd enc:\n%s\n",cmd);
	if( -1 != Popen(cmd, &result ))
	{
        //printf("result.count:%d\n",result.count);
        //printf("result.boundary:%d\n",result.boundary);
        if( result.count > 0 )
        {
            //printf("len:%d\n",sizeof(Key));
            //memset(Key, 0, sizeof(Key));
            *Key = '\0';
            for( i = 0; i < result.count; i++)
            {
                strcat(Key, result.str[i]);
            }
            strings_remove(result);
            return Key;
        }
    }
    else
        return NULL;

}

int askey_enc_path( char* key_path, char* enc_key_path)
{
    char cmd[1024] = {0};
    Strings result;
    int i;
    
	time_t theTime = time(NULL);
    struct tm *aTime = localtime(&theTime);
    int month = aTime->tm_mon;    

    if(NULL == key_path || NULL == enc_key_path)
        return -1;

	#ifdef WIN32
		sprintf(cmd, "type %s | openssl enc -aes-256-cbc -a -k %s > %s", key_path, pwd[month], enc_key_path);
	#else
		sprintf(cmd, "cat %s | openssl enc -aes-256-cbc -a -k %s > %s", key_path, pwd[month], enc_key_path);
	#endif    
    //printf("cmd enc:\n%s\n",cmd);
	if( -1 != Popen(cmd, &result ))
	{
        //printf("result.count:%d\n",result.count);
        //printf("result.boundary:%d\n",result.boundary);
        strings_remove(result);
    }
    else
        return -1;

    return 0;
}

char *askey_dec_cmd( char* eKey, char* pwd)
{
    char cmd[10240] = {0};
    Strings result;
    int i;
    
    if( NULL == eKey || NULL == pwd)
        return NULL;
    
	sprintf(cmd, "echo \"%s\" | openssl enc -aes-256-cbc -a -d -k %s", eKey, pwd);
    //printf("cmd dec:\n%s\n",cmd);
	if( -1 != Popen(cmd, &result ))
	{
        //printf("1result.count:%d\n",result.count);
        //printf("1result.boundary:%d\n",result.boundary);
        if( result.count > 0 )
        {
            //memset(eKey, 0, sizeof(*eKey));
            *eKey = '\0';
            for( i = 0; i < result.count; i++)
            {
                strcat(eKey, result.str[i]);
            }
            strings_remove(result);
            return eKey;
        }
    }
    else
        return NULL;
}

int askey_enc(char* in, char* pwd, char* out, int *out_len)
{
    if(!in || !pwd || !out)
    {
        printf("Invalid parameters\n");
        return -1;
    }
    
    int i, len = 0;
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];
    
    for(i = 0; i < AES_BLOCK_SIZE; ++i)
        iv[i]=0;
    // Set encryption key 256bit
    if(AES_set_encrypt_key((unsigned char*)pwd, 256, &aes) < 0)
    {
        printf("AES_set_encrypt_key error\n");
        return -1;
    }
    len = strlen(in);//enc string length
    if (len % AES_BLOCK_SIZE == 0) {  
        *out_len = len;  
    } else {  
        *out_len = (len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;  
    }
    
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);
    return 0;
}

int askey_dec(char* in, int in_len, char* pwd, char* out)
{
    if(!in || !pwd || !out) 
    {
        printf("Invalid parameters\n");
        return -1;
    }
    
    int i;
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];

    for(i=0; i<AES_BLOCK_SIZE; ++i)//the same value as encryption
        iv[i]=0;
    // Set decryption key 256bit
    if(AES_set_decrypt_key((unsigned char*)pwd, 256, &aes) < 0)
    {
        printf("AES_set_decrypt_key error\n");
        return -1;
    }
    AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, in_len, &aes, iv, AES_DECRYPT);
    return 0;
}

