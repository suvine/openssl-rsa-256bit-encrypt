#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "askey_locker.h"


#define ENC_FILE_NAME "key.enc"

void print_usage()
{
	printf("Usage: EXEC enc FILE_PATH\n");
	printf("       EXEC dec FILE_PATH\n");
	exit(-1);
}

static void* get_file_content(char *filename)
{
    if (!filename)
    {
        printf("filename is null \n", filename);
        return NULL;        
    }

    char* text;
    FILE *pf = fopen(filename, "rb");
    if (NULL == pf)
    {
        printf("fopen %s error \n", filename);
        return NULL;
    }
    fseek(pf, 0L, SEEK_END);
    long lSize = ftell(pf);
    //free after use
    text=(char*)malloc(lSize+1);
    rewind(pf);
    fread(text, sizeof(char), lSize, pf);
    text[lSize] = '\0';
    fclose(pf);
    return text;
}

static int set_file_content(char *filename, char *text, int len)
{
    FILE *fp;

    if (NULL == filename || NULL == text)
        return -1;
    
    fp = fopen(filename, "wb");
    if(fp == NULL)
    {
        printf("fopen %s Error!", filename);
        return -1;
    }
    fwrite(text,len,1,fp);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    char *key = NULL;
    char text[2048] = {0};
    char text_en[2048] = {0};
    char text_dc[2048] = {0};
    int out_len = 0;

	if( argc != 3 ) print_usage();

	printf("=== Askey private key protection tool === \n");

    askey_init();
	time_t theTime = time(NULL);
    struct tm *aTime = localtime(&theTime);
    int month = aTime->tm_mon;
    
	if( !strcmp(argv[1], "enc") ){
        key = get_file_content(argv[2]);
        strcpy(text, key);
        free(key);
        key = NULL;
        char pwd[32] = {0};
        
        if(get_pwd(month,pwd))
        {
            printf("get_pwd error\n");
            exit(-1);
        }
        //printf("need encryp string:\n%s\nlen:%d\npwd:%s\n",text,strlen(text),pwd);
        if(askey_enc(text, pwd, text_en, &out_len))
        {
            printf("askey_enc error\n");
            exit(-1);
        }    
        //write to file
        if(set_file_content(ENC_FILE_NAME, text_en, out_len))
        {
            printf("set_file_content error\n");
            exit(-1);
        }    
	}else if(!strcmp(argv[1], "dec")){
		char pwd[64];
		printf("Please enter password: ");
		scanf("%s", pwd);
        int count = 0;
        FILE *fd = fopen (argv[2], "rb");
        if( NULL == fd)
        {
            printf("fopen %s error\n",argv[2]);
            exit(-1);
        }    
        fseek(fd,0L,SEEK_END);  
        int size = ftell(fd);    
        rewind(fd);;    
        fread (text, sizeof (char), size, fd);
        fclose(fd);
        if(askey_dec(text,size,pwd,text_dc))
        {
            printf("askey_dec error\n");
            exit(-1);
        }    
        printf("dec key:\n%s",text_dc);
	}else
		print_usage();    
	printf("=== Complete === \n");
	return 0;    
}

