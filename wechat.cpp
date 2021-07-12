using namespace std;
#include <Windows.h>
#include <iostream>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#undef _UNICODE
#define SQLITE_FILE_HEADER "SQLite format 3" 
#define IV_SIZE 16
#define HMAC_SHA1_SIZE 20
#define KEY_SIZE 32

#define SL3SIGNLEN 20

#ifndef ANDROID_WECHAT
#define DEFAULT_PAGESIZE 4096       //4048数据 + 16IV + 20 HMAC + 12
#define DEFAULT_ITER 64000
#else
#define NO_USE_HMAC_SHA1
#define DEFAULT_PAGESIZE 1024
#define DEFAULT_ITER 4000
#endif
//pc端密码是经过OllyDbg得到的32位pass。

unsigned char pass[] = { 0x53,0xE9,0xBF,0xB2,0x3B,0x72,0x41,0x95,0xA2,0xBC,0x6E,0xB5,0xBF,0xEB,0x06,0x10,0xDC,0x21,0x64,0x75,0x6B,0x9B,0x42,0x79,0xBA,0x32,0x15,0x76,0x39,0xA4,0x0B,0xB1 };
char dbfilename[50];
int Decryptdb();
int CheckKey();
int CheckAESKey();
int main(int argc, char* argv[])
{
    if (argc >= 2)    //第二个参数argv[1]是文件名
        strcpy_s(dbfilename, argv[1]);  //复制    
           //没有提供文件名，则提示用户输入
    else {
        cout << "请输入文件名:" << endl;
        cin >> dbfilename;
    }
    Decryptdb();
    return 0;
}

int Decryptdb()
{
    FILE* fpdb;
    fopen_s(&fpdb, dbfilename, "rb+");
    if (!fpdb)
    {
        printf("打开文件错!");
        getchar();
        return 0;
    }
    fseek(fpdb, 0, SEEK_END);
    long nFileSize = ftell(fpdb);
    fseek(fpdb, 0, SEEK_SET);
    unsigned char* pDbBuffer = new unsigned char[nFileSize];
    fread(pDbBuffer, 1, nFileSize, fpdb);
    fclose(fpdb);

    unsigned char salt[16] = { 0 };
    memcpy(salt, pDbBuffer, 16);

#ifndef NO_USE_HMAC_SHA1
    unsigned char mac_salt[16] = { 0 };
    memcpy(mac_salt, salt, 16);
    for (int i = 0; i < sizeof(salt); i++)
    {
        mac_salt[i] ^= 0x3a;
    }
#endif

    int reserve = IV_SIZE;      //校验码长度,PC端每4096字节有48字节
#ifndef NO_USE_HMAC_SHA1
    reserve += HMAC_SHA1_SIZE;
#endif
    reserve = ((reserve % AES_BLOCK_SIZE) == 0) ? reserve : ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

    unsigned char key[KEY_SIZE] = { 0 };
    unsigned char mac_key[KEY_SIZE] = { 0 };

    OpenSSL_add_all_algorithms();
    PKCS5_PBKDF2_HMAC_SHA1((const char*)pass, sizeof(pass), salt, sizeof(salt), DEFAULT_ITER, sizeof(key), key);
#ifndef NO_USE_HMAC_SHA1
    PKCS5_PBKDF2_HMAC_SHA1((const char*)key, sizeof(key), mac_salt, sizeof(mac_salt), 2, sizeof(mac_key), mac_key);
#endif

    unsigned char* pTemp = pDbBuffer;
    unsigned char pDecryptPerPageBuffer[DEFAULT_PAGESIZE];
    int nPage = 1;
    int offset = 16;
    while (pTemp < pDbBuffer + nFileSize)
    {
        printf("解密数据页:%d/%d \n", nPage, nFileSize / DEFAULT_PAGESIZE);

#ifndef NO_USE_HMAC_SHA1
        unsigned char hash_mac[HMAC_SHA1_SIZE] = { 0 };
        unsigned int hash_len = 0;
        HMAC_CTX hctx;
        HMAC_CTX_init(&hctx);
        HMAC_Init_ex(&hctx, mac_key, sizeof(mac_key), EVP_sha1(), NULL);
        HMAC_Update(&hctx, pTemp + offset, DEFAULT_PAGESIZE - reserve - offset + IV_SIZE);
        HMAC_Update(&hctx, (const unsigned char*)& nPage, sizeof(nPage));
        HMAC_Final(&hctx, hash_mac, &hash_len);
        HMAC_CTX_cleanup(&hctx);
        if (0 != memcmp(hash_mac, pTemp + DEFAULT_PAGESIZE - reserve + IV_SIZE, sizeof(hash_mac)))
        {
            printf("\n 哈希值错误! \n");
            getchar();
            return 0;
        }
#endif
        //
        if (nPage == 1)
        {
            memcpy(pDecryptPerPageBuffer, SQLITE_FILE_HEADER, offset);
        }

        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ectx, EVP_get_cipherbyname("aes-256-cbc"), NULL, NULL, NULL, 0);
        EVP_CIPHER_CTX_set_padding(ectx, 0);
        EVP_CipherInit_ex(ectx, NULL, NULL, key, pTemp + (DEFAULT_PAGESIZE - reserve), 0);

        int nDecryptLen = 0;
        int nTotal = 0;
        EVP_CipherUpdate(ectx, pDecryptPerPageBuffer + offset, &nDecryptLen, pTemp + offset, DEFAULT_PAGESIZE - reserve - offset);
        nTotal = nDecryptLen;
        EVP_CipherFinal_ex(ectx, pDecryptPerPageBuffer + offset + nDecryptLen, &nDecryptLen);
        nTotal += nDecryptLen;
        EVP_CIPHER_CTX_free(ectx);

        memcpy(pDecryptPerPageBuffer + DEFAULT_PAGESIZE - reserve, pTemp + DEFAULT_PAGESIZE - reserve, reserve);
        char decFile[1024] = { 0 };
        sprintf_s(decFile, "dec_%s", dbfilename);
        FILE * fp;
        fopen_s(&fp, decFile, "ab+");
        {
            fwrite(pDecryptPerPageBuffer, 1, DEFAULT_PAGESIZE, fp);
            fclose(fp);
        }

        nPage++;
        offset = 0;
        pTemp += DEFAULT_PAGESIZE;
    }
    printf("\n 解密成功! \n");
    return 0;
}

