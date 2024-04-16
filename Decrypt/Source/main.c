#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "ida.h"

//按位异或运算
void xor_bytes(const unsigned char *input1, const unsigned char *input2, unsigned char *output) {
    for (size_t i = 0; i < 8; ++i) {
        output[i] = input1[i] ^ input2[i];
    }
}

void printArray(const unsigned char *array,int input_len,const char* name){
    printf("%s",name);
    for(int i = 0; i < input_len; i++){
        printf("0x%02x ",array[i]);
    }
    printf("\n");
}

// RTX_TEA加密
void rtxTeaEncrypt(unsigned char *data,unsigned char *key,unsigned char *out)
{
    int i;
    unsigned int y=0,z=0,a,b,c,d;
    int  e = 0;
    // todo   delta = (0 - sum * 轮数 ) &0xFFFFFFFF  0xE3779B90
    unsigned int sum = 0x61C88647;

    //设置y和z
    y =  ntohl(*(DWORD*)data);
    z =  ntohl(*(DWORD*)(data+4));
    //变形key设置a,b,c,d值
    a = ntohl(*(DWORD*)(key+0));
    b = ntohl(*(DWORD*)(key+4));
    c = ntohl(*(DWORD*)(key+8));
    d = ntohl(*(DWORD*)(key+12));

    //Decrypt
    for(i=0; i<16; i++)
    {
        e -= sum;
        y += (e+z) ^ (a+(z<<4)) ^ (b+(z>>5));
        z += (e+y) ^ (c+(y<<4)) ^ (d+(y>>5));
    }

    //output y
    *(DWORD*)out =  ntohl(y);
    //output z
    *(DWORD*)(out+4) = ntohl(z);
    return;
}

// RTX_TEA解密
void rtxTeaDecrypt(unsigned char *data,unsigned char *key,unsigned char *out)
{

  unsigned int y=0,z=0,a,b,c,d;
  int  e = 0;
  // todo   delta = (0 - sum * 轮数 ) &0xFFFFFFFF  0xE3779B90
  unsigned int sum = 0x61C88647;
  unsigned delta = 0xE3779B90;

  //设置y和z
  y =  ntohl(*(DWORD*)data);
  z =  ntohl(*(DWORD*)(data+4));



  //变形key设置a,b,c,d值
  a = ntohl(*(DWORD*)(key));
  b = ntohl(*(DWORD*)(key+4));
  c = ntohl(*(DWORD*)(key+8));
  d = ntohl(*(DWORD*)(key+12));


  // printf("y:%08x\n",y);
  // printf("z:%08x\n",z);
  // printf("a:%08x\n",a);
  // printf("b:%08x\n",b);
  // printf("c:%08x\n",c);
  // printf("d:%08x\n",d);


  //Decrypt
  for(int i=0; i<16; i++)
  {
    z -= (delta+y) ^ (c+(y<<4)) ^ (d+(y>>5));
    e = (delta+z) ^ (a+(z<<4)) ^ (b+(z>>5));
    delta += sum;
    y -= e;
  }


  //output y
  *(DWORD*)out =  ntohl(y);
  //output z
  *(DWORD*)(out+4) = ntohl(z);
  return;
}

// 每8字节分割数据传入RTX_TEA解密
int DecryptData(unsigned char *key,unsigned char *inputData, int inputData_len,unsigned char *out){
  if(inputData_len %8 != 0){
    return -1;
  }

  // 每8字节进行切分并分析
  unsigned char cipher_Data_Part[8] = {0};
  unsigned char rtxTea_Data_Part[8] = {0};
  unsigned char rtxTea_out[8]={0};
  unsigned char out_part[8]={0};
  int count = inputData_len / 8;

  int out_len = 0;
  unsigned char iV_1[8] = {0};
  unsigned char iV_2[8] = {0};
  for(int i = 0; i <count;i++){
    for(int j = 0; j<8;j++){
      cipher_Data_Part[j] = inputData[j+i*8];
    }

    xor_bytes(cipher_Data_Part,iV_1,rtxTea_Data_Part);

    rtxTeaDecrypt(rtxTea_Data_Part,key,rtxTea_out);

    memcpy(iV_1, rtxTea_out, sizeof(rtxTea_out));

    xor_bytes(rtxTea_out,iV_2,out_part);

    memcpy(iV_2, cipher_Data_Part, sizeof(cipher_Data_Part));


    for(int k = 0; k<8;k++){
      out[k + i*8] = out_part[k];
    }
    out_len = out_len + 8;

    // TODO TEST
    // printArray(cipher_Data_Part,8,"密文输入: ");
    // printArray(rtxTea_Data_Part,8,"rtxTeaDecrypt输入: ");
    // printArray(rtxTea_out,8,"rtxTeaDecrypt输出: ");
  }
  return out_len;
}



int main() {
    // FIXME RTX_TEA加密
    // unsigned char data1[8] = { 0xBC,0xC3,0xDF,0x43,0x56,0xF1,0xB4,0x1F};
    // unsigned char key1[16] = {0x52,0x00,0x54,0x00,0x58,0x00,0x21,0x00,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    // unsigned char out1[]={};
    // rtxTeaEncrypt(data1, key1, out1);

    // printf("rtxTeaEncrypt输出: ");
    // for(int i = 0; i < 8; i++){
    //     printf("0x%02x ",out1[i]);
    // }
    // printf("\n");


    // FIXME RTX_TEA解密
    // unsigned char data2[8] = {0x69, 0x8c, 0x46, 0xf6, 0xcc, 0x9f, 0x60, 0xe6};
    // unsigned char out2[]={};
    // rtxTeaDecrypt(data2,key1,out2);
    // printf("rtxTeaDecrypt输出: ");
    // for(int i = 0; i < 8; i++){
    //     printf("0x%02x ",out2[i]);
    // }
    // printf("\n");



  // NOTE RTX_TEA解密

    // 密钥
    unsigned char key[16] = {0x52,0x00,0x54,0x00,0x58,0x00,0x21,0x00,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    // 明文，输出
    // 注意:此变量大小根据报文长度自定义
    unsigned char out[20480]={0};
    // 密文，输入
    unsigned char cipherText[] = {
      0x95,0x8D,0x23,0x06,0x89,0xBB,0x15,0xDA,0xC2,0x6B,0x0E,0xFF,0xE7,0x0F,0x6D,0x23,
      0x88,0x26,0x91,0x1F,0x58,0x68,0xBE,0xF0,0x3E,0x24,0x52,0xBB,0x53,0xF0,0x89,0x8D,
      0xB3,0xBE,0xE2,0xAC,0xC1,0x81,0xBA,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      0xB3,0xBE,0xE2,0xAC,0xC1,0x81,0xBA,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    // 密文长度
    int cipherText_len = sizeof(cipherText);

    // 解密
    int outlen = DecryptData(key,cipherText,cipherText_len,out);

    if(outlen == -1){
      printf("输入数据长度不正确,应为8的倍数!\n");
      return -1;
    }

    printf("DecryptData输出: \n");
    for(int i = 0; i < outlen; i++){
        if((i!=0) && (i%16==0)){
          printf("\n");
        }
        printf("0x%02x ",out[i]);
    }
    printf("\n");

    return 0;
}
