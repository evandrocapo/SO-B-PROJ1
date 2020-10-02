/**
 * @file   testecryptodev.c
 * @brief  A Linux user space program that communicates with the cryptodev.c LKM. It passes a
 * string to the LKM and reads the response from the LKM. For this example to work the device
 * must be called /dev/crypto.
*/
#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
#define REC_BUFFER_LENGTH 800
#define NBR_ARGUMENTS 3

static char receive[REC_BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main(int argc, char *argv[]) {

   int ret, fd;
   char stringToSend[BUFFER_LENGTH];

   if(argc < NBR_ARGUMENTS)
      printf("Nao ha argumentos o suficiente para continuar a execucao. \n");

   printf("Iniciando o programa de teste...\n");

   fd = open("/dev/crypto", O_RDWR);             // Open the device with read/write access

   if (fd < 0){
      perror("Nao foi possivel abrir o dispositivo...");
      return errno;
   }

   stringToSend[0] = argv[1][0];
   strcat(stringToSend, argv[2]);

   printf("StringToSend = %s \n",stringToSend);

   printf("Enviando a requisicao ao dispositivo [%s].\n", stringToSend);

   ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM

   if (ret < 0){
      perror("Falha ao enviar a mensagem ao dispositivo.");
      return errno;
   }

   printf("Pressione ENTER para ver a resposta do dispositivo...\n");
   getchar();

   printf("Lendo do dispositivo...\n");
   ret = read(fd, receive, REC_BUFFER_LENGTH);        // Read the response from the LKM

   if (ret < 0){
      perror("Falha ao ler a mensagem do dispositivo.");
      return errno;
   }

   printf("Mensagem lida:\n");
   printf("%s\n", receive);
   printf("The end.\n");

   return 0;
}
