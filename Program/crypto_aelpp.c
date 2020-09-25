/**
 * 16507915 - Agostinho Sanches de Araujo
 * 16023905 - Evandro Douglas Capovilla Junior
 * 16105744 - Lucas Tenani Felix Martins
 * 16124679 - Pedro Andrade Caccavaro
 * xxxxxxxx - Pedro
 */

#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main(){
	int ret, fd;
	char stringToSend[BUFFER_LENGTH], input[BUFFER_LENGTH - 10];
	char operation;
	printf("[+] Starting device crypto_aelpp...\n");
	fd = open("/dev/crypto_aelpp", O_RDWR);
	if (fd < 0){
		perror("[!] Failed to open the device...");
		return errno;
	}

	printf("[+] Options: (c)ipher (d)ecipher (h)ash\n[+] Select the operation: ");
	operation = getchar();
	switch(operation){
		case 'c':
			printf("[+] Input String: ");
			getchar();
			scanf("%[^\n]%*c", input);
			strcpy(stringToSend,"c ");
			strcat(stringToSend,input);
			break;
		case 'd':
			printf("[+] Input String: ");
			getchar();
			scanf("%[^\n]%*c", input);
			strcpy(stringToSend,"d ");
			strcat(stringToSend,input);
			break;
		case 'h':
			printf("[+] Input String: ");
			getchar();
			scanf("%[^\n]%*c", input);
			strcpy(stringToSend,"h ");
			strcat(stringToSend,input);
			break;
		default:
			printf("[!] Invalid operation\n");
			return 0;
	}
	ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
	if (ret < 0){
		perror("[!] Failed to write the message to the device.");
		return errno;
	}
	printf("[+] Press ENTER to receive your ciphertext...\n");
	getchar();

	ret = read(fd, receive, BUFFER_LENGTH);        // Read the response from the LKM
	if (ret < 0){
		perror("[!] Failed to read the message from the device.");
		return errno;
	}
	printf("[+] Ciphertext: %s\n", receive);
	printf("[-] End of the program\n");
	return 0;
}
