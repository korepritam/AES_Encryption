//============================================================================
// Name        : TCPClient.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "AES_GCM_256_ENCRYPTION.h"

timespec LATENCY_PROFILE[6];

int getAESValuesFromServer(int serverSocket)
{
    unsigned char key_iv[AES_32_BYTES + EVP_MAX_IV_LENGTH];

    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[0]);
    int key_iv_len = read(serverSocket, key_iv, AES_32_BYTES + EVP_MAX_IV_LENGTH);
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[1]);

    if(key_iv_len > 0)
    {
        char key[AES_32_BYTES]; char iv[EVP_MAX_IV_LENGTH];
        memcpy(key, key_iv, AES_32_BYTES);
        memcpy(iv, key_iv+AES_32_BYTES, EVP_MAX_IV_LENGTH);

        AES_GCM_256_ENCRYPTION::getInstance(key,iv);

        return EXIT_SUCCESS;
    }
    else
    {
        cerr << "Error receiving (Cryptographic Key/iv) response from server." << endl;
        return EXIT_FAILURE;
    }
}

void encryptAndSendMessage(int serverSocket, const char *message)
{
	AES_GCM_256_ENCRYPTION &aes = AES_GCM_256_ENCRYPTION::getInstance();
    unsigned char ciphertext[MSG_LEN];

    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[2]);
    int ciphertext_len = aes.encryptMessage(reinterpret_cast<const unsigned char *>(message), strlen(message), ciphertext);
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[3]);

    if(ciphertext_len == -1)
    {
        cerr << "Encryption failed." << endl;
        return;
    }
    write(serverSocket, ciphertext, ciphertext_len);  //Send the ciphertext
}

int decryptAndReceiveMessage(unsigned const char* encrypted_server_response, int encrypted_server_response_len)
{
    unsigned char decrypted[1024];
    AES_GCM_256_ENCRYPTION &aes = AES_GCM_256_ENCRYPTION::getInstance();

    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[4]);
    int decrypted_len = aes.decryptMessage(encrypted_server_response, encrypted_server_response_len, decrypted);
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[5]);

    if(decrypted_len == -1) {
    	perror("Unable to decrypt server packet.");
    	return EXIT_FAILURE;
    }
    else {
		decrypted[decrypted_len] = '\0';
		cout << "Decrypted message from client: " << decrypted << endl;
		return EXIT_SUCCESS;
    }

}

unsigned long get_latency(struct timespec& start, struct timespec& end)
{
    long seconds = end.tv_sec - start.tv_sec;
    long nanoseconds = end.tv_nsec - start.tv_nsec;

    if (nanoseconds < 0) {
        seconds--;
        nanoseconds += NANO_MULTIPLIER;
    }

    return (seconds * NANO_MULTIPLIER) + nanoseconds;
}

int main(int argc, char **argv)
{
	for(int i=0; i<6; i++) memset(&LATENCY_PROFILE[i], 0, sizeof(timespec));

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>" << std::endl;
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int serverPort = atoi(argv[2]);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);

    if(connect(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
        perror("Connection to server failed");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    cout << "Connected to server at " << serverIp << ":" << serverPort << endl;

    if(getAESValuesFromServer(serverSocket) == EXIT_FAILURE) {
    	perror("Unable to get Cryptographic Key and IV");
    	close(serverSocket);
    	return EXIT_FAILURE;
    }

    const char *message = "Hello, this is an encrypted message!";
    cout << "Client message: " << message << endl;
    encryptAndSendMessage(serverSocket, message);
    unsigned char server_response[MSG_LEN];
    int server_response_len = read(serverSocket, server_response, sizeof(server_response));
    if (server_response_len > 0) {
    	decryptAndReceiveMessage(server_response, server_response_len);
	}
	else {
		cerr << "Error receiving response from server." << endl;
	}

    close(serverSocket);

    cout << "Client Latency Profile =>" << endl;
    cout << "TCP receive [" << get_latency(LATENCY_PROFILE[0],LATENCY_PROFILE[1]) << "]" << endl;
    cout << "Encrypt Message [" << get_latency(LATENCY_PROFILE[2],LATENCY_PROFILE[3]) << "]" << endl;
    cout << "Decrypt Message [" << get_latency(LATENCY_PROFILE[4],LATENCY_PROFILE[5]) << "]" << endl;


    return EXIT_SUCCESS;
}
