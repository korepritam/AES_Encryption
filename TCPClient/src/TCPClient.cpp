//============================================================================
// Name        : TCPClient.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "AES_GCM_256_ENCRYPTION.h"

int getAESValuesFromServer(int serverSocket)
{
    unsigned char key_iv[AES_32_BYTES + EVP_MAX_IV_LENGTH];
    int key_iv_len = read(serverSocket, key_iv, AES_32_BYTES + EVP_MAX_IV_LENGTH);
    if (key_iv_len > 0)
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
    int ciphertext_len = aes.encryptMessage(reinterpret_cast<const unsigned char *>(message), strlen(message), ciphertext);

    if (ciphertext_len == -1)
    {
        cerr << "Encryption failed." << endl;
        return;
    }

    write(serverSocket, ciphertext, ciphertext_len);  //Send the ciphertext

}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port>" << std::endl;
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int serverPort = atoi(argv[2]);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    serverAddr.sin_addr.s_addr = inet_addr(serverIp);

    if (connect(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
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
    int response_len = read(serverSocket, server_response, sizeof(server_response));
    if (response_len > 0)
	{
    	server_response[response_len] = '\0';  // Null-terminate the response
		cout << "Server response: " << server_response << endl;
	}
	else
	{
		cerr << "Error receiving response from server." << endl;
	}

    close(serverSocket);

    return EXIT_SUCCESS;
}
