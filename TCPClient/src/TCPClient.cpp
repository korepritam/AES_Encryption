//============================================================================
// Name        : TCPClient.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "AES_GCM_256_ENCRYPTION.h"

void handleServer(int clientSocket)
{
    const char* clientMsg = "Hello from Client";
    write(clientSocket, clientMsg, strlen(clientMsg));

    unsigned char buffer[1024];
    int len = read(clientSocket, buffer, sizeof(buffer));
    if (len > 0) {
        buffer[len] = '\0';
        std::cout << "Server response: " << buffer << std::endl;
    }

    close(clientSocket);
}

void encryptAndSendMessage(int serverSocket, const char *message, const char *key)
{
	AES_GCM_256_ENCRYPTION &aes = AES_GCM_256_ENCRYPTION::getInstance();
    unsigned char ciphertext[MSG_LEN];
    int ciphertext_len = aes.encryptMessage(reinterpret_cast<const unsigned char *>(message), strlen(message), ciphertext);

    if (ciphertext_len == -1)
    {
        cerr << "Encryption failed." << endl;
        return;
    }

//    write(serverSocket, iv, EVP_MAX_IV_LENGTH);  //Send the IV
    write(serverSocket, ciphertext, ciphertext_len);  //Send the ciphertext
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port> <cryptographic_key> <IV>" << std::endl;
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int serverPort = atoi(argv[2]);
    const char *keyStr = argv[3];
    const char *ivStr = argv[4];

    if (strlen(keyStr) != AES_32_BYTES)
    {
        cerr << "Error: AES key must be 32 characters long. sent length (" << strlen(keyStr) << ")" << endl;
        return EXIT_FAILURE;
    }
    char key[AES_32_BYTES]; memcpy(key, keyStr, AES_32_BYTES);

    if (strlen(ivStr) != EVP_MAX_IV_LENGTH)
    {
        cerr << "Error: AES key must be 16 characters long. sent length (" << strlen(keyStr) << ")" << endl;
        return EXIT_FAILURE;
    }
    char iv[EVP_MAX_IV_LENGTH]; memcpy(key, keyStr, EVP_MAX_IV_LENGTH);

    AES_GCM_256_ENCRYPTION::getInstance(key,iv);

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

    const char *message = "Hello, this is an encrypted message!";
    cout << "Client message: " << message << endl;

    encryptAndSendMessage(serverSocket, message, key);

    unsigned char response[1024];
    int response_len = read(serverSocket, response, sizeof(response));
    if (response_len > 0)
    {
        response[response_len] = '\0';  // Null-terminate the response
        cout << "Server response: " << response << endl;
    }
    else
    {
        cerr << "Error receiving response from server." << endl;
    }

    close(serverSocket);
    return EXIT_SUCCESS;
}
