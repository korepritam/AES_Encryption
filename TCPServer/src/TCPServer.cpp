//============================================================================
// Name        : TCPServer.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "AES_GCM_256_ENCRYPTION.h"

void handleClient(int clientSocket)
{
    unsigned char buffer[MSG_LEN];

    int iv_len = read(clientSocket, buffer, EVP_MAX_IV_LENGTH);
    if (iv_len != EVP_MAX_IV_LENGTH)
    {
        cerr << "Error reading IV from client." << endl;
        close(clientSocket);
        return;
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    memcpy(iv, buffer, EVP_MAX_IV_LENGTH);

    int ciphertext_len = read(clientSocket, buffer, sizeof(buffer));
    if (ciphertext_len <= 0)
    {
        cerr << "Error reading ciphertext from client." << endl;
        close(clientSocket);
        return;
    }

    unsigned char decrypted[1024];
    AES_GCM_256_ENCRYPTION &aes = AES_GCM_256_ENCRYPTION::getInstance();

    int decrypted_len = aes.decryptMessage(buffer, ciphertext_len, iv, decrypted);
    if (decrypted_len == -1)
    {
        cerr << "Decryption failed." << endl;
        close(clientSocket);
        return;
    }

    decrypted[decrypted_len] = '\0';
    cout << "Decrypted message from client: " << decrypted << endl;

    const char *response = "Message received and decrypted!";
    write(clientSocket, response, strlen(response));

    close(clientSocket);
}

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port> <cryptography_key> <IV>" << std::endl;
        return EXIT_FAILURE;
    }

    const char* tcpServerIP = argv[1];
    int tcpServerPort = atoi(argv[2]);
    const char *keyStr = argv[3];
    const char *ivStr = argv[4];

    if (strlen(keyStr) != AES_32_BYTES)
    {
        cerr << "Error: AES key must be 32 characters long (128-bit key). sent length (" << strlen(keyStr) << ")" << endl;
        return EXIT_FAILURE;
    }
    char key[AES_32_BYTES]; memcpy(key, keyStr, AES_32_BYTES);

    if(strlen(ivStr) != EVP_MAX_IV_LENGTH)
    {
		cerr << "Error: IV must be 16 characters long . sent length (" << strlen(ivStr) << ")" << endl;
		return EXIT_FAILURE;
    }
    char iv[EVP_MAX_IV_LENGTH]; memcpy(iv, ivStr, EVP_MAX_IV_LENGTH);

    AES_GCM_256_ENCRYPTION::getInstance(key,iv);

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(tcpServerIP);
    server_addr.sin_port = htons(tcpServerPort);

    if (bind(serverSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Binding failed");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    if (listen(serverSocket, 1) == -1)
    {
        perror("Listen failed");
        close(serverSocket);
        return EXIT_FAILURE;
    }

    cout << "Server listening on port " << tcpServerPort << endl;

    while (true)
    {
        int clientSocket = accept(serverSocket, (struct sockaddr *)&client_addr, &client_len);
        if (clientSocket < 0)
        {
            perror("Client accept failed");
            continue;
        }

        cout << "Client connected." << endl;
        handleClient(clientSocket);
    }

    close(serverSocket);

    return EXIT_SUCCESS;
}
