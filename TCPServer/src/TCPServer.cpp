//============================================================================
// Name        : TCPServer.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "AES_GCM_256_ENCRYPTION.h"

timespec LATENCY_PROFILE[6];

const char* create_key_iv(const char *key, const char* iv)
{
	char key_iv_string[AES_32_BYTES + EVP_MAX_IV_LENGTH];
	memset(key_iv_string, 0, AES_32_BYTES + EVP_MAX_IV_LENGTH);
	memcpy(key_iv_string, key, AES_32_BYTES);
	memcpy(key_iv_string + AES_32_BYTES, iv, EVP_MAX_IV_LENGTH);
	return key_iv_string;
}

void encryptAndSendMessage(int clientSocket, const char *message)
{
	AES_GCM_256_ENCRYPTION &aes = AES_GCM_256_ENCRYPTION::getInstance();
    unsigned char ciphertext[MSG_LEN];

    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[4]);
    int ciphertext_len = aes.encryptMessage(reinterpret_cast<const unsigned char *>(message), strlen(message), ciphertext);
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[5]);

    if (ciphertext_len == -1)
    {
        cerr << "Encryption failed." << endl;
        return;
    }

    write(clientSocket, ciphertext, ciphertext_len);  //Send the ciphertext
}


void handleClient(int clientSocket, const char* KeyIV)
{
	clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[0]);
	//send key_iv
	if(write(clientSocket, KeyIV, AES_32_BYTES + EVP_MAX_IV_LENGTH) < 0) {
		perror("Write Error, Unable to send Key,IV!!");
		return;
	}
	clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[1]);

	unsigned char buffer[MSG_LEN];
	int ciphertext_len = read(clientSocket, buffer, sizeof(buffer));
    if (ciphertext_len <= 0) {
        perror("Error reading ciphertext from client.");
        close(clientSocket);
        return;
    }

    unsigned char decrypted[MSG_LEN];
    AES_GCM_256_ENCRYPTION &aes = AES_GCM_256_ENCRYPTION::getInstance();

    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[2]);
    int decrypted_len = aes.decryptMessage(buffer, ciphertext_len, decrypted);
    clock_gettime(CLOCK_MONOTONIC, &LATENCY_PROFILE[3]);

    if(decrypted_len == -1) {
    	perror("Unable to decrypt packet.");
    }
    else {
		decrypted[decrypted_len] = '\0';
		cout << "Decrypted message from client: " << decrypted << endl;
		const char *response = "Message received and decrypted!";
		encryptAndSendMessage(clientSocket,response);
    }

    close(clientSocket);
    return;
}

// 2.48 - 1.25 = (2-1) + (0.48 - 0.25)
// 2.48 - 1.75 = (2-1) + -1 + (0.48 - 0.75 + 1)

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

    char key_iv[AES_32_BYTES+EVP_MAX_IV_LENGTH];

	memset(key_iv, 0, AES_32_BYTES + EVP_MAX_IV_LENGTH);
	memcpy(key_iv, key, AES_32_BYTES);
	memcpy(key_iv + AES_32_BYTES, iv, EVP_MAX_IV_LENGTH);


//    memcpy(key_iv, create_key_iv(key,iv), AES_32_BYTES+EVP_MAX_IV_LENGTH);

    cout << "Key_IV[";
    for(int i=0; i<AES_32_BYTES+EVP_MAX_IV_LENGTH; i++) {
    	cout << key_iv[i];
    }
    cout << "]" << endl;

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
    bool send_response = false;

    while (!send_response)
    {
        int clientSocket = accept(serverSocket, (struct sockaddr *)&client_addr, &client_len);
        if (clientSocket < 0)
        {
            perror("Client accept failed");
            continue;
        }

        cout << "Client connected." << endl;
        handleClient(clientSocket, key_iv);
        send_response = true;
    }

    close(serverSocket);

    cout << "Server Latency Profile =>" << endl;
    cout << "TCP send [" << get_latency(LATENCY_PROFILE[0],LATENCY_PROFILE[1]) << "]" << endl;
    cout << "Decrypt Message [" << get_latency(LATENCY_PROFILE[2],LATENCY_PROFILE[3]) << "]" << endl;
    cout << "Encrypt Message [" << get_latency(LATENCY_PROFILE[4],LATENCY_PROFILE[5]) << "]" << endl;

    return EXIT_SUCCESS;
}
