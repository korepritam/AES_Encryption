//============================================================================
// Name        : tcp_client.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "StandardIncludes.h"

void handleServer(int clientSocket)
{
    const char* clientMsg = "Hello from Client";
    write(clientSocket, clientMsg, strlen(clientMsg));

    unsigned char buffer[1024];
    int len = read(clientSocket, buffer, sizeof(buffer));
    if (len > 0)
    {
        buffer[len] = '\0';
        cout << "Server response: " << buffer << endl;
    }

    close(clientSocket);
}

int main(int argc, char **argv)
{
	if(argc != 3)
	{
		cerr << "Error!! [" << argv[0] << " tcp_src_ip " << " tcp_src_port " << "]" << endl;
		return EXIT_FAILURE;
	}

	const char* tcpServerIp = argv[1];
	int tcpServerPort = atoi(argv[2]);

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcpServerPort);

    if (inet_pton(AF_INET, tcpServerIp, &server_addr.sin_addr) <= 0)
    {
        perror("Invalid address");
        close(clientSocket);
        return EXIT_FAILURE;
    }

    if (connect(clientSocket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Connection failed");
        close(clientSocket);
        return -1;
    }

    handleServer(clientSocket);

	return EXIT_SUCCESS;
}
