//============================================================================
// Name        : tcp_server.cpp
// Author      : Pritam Kore
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include "StandardIncludes.h"

void handleClient(int clientSocket)
{
    unsigned char buffer[1024];
    int len = read(clientSocket, buffer, sizeof(buffer));

    if (len <= 0)
    {
        cerr << "Error reading data from client." << endl;
        close(clientSocket);
        return;
    }
    else
    {
    	buffer[len] = '\0';
    	cout << "Client response: " << buffer << endl;
		const char *response = "Hello from Server";
		write(clientSocket, response, strlen(response));
		close(clientSocket);
    }
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

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(tcpServerIp);
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
        close(tcpServerPort);
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
