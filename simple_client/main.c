#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define LENGTH_PREFIX_SIZE 4
#define BUFFER_SIZE 512

const char* SERVER_IP = "127.0.0.1";
const char* SERVER_PORT = "8080";
const unsigned int KEY_SIZE = 15;


int initializeWSA(void) {
	WSADATA wsa_data;
	return WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

void cleanup(struct addrinfo* server_address, SOCKET server_socket, char* data) {
	if (server_address != NULL)
	{
		freeaddrinfo(server_address);
	}

	if (server_socket != INVALID_SOCKET)
	{
		closesocket(server_socket);
	}

	if (data != NULL)
	{
		free(data);
	}

	WSACleanup();
}

int receive_data(SOCKET server_socket, char** payload)
{
	// Create buffer to hold first 4 bytes of data - the length prefix
	char length_prefix_buffer[LENGTH_PREFIX_SIZE];

	// Receive the length data into the buffer
	int length_bytes_received = recv(server_socket, length_prefix_buffer, LENGTH_PREFIX_SIZE, 0);

	if (length_bytes_received <= 0)
	{
		fprintf(stderr, "[!] recv() failed. (%d)\n", WSAGetLastError());
		return 1;
	}

	// Convert the 4 bytes in the prefix to a 32-bit big-endian integer
	uint32_t preprocessed_payload_size = ((uint32_t)length_prefix_buffer[0] << 24)    |
											((uint32_t)length_prefix_buffer[1] << 16) |
											((uint32_t)length_prefix_buffer[2] << 8)  |
											((uint32_t)length_prefix_buffer[3]);

	// Create new integer from preprocessed_payload_size with endianness that matches system
	size_t payload_size = ntohl((u_long)preprocessed_payload_size);

	// Initialize counter to track total number of payload bytes received so far
	size_t payload_bytes_received = 0;

	// Allocate memory to store the payload now that we know its size
	*payload = (char*)calloc(payload_size, 1);

	if (*payload == NULL)
	{
		fprintf(stderr, "[!] malloc() failed.\n");
		return 1;
	}

	// Use a loop to process payload stream in chunks
	while (payload_bytes_received < payload_size)
	{
		// Default chunk size is BUFFER_SIZE so we take min between that and what's left 
		size_t bytes_to_receive = (size_t)min(BUFFER_SIZE, payload_size - payload_bytes_received);

		// Read bytes from the socket into the payload buffer, offset by payload_bytes_received
		int bytes_received = recv(server_socket, *payload + payload_bytes_received, bytes_to_receive, 0);

		if (bytes_received <= 0)
		{
			fprintf(stderr, "[!] recv() failed. (%d)\n", WSAGetLastError());
			free(*payload);
			return 1;
		}

		// Update the number of bytes which have been received so far
		payload_bytes_received += bytes_received;
	}

	return 0;
}

void printBytes(const unsigned char* data, size_t dataLen) {
	for (size_t i = 0; i < dataLen; ++i) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

int main(void)
{
	if (initializeWSA() != 0)
	{
		printf("[!] Failed to run WSAStartup.\n");
		cleanup(NULL, INVALID_SOCKET, NULL);
		return 1;
	}

	printf("[+] Configuring remote address ...\n");

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* server_address;
	if (getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &server_address) != 0)
	{
		fprintf(stderr, "[!] getaddrinfo() failed. (%d)\n", WSAGetLastError());
		cleanup(server_address, INVALID_SOCKET, NULL);
		return 1;
	}

	printf("[+] Creating socket ...\n");

	SOCKET server_socket = INVALID_SOCKET;
	server_socket = socket(
		server_address->ai_family,
		server_address->ai_socktype,
		server_address->ai_protocol
	);

	// Check if socket is valid
	if (server_socket == INVALID_SOCKET)
	{
		fprintf("[!] socket() failed. (%d)\n", WSAGetLastError());
		cleanup(server_address, server_socket, NULL);
		return 1;
	}

	printf("[+] Connecting to remote host ...\n");

	if (connect(server_socket, server_address->ai_addr, server_address->ai_addrlen) != 0)
	{
		fprintf(stderr, "[!] connect() failed. (%d)\n", WSAGetLastError());
		cleanup(server_address, server_socket, NULL);
		return 1;
	}
	freeaddrinfo(server_address);
	server_address = NULL;

	printf("[+] Connected to remote host at %s:%s\n", SERVER_IP, SERVER_PORT);

	const char* key = "This is a test!";

	printf("[+] Authenticating with remote host ...\n");

	int bytes_sent = send(server_socket, key, KEY_SIZE, 0);
	if (bytes_sent == 0)
	{
		fprintf("[!] send() failed. (%d)\n", WSAGetLastError());
		cleanup(server_address, server_socket, NULL);
		return 1;
	}

	char data_buffer[1024];
	int bytes_received = recv(server_socket, data_buffer, sizeof(data_buffer), 0);

	if (bytes_received <= 0)
	{
		fprintf(stderr, "[!] recv() failed. (%d)\n", WSAGetLastError());
		cleanup(server_address, server_socket, NULL);
		return 1;
	}

	char* data = (char*)malloc(bytes_received);
	if (data == NULL)
	{
		fprintf(stderr, "[!] Failed to allocate memory for key.\n");
		cleanup(server_address, server_socket, NULL);
	}
	else
	{
		memcpy(data, data_buffer, bytes_received);
	}

	printBytes(data, bytes_received);

	cleanup(server_address, server_socket, data);
	return 0;
}