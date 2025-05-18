#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <process.h> // Для использования _beginthreadex

#pragma comment(lib, "ws2_32.lib")

#define DEFAULT_UDP_IP "172.16.1.222"
#define DEFAULT_UDP_PORT 49000
#define DEFAULT_POLL_INTERVAL 37
#define MESSAGE "READDATA"
#define PIPE_NAME L"\\\\.\\pipe\\udp_rs"

typedef struct {
    uint32_t num;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint16_t len;
    uint16_t res16;
} THeaderPack;

typedef struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcaprec_hdr_t;

void create_pcap_packet_data(uint32_t sec, uint32_t usec, char* packet, int packet_len, char* pcap_packet) 
{
    pcaprec_hdr_t hdr_s;
    hdr_s.ts_sec = sec;
    hdr_s.ts_usec = usec;
    hdr_s.incl_len = packet_len;
    hdr_s.orig_len = packet_len;

    memcpy(pcap_packet, &hdr_s, sizeof(pcaprec_hdr_t));
    memcpy(pcap_packet + 16, packet, packet_len);
}

int initialize_winsock(WSADATA* wsaData) 
{
    if (WSAStartup(MAKEWORD(2, 2), wsaData) != 0) {
        printf("Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
        return 1;
    }
    return 0;
}

SOCKET create_udp_socket() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) 
    {
        printf("Could not create socket. Error Code: %d\n", WSAGetLastError());
    }
    return sock;
}

HANDLE create_named_pipe() 
{
    HANDLE pipe = CreateNamedPipe(
        PIPE_NAME,
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_WAIT,
        1, 65536, 65536,
        300,
        NULL);

    if (pipe == INVALID_HANDLE_VALUE) 
    {
        printf("Failed to create named pipe. Error Code: %d\n", GetLastError());
    }
    return pipe;
}

int connect_named_pipe(HANDLE pipe) 
{
    if (!ConnectNamedPipe(pipe, NULL)) 
    {
        printf("Failed to connect to named pipe. Error Code: %d\n", GetLastError());
        return 1;
    }
    return 0;
}

typedef struct {
    SOCKET sock;
    struct sockaddr_in* server;
    HANDLE pipe;
    HANDLE stopEvent;
} ThreadData;

// Поток запроса данных с MP-106
unsigned __stdcall send_thread(void* arg) 
{
    ThreadData* data = (ThreadData*)arg;
    while (WaitForSingleObject(data->stopEvent, 0) == WAIT_TIMEOUT) {
        if (sendto(data->sock, MESSAGE, strlen(MESSAGE), 0, (struct sockaddr*)data->server, sizeof(*data->server)) == SOCKET_ERROR) {
            printf("Send failed. Error Code: %d\n", WSAGetLastError());
            return 1;
        }
        Sleep(DEFAULT_POLL_INTERVAL);
    }
    return 0;
}

// Отбработка ответов с MP-106
unsigned __stdcall receive_thread(void* arg)
{
    ThreadData* data = (ThreadData*)arg;
    char buffer[2048];
    DWORD bytes_written;
    char pcap_packet[2048];

    while (1)
    {
        int server_len = sizeof(*data->server);
        int recv_len = recvfrom(data->sock, buffer, sizeof(buffer), 0, (struct sockaddr*)data->server, &server_len);
        if (recv_len == SOCKET_ERROR)
        {
            printf("Receive failed. Error Code: %d\n", WSAGetLastError());
            SetEvent(data->stopEvent); // Устанавливаем событие для остановки потоков
            return 2;
        }

        int offset = 0;
        while (offset < recv_len)
        {
            THeaderPack header;
            memcpy(&header, buffer + offset, sizeof(THeaderPack));
            offset += sizeof(THeaderPack);

            char* packet_data = buffer + offset;
            offset += header.len;

            printf("[% 8i] [%i]\n", header.num, header.len);
            create_pcap_packet_data(header.ts_sec, header.ts_usec, packet_data, header.len, pcap_packet);
            if (!WriteFile(data->pipe, pcap_packet, 16 + header.len, &bytes_written, NULL))
            {
                printf("Failed to write to pipe. Error Code: %d\n", GetLastError());
                SetEvent(data->stopEvent); // Устанавливаем событие для остановки потоков
                return 3;
            }
        }
    }
    return 0;
}

int send_receive_data(SOCKET sock, struct sockaddr_in* server, HANDLE pipe, int poll_interval)
{
    HANDLE stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (stopEvent == NULL)
    {
        printf("Failed to create stop event. Error Code: %d\n", GetLastError());
        return 1;
    }

    ThreadData data = { sock, server, pipe, stopEvent };
    HANDLE sendThread = (HANDLE)_beginthreadex(NULL, 0, send_thread, &data, 0, NULL);
    HANDLE receiveThread = (HANDLE)_beginthreadex(NULL, 0, receive_thread, &data, 0, NULL);

    WaitForSingleObject(receiveThread, INFINITE);
    SetEvent(stopEvent); // Устанавливаем событие для остановки send_thread
    WaitForSingleObject(sendThread, INFINITE);

    CloseHandle(sendThread);
    CloseHandle(receiveThread);
    CloseHandle(stopEvent);

    return 0;
}
/*
int send_receive_data(SOCKET sock, struct sockaddr_in* server, HANDLE pipe, int poll_interval)
{
    char buffer[2048];
    DWORD bytes_written;
    char pcap_packet[2048];

    while (1)
    {
        if (sendto(sock, MESSAGE, strlen(MESSAGE), 0, (struct sockaddr*)server, sizeof(*server)) == SOCKET_ERROR)
        {
            printf("Send failed. Error Code: %d\n", WSAGetLastError());
            return 1;
        }

        int server_len = sizeof(*server);
        int recv_len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)server, &server_len);
        if (recv_len == SOCKET_ERROR)      
        {
            printf("Receive failed. Error Code: %d\n", WSAGetLastError());
            return 2;
        }

        int offset = 0;
        while (offset < recv_len) 
        {
            THeaderPack header;
            memcpy(&header, buffer + offset, sizeof(THeaderPack));
            offset += sizeof(THeaderPack);

            char* packet_data = buffer + offset;
            offset += header.len;

            printf("[% 8i] [%i]\n", header.num, header.len);
            create_pcap_packet_data(header.ts_sec, header.ts_usec, packet_data, header.len, pcap_packet);
            if (!WriteFile(pipe, pcap_packet, 16 + header.len, &bytes_written, NULL)) 
            {
                printf("Failed to write to pipe. Error Code: %d\n", GetLastError());
                return 3;
            }
        }

        Sleep(100);
    }
}
*/

int main(int argc, char* argv[]) 
{
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;
    HANDLE pipe;

    // Установка значений по умолчанию
    const char* udp_ip = DEFAULT_UDP_IP;
    int udp_port = DEFAULT_UDP_PORT;
    int poll_interval = DEFAULT_POLL_INTERVAL;

    // Обработка аргументов командной строки
    if (argc > 1) udp_ip = argv[1];
    if (argc > 2) udp_port = atoi(argv[2]);
    if (argc > 3) poll_interval = atoi(argv[3]);

    if (initialize_winsock(&wsaData) != 0) return 1;

    while (1)
    {
        sock = create_udp_socket();
        if (sock == INVALID_SOCKET) return 1;

        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr(udp_ip);
        server.sin_port = htons(udp_port);

        pipe = create_named_pipe();
        printf("create_named_pipe\n");

        if (pipe == INVALID_HANDLE_VALUE) return 1;

        if (connect_named_pipe(pipe) != 0) return 1;

        pcap_hdr_t pcap_hdr;
        pcap_hdr.magic_number = 0xA1B2C3D4;
        pcap_hdr.version_major = 2;
        pcap_hdr.version_minor = 4;
        pcap_hdr.thiszone = 0;
        pcap_hdr.sigfigs = 0;
        pcap_hdr.snaplen = 0xFFFF;
        pcap_hdr.network = 147;

        DWORD bytes_written;
        if (!WriteFile(pipe, &pcap_hdr, sizeof(pcap_hdr), &bytes_written, NULL))
        {
            printf("Failed to write to pipe. Error Code: %d\n", GetLastError());
        }
        printf("WriteFile pcap_hdr\n");

        send_receive_data(sock, &server, pipe, poll_interval);

        CloseHandle(pipe);
        closesocket(sock);
    }

    WSACleanup();

    return 0;
}