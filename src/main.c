#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <string.h> // memset
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"           // 공용 구조체
#include "ts_packet_queue.h"    // Packet Queue
// #include "ts_alert_queue.h"     // Alert Queue
#include "thread_capture.h"     // libpcap 캡처 스레드
#include "thread_parser.h"   // 파싱/분류 스레드
#include "sessionManager.h"
// #include "thread_analyzer.h" // 융합/위협 분석 스레드
// #include "thread_response.h"  // 후처리/로깅 스레드
#include "shm_ipc.h" // IPS -> IDS rawpacket 전송을 위한 공유 메모리 구조체 정의 헤더 include

// 전역 서버 소켓(== server_sock) -> 클라이언트 연결 관리/종료 시
int server_sock_global;

// 클라이언트 연결 관리를 위한 전역 변수
#define MAX_CLIENTS 10
int client_sockets[MAX_CLIENTS];
pthread_mutex_t client_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

// 스레드 간 데이터 통로인 큐
PacketQueue packetQueue;
SessionManager sessionManager;
// AlertQueue alertQueue;

// 프로그램의 종료를 제어하기 위한 플래그
volatile sig_atomic_t is_running = 1;

// 함수 프로토타입들 (하단 정의 확인)
void handle_shutdown_signal(int signal);
// ... 클라이언트 연결을 수락하는 스레드 함수
void* client_connection_thread(void* arg);
// ... 각 클라이언트와의 통신을 전담하는 스레드 함수
void* handle_client_comm(void* arg);


// main 함수
int main(int argc, char *argv[]) {
    
    printf("Argus IPS 초기화 진행 중...\n");

    // Ctrl+C, 프로세스 종료 시그널 수신 시ㄴ 핸들 함수 호출
    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);

    // 공유 자원 초기화
    tsPacketqInit(&packetQueue, &is_running);
    // tsAlertqInit(&alertQueue, &is_running);
    memset(client_sockets, 0, sizeof(client_sockets));
    printf("공유 자원 초기화 완료.\n");

    // 스레드에 전달할 인자 준비
    // 각 스레드에서 common_args 를 받고 ex. args->packetqueue 와 같은 방식으로 사용
    ThreadArgs common_args = { 
        .packetQueue = &packetQueue, 
        // .alertQueue = &alertQueue,
        .isRunning = &is_running
    };

    // 워커 스레드 선언
    pthread_t /*nfqueue_tid, */capture_tid , parser_tid 
    /*, analyzer_tid, response_tid*/;
    pthread_t connection_tid; // 클라이언트 연결 수락용 스레드

    printf("IDS 워커 스레드 생성 중...\n");

    // 스레드 생성 확인을 위한 출력 추가
    /*
    if (pthread_create(&nfqueue_tid, NULL, nfqueue_thread_main, &common_args) != 0) {
        perror("NFQUEUE 수신 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 1-1. NFQUEUE 수신 스레드가 생성되었습니다.\n");
    */

    if (pthread_create(&capture_tid, NULL, pcap_thread_main, &common_args) != 0) {
        perror("libpcap 캡처 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-1. libpcap 캡처 스레드가 생성되었습니다.\n");
    
    
    if (pthread_create(&parser_tid, NULL, parser_thread_main, &common_args) != 0) {
        perror("파싱/분류 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-2. 파싱/분류 스레드가 생성되었습니다.\n");
    

    /*
    if (pthread_create(&analyzer_tid, NULL, analyzer_thread_main, &common_args) != 0) {
        perror("융합/위협 분석 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-3. 융합/위협 분석 스레드가 생성되었습니다.\n");
    */

    /*
    if (pthread_create(&response_tid, NULL, response_thread_main, &common_args) != 0) {
        perror("후처리/로깅 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 2-4. 후처리/로깅 스레드가 생성되었습니다.\n");
    */

    // start : IDS 프로세스에서 IPS 에서 보내는 raw packet 받기

    // end : IDS 프로세스에서 IPS 에서 보내는 raw packet 받기

    // 클라이언트 연결 수락 스레드 생성
    if (pthread_create(&connection_tid, NULL, client_connection_thread, (void*)&is_running) != 0) {
        perror("클라이언트 연결 관리 스레드 생성 실패"); exit(EXIT_FAILURE);
    }
    printf(" -> [OK] 클라이언트 연결 관리 스레드가 생성되었습니다.\n");

    printf("\n모든 스레드가 정상적으로 생성되었습니다. Argus가 활성화되었습니다.\n");
    printf("Ctrl+C를 입력하면 종료됩니다.\n");
    
    // 스레드 종료 대기
    // pthread_join(nfqueue_tid, NULL);
    pthread_join(capture_tid, NULL);
    // pthread_join(parser_tid, NULL);
    // pthread_join(analyzer_tid, NULL);
    // pthread_join(response_tid, NULL);
    pthread_join(connection_tid, NULL);

    // 공유 자원 해제
    printf("\n모든 스레드가 종료되었습니다. 할당한 자원을 해제합니다...\n");
    tsPacketqDestroy(&packetQueue);
    // tsAlertqDestroy(&alertQueue);
    pthread_mutex_destroy(&client_sockets_mutex);
    printf("종료 완료.\n");

    return 0;
}


// 시그널 핸들러 함수
void handle_shutdown_signal(int signal) {
    printf("\n종료 시그널을 수신했습니다. 모든 스레드를 안전하게 종료합니다...\n");
    is_running = 0;
    
    // 캡처 스레드 캡처 루프(dispatcher) 중단
    capture_request_stop();

    // 큐에서 대기 중인 스레드를 깨우기 위한 추가 조치
    tsPacketqSignalExit(&packetQueue);
    // tsAlertqSignalExit(&alertQueue);

    if(server_sock_global != -1){
        close(server_sock_global);
        server_sock_global = -1;
    }
}

// 각 클라이언트와의 통신을 전담하는 스레드 함수
void* handle_client_comm(void* arg) {
    int client_sock = *(int*)arg;
    // 동적 할당된 메모리 해제
    free(arg);
    char buffer[BUFSIZ];
    int read_len;

    // 서버의 각 통신 스레드는 자신만의 클라이언트와 계속 통신
    while ((read_len = read(client_sock, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[read_len] = '\0';
        printf("[Client %d] 메시지 수신: %s", client_sock, buffer);

        // Todo list 3~4주차? (직접 명령 받을 때 추가 json 받고 파싱) : 여기서 수신된 JSON 명령을 파싱하고,
        // AlertQueue나 다른 메커니즘을 통해 다른 스레드에 작업을 요청해야 함.
        // (예: "스트리밍 시작" 명령을 받으면, 홈캠 서버로 전달)

        // 명령 처리 후 응답처리 (간단하게 일단.. 첫 싲ㅏㄱ이므로 !)
        write(client_sock, "명령 수신 완료\n", strlen("명령 수신 완료\n"));
    }

    // read()가 0 이하를 반환하면 클라이언트 연결이 끊긴 것
    printf("관제 클라이언트(%d) 연결 종료.\n", client_sock);
    
    // 전역 소켓 배열에서 자신을 제거 (뮤텍스로 보호)
    pthread_mutex_lock(&client_sockets_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (client_sockets[i] == client_sock) {
            client_sockets[i] = 0; // 슬롯 비우기
            break;
        }
    }
    pthread_mutex_unlock(&client_sockets_mutex);

    close(client_sock);
    return NULL;
}

// 클라이언트 연결을 수락하고 관리하는 스레드 함수
void* client_connection_thread(void* arg) {
    volatile sig_atomic_t* isRunning = (volatile sig_atomic_t*)arg;
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size;
    // 아직 라즈베리파이 x -> gw ip : 192.168.2.29
    const int PORT = 8085;

    // Argus Listen 소켓
    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    if (server_sock == -1) {
        perror("서버 소켓 생성 실패");
        return NULL;
    }
    server_sock_global = server_sock;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("서버 소켓 바인드 실패");
        close(server_sock);
        return NULL;
    }

    if (listen(server_sock, 5) == -1) {
        perror("서버 소켓 리슨 실패");
        close(server_sock);
        return NULL;
    }

    printf("관제 클라이언트 연결 대기 중... (Port: %d)\n", PORT);

    while (*isRunning) {
        client_addr_size = sizeof(client_addr);
        // Argus 와 각 클라이언트 "통신" 소켓 accept 처리
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
        
        if (client_sock == -1) {
            if (*isRunning == 0) break;
            perror("클라이언트 연결 수락 실패");
            continue;
        }

        printf("관제 클라이언트 연결됨: %s\n", inet_ntoa(client_addr.sin_addr));

        // 새 클라이언트를 배열에 추가 (뮤텍스로 보호)
        pthread_mutex_lock(&client_sockets_mutex);
        int client_added = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (client_sockets[i] == 0) {
                client_sockets[i] = client_sock;
                client_added = 1;
                break;
            }
        }
        pthread_mutex_unlock(&client_sockets_mutex);

        if (client_added) {
            // 통신을 전담할 새로운 스레드를 생성
            pthread_t tid;
            int* client_sock_ptr = (int*)malloc(sizeof(int));
            if (client_sock_ptr == NULL) {
                perror("메모리 할당 실패");
                close(client_sock);
                continue;
            }
            *client_sock_ptr = client_sock;

            if (pthread_create(&tid, NULL, handle_client_comm, client_sock_ptr) != 0) {
                perror("클라이언트 통신 스레드 생성 실패");
                free(client_sock_ptr);
                close(client_sock);
            }
            // 생성된 스레드는 알아서 동작하므로, main에서 join할 필요 없음 (분리)
            pthread_detach(tid); 
        } else {
            printf("클라이언트 수용량 초과. 연결을 거부합니다.\n");
            write(client_sock, "서버가 가득 찼습니다.\n", strlen("서버가 가득 찼습니다.\n"));
            close(client_sock);
        }
    }

    close(server_sock);

    printf("클라이언트 연결 관리 스레드가 종료됩니다.\n");
    return NULL;
}