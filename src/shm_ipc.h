// shm_ipc.h
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include "rowPacket.h"

#define SHM_NAME "/argus_shm"
#define SEM_FULL_NAME "/sem_full"
#define SEM_EMPTY_NAME "/sem_empty"
#define BUF_SIZE 4096 // 전체 버퍼 크기
#define PKT_MAX 512 // 최대 패킷 크기

// 공유 메모리 버퍼 구조체
typedef struct {
    pthread_mutex_t lock; // 공유 버퍼 접근을 위한 뮤텍스
    pthread_cond_t cond_read; // 데이터가 있음을 알리는 조건 변수
    pthread_cond_t cond_write; // 공간이 있음을 알리는 조건 변수
    int write_idx; // 다음 데이터를 쓸 위치
    int read_idx; // 다음 데이터를 읽을 위치
    int count; // 버퍼에 있는 데이터 개수
    RawPacket packets[BUF_SIZE]; // 실제 데이터 저장 공간
} SharedPacketBuffer;