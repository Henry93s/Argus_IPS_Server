// (hyungoo)
#define _POSIX_C_SOURCE 200809L
#include <semaphore.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include "shm_ipc.h"
#include "ips_event.h"
#include "ids_log.h"

static shm_ipc_t g_ipc;

static void* shm_loop(void* arg){
    (void)arg;
    for(;;){
        struct timespec ts;
        // 200ms 타임아웃 대기
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 200*1000*1000L;
        if (ts.tv_nsec >= 1000000000L){ ts.tv_sec+=1; ts.tv_nsec-=1000000000L; }
        // 타임아웃 대기
        (void)sem_timedwait(g_ipc.sem, &ts);
        
        // drain
        ips_event_t ev;
        while (ips_ring_pop(g_ipc.ring, &ev)){
            ids_log_event(&ev); // 대시보드/세션탭으로 올릴 핵심 근거
        }
    }
    return NULL;
}

int shm_consumer_start(void){
  if (shm_ipc_open(&g_ipc, /*create=*/0) != 0) {
    fprintf(stderr, "SHM attach failed\n"); return -1;
  }
  pthread_t th; pthread_create(&th, NULL, shm_loop, NULL);
  pthread_detach(th);
  return 0;
}
