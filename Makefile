CC      = gcc
CSTD    = -std=c11
CFLAGS  = -O2 -Wall -pthread $(CSTD)

# 디렉토리
SRC_DIR    = src
INLINE_DIR = inline_hyungoo
BIN_DIR    = bin

# 외부 라이브러리
PCAP_LIBS  = -lpcap
NFQ_CFLAGS = $(shell pkg-config --cflags libnetfilter_queue 2>/dev/null)
NFQ_LIBS   = $(shell pkg-config --libs   libnetfilter_queue 2>/dev/null)

# 실행파일
TARGET_IDS = $(BIN_DIR)/argus
TARGET_IPS = $(BIN_DIR)/argus_inline

# 소스
SRC_IDS = \
  $(SRC_DIR)/main.c \
  $(SRC_DIR)/thread_capture.c \
  $(SRC_DIR)/ts_packet_queue.c

SRC_IPS = \
  $(INLINE_DIR)/main_nfq.c \
  $(INLINE_DIR)/nfq_iface.c \
  $(INLINE_DIR)/packet_utils.c \
  $(INLINE_DIR)/ruleset.c

# 기본 타겟
all: $(TARGET_IDS) $(TARGET_IPS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET_IDS): $(SRC_IDS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_IDS) $(PCAP_LIBS)

$(TARGET_IPS): $(SRC_IPS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(NFQ_CFLAGS) -o $@ $(SRC_IPS) $(NFQ_LIBS)

run_ids: $(TARGET_IDS)
	@echo "sudo $(TARGET_IDS)"
	@sudo $(TARGET_IDS)

run_ips: $(TARGET_IPS)
	@echo "sudo $(TARGET_IPS)"
	@sudo $(TARGET_IPS)

setcap_inline: $(TARGET_IPS)
	sudo setcap cap_net_admin,cap_net_raw+ep $(TARGET_IPS)

clean:
	rm -rf $(BIN_DIR)

rebuild: clean all

.PHONY: all clean rebuild run_ids run_ips setcap_inline
