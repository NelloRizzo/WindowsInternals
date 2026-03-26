#ifndef WININTERNALS_H
#define WININTERNALS_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdint.h>
#include <time.h>

/* ============================================================
 *  Tipi base
 * ============================================================ */
typedef uint8_t BYTE8;
typedef uint16_t WORD16;
typedef uint32_t DWORD32;
typedef uint64_t QWORD64;
typedef uintptr_t ADDR; /* indirizzo di memoria generico */

/* ============================================================
 *  Strutture
 * ============================================================ */

/* Informazioni sintetiche su un processo */
typedef struct
{
    DWORD pid;
    DWORD ppid;
    DWORD thread_count;
    char name[MAX_PATH];
    SIZE_T working_set; /* byte in RAM */
} ProcessInfo;

/* ============================================================
 *  Costanti e macro utili
 * ============================================================ */
#define KB(x) ((x) / 1024ULL)
#define MB(x) ((x) / (1024ULL * 1024ULL))

#define DUMP_BLOCK_SIZE 256
#define MAX_REGIONS 4096
#define MAX_MODULES 256

/* ============================================================
 *  Colori
 * ============================================================ */
#define COL_RESET "\033[0m"
#define COL_BOLD "\033[1m"
#define COL_RED "\033[31m"
#define COL_GREEN "\033[32m"
#define COL_YELLOW "\033[33m"
#define COL_CYAN "\033[36m"
#define COL_WHITE "\033[37m"

/* ============================================================
 *  Gestione dei processi
 * ============================================================ */
typedef struct
{
    SIZE_T current;
    SIZE_T max;
    SIZE_T pagefile;
    SIZE_T max_virtual;
    SIZE_T unshared;
    DWORD page_fault;
} memory_info;

typedef struct process_entry
{
    DWORD process_id;
    DWORD parent_process_id;
    DWORD threads_count;
    memory_info memory;
    char exe_file_name[MAX_PATH];
    struct process_entry *next;
} process_entry;

typedef struct
{
    process_entry *head;
    process_entry *tail;
    time_t last_update;
    size_t process_count;
} process_list;

typedef void (*fn)(process_entry *processes);

process_list *process_list_create(char *exe_name, int read_memory_info);
void process_list_free(process_list *processes);
void process_list_apply(process_list *list, fn function);
int read_process_memory_info(DWORD pid, memory_info *mem_info);

/* ============================================================
 *  Gestione dei servizi
 * ============================================================ */
typedef struct service_entry
{
    char name[256];
    char display_name[256];
    DWORD pid;
    DWORD status;
    DWORD type;
    struct service_entry *next;
} service_entry;

typedef struct
{
    service_entry *head;
    service_entry *tail;
    int count;
    time_t last_update;
} service_list;

service_list *service_list_create(DWORD pid);
void service_list_free(service_list *services);
void service_list_apply(service_list *list, void (*fn)(service_entry *));

/* ============================================================
 *  Accesso alla memoria
 * ============================================================ */
typedef struct
{
    ADDR base;
    SIZE_T size;
    DWORD protect;
    DWORD type;
    BYTE8 *data;
    SIZE_T bytes_read;
} memory_region;

typedef struct
{
    size_t total_regions;
    size_t readable_regions;
    SIZE_T total_bytes;
    SIZE_T committed_bytes;
    DWORD pid;
    time_t timestamp;
} memory_scan_stats;

typedef struct
{
    DWORD pid;
    time_t timestamp;
    ADDR base_address;
    BYTE8 *search_pattern;
    SIZE_T pattern_len;
} search_result;

typedef void (*region_callback)(memory_region *region, memory_scan_stats *stats);
memory_scan_stats *memory_scan(DWORD pid, region_callback callback);
search_result *pattern_bytes_search(ADDR start_address, DWORD pid, BYTE8 *pattern, SIZE_T pattern_len);
search_result *pattern_chars_search(ADDR start_address, DWORD pid, char *pattern);
void free_search_result(search_result *result);
/* ============================================================
 *  Utils
 * ============================================================ */

void enable_ansi(void);
void print_separator(char c, int len);

#endif /* WININTERNALS_H */