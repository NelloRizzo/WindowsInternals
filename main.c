#include "wininternals.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
 *  Gestione argomenti
 * ============================================================ */
typedef enum
{
    CMD_NONE,
    CMD_PID,
    CMD_NAME,
    CMD_SCAN
} command_type;

typedef struct
{
    command_type command;
    DWORD pid;
    char name[256];
    BYTE8 pattern[256];
    SIZE_T pattern_len;
    int has_pattern;
} args;

static void print_usage(void)
{
    printf(COL_BOLD "Uso:\n" COL_RESET);
    printf("  process_analyzer.exe " COL_CYAN "-name" COL_RESET " <nome>              Lista processi per nome\n");
    printf("  process_analyzer.exe " COL_CYAN "-pid" COL_RESET " <pid>               Info processo + servizi + scan\n");
    printf("  process_analyzer.exe " COL_CYAN "-pid" COL_RESET " <pid> " COL_CYAN "-scan" COL_RESET "           Hex dump memoria\n");
    printf("  process_analyzer.exe " COL_CYAN "-pid" COL_RESET " <pid> " COL_CYAN "-scan" COL_RESET " \"stringa\"  Cerca stringa\n");
    printf("  process_analyzer.exe " COL_CYAN "-pid" COL_RESET " <pid> " COL_CYAN "-scan -str" COL_RESET " str  Cerca stringa\n");
    printf("  process_analyzer.exe " COL_CYAN "-pid" COL_RESET " <pid> " COL_CYAN "-scan" COL_RESET " FF 4D 5A  Cerca byte hex\n");
}

static int parse_args(int argc, char *argv[], args *out)
{
    memset(out, 0, sizeof(args));
    out->command = CMD_NONE;

    if (argc < 2)
        return 0;

    int i = 1;
    while (i < argc)
    {
        if (strcmp(argv[i], "-name") == 0)
        {
            if (i + 1 >= argc)
                return 0;
            out->command = CMD_NAME;
            strncpy(out->name, argv[++i], 255);
            out->name[255] = '\0';
        }
        else if (strcmp(argv[i], "-pid") == 0)
        {
            if (i + 1 >= argc)
                return 0;
            out->pid = (DWORD)atoi(argv[++i]);
            if (out->command == CMD_NONE)
                out->command = CMD_PID;
        }
        else if (strcmp(argv[i], "-scan") == 0)
        {
            out->command = CMD_SCAN;
        }
        else if (strcmp(argv[i], "-str") == 0)
        {
            if (i + 1 >= argc)
                return 0;
            i++;
            SIZE_T len = strlen(argv[i]);
            if (len > 255)
                len = 255;
            memcpy(out->pattern, argv[i], len);
            out->pattern_len = len;
            out->has_pattern = 1;
        }
        else if (out->command == CMD_SCAN && !out->has_pattern)
        {
            /* stringa tra virgolette oppure byte hex */
            char *endp;
            unsigned long val = strtoul(argv[i], &endp, 16);

            if (*endp == '\0' && endp != argv[i] && val <= 0xFF)
            {
                /* byte hex — accumula finché ci sono hex validi */
                while (i < argc && out->pattern_len < 255)
                {
                    val = strtoul(argv[i], &endp, 16);
                    if (*endp != '\0' || endp == argv[i] || val > 0xFF)
                        break;
                    out->pattern[out->pattern_len++] = (BYTE8)val;
                    i++;
                }
                out->has_pattern = 1;
                continue;
            }
            else
            {
                /* stringa tra virgolette */
                SIZE_T len = strlen(argv[i]);
                if (len > 255)
                    len = 255;
                memcpy(out->pattern, argv[i], len);
                out->pattern_len = len;
                out->has_pattern = 1;
            }
        }
        i++;
    }

    return out->command != CMD_NONE;
}

/* ============================================================
 *  Callback
 * ============================================================ */
void print_entry(process_entry *e)
{
    printf(COL_BOLD "%-40s" COL_RED " PID: %-6lu" COL_RESET COL_CYAN " RAM: %4zu MB  Peak: %4zu MB  Private: %4zu KB\n" COL_RESET,
           e->exe_file_name,
           e->process_id,
           MB(e->memory.current),
           MB(e->memory.max),
           KB(e->memory.unshared));
}

void print_service(service_entry *e)
{
    printf("  " COL_BOLD "%-40s" COL_RESET COL_CYAN " %s\n" COL_RESET,
           e->name, e->display_name);
}

void print_memory(memory_region *region, memory_scan_stats *stats)
{
    (void)stats;
    print_separator('-', 72);
    printf(" 0x%016llX  %llu KB\n",
           (unsigned long long)region->base,
           (unsigned long long)KB(region->bytes_read));
    print_separator('-', 72);

    SIZE_T i;
    for (i = 0; i < region->bytes_read; i += 16)
    {
        SIZE_T j;
        SIZE_T chunk = (region->bytes_read - i < 16)
                           ? (region->bytes_read - i)
                           : 16;

        printf("%016llX  ", (unsigned long long)(region->base + i));

        for (j = 0; j < 16; j++)
        {
            if (j < chunk)
                printf("%02X ", region->data[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }

        printf("|");
        for (j = 0; j < chunk; j++)
            printf("%c", isprint(region->data[i + j]) ? region->data[i + j] : '.');
        for (j = chunk; j < 16; j++)
            printf(" ");
        printf("|\n");
    }
}

char *time_str(time_t t)
{
    char *buf = calloc(32, sizeof(char));
    struct tm *tm_info = localtime(&t);
    strftime(buf, 32, "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

/* ============================================================
 *  Main
 * ============================================================ */
int main(int argc, char *argv[])
{
    enable_ansi();

    args a;
    if (!parse_args(argc, argv, &a))
    {
        print_usage();
        return 1;
    }

    switch (a.command)
    {
    case CMD_NAME:
    {
        process_list *list = process_list_create(a.name, 1);
        if (!list || list->process_count == 0)
        {
            printf(COL_YELLOW "Nessun processo trovato per: %s\n" COL_RESET, a.name);
            return 1;
        }
        char *ts = time_str(list->last_update);
        printf("Processi trovati: %zu (%s)\n", list->process_count, ts);
        free(ts);
        process_list_apply(list, print_entry);
        process_list_free(list);
        printf("Fine. Resto in attesa per terminare...\n");
        getchar();
        break;
    }

    case CMD_PID:
    {
        /* Info memoria */
        memory_info mem = {0};
        read_process_memory_info(a.pid, &mem);
        printf(COL_BOLD "\n=== PID %lu ===\n" COL_RESET, a.pid);
        printf("  RAM      : %zu MB\n", MB(mem.current));
        printf("  Peak     : %zu MB\n", MB(mem.max));
        printf("  Private  : %zu KB\n", KB(mem.unshared));
        printf("  Pagefile : %zu MB\n", MB(mem.pagefile));
        printf("  Fault    : %lu\n", mem.page_fault);

        /* Servizi */
        service_list *services = service_list_create(a.pid);
        if (services && services->count > 0)
        {
            printf(COL_BOLD "\nServizi ospitati (%d):\n" COL_RESET, services->count);
            service_list_apply(services, print_service);
            service_list_free(services);
        }

        /* Scan memoria */
        printf(COL_BOLD "\nScan memoria...\n" COL_RESET);
        memory_scan_stats *stats = memory_scan(a.pid, print_memory);
        if (stats)
        {
            printf("\nRegioni lette : %zu\n", stats->readable_regions);
            printf("Totale        : %llu MB\n",
                   (unsigned long long)MB(stats->total_bytes));
            free(stats);
        }
        break;
    }

    case CMD_SCAN:
    {
        if (a.pid == 0)
        {
            printf(COL_RED "Errore: -scan richiede -pid\n" COL_RESET);
            print_usage();
            return 1;
        }

        if (a.has_pattern)
        {
            /* Ricerca pattern */
            search_result *res = pattern_bytes_search(0, a.pid,
                                                      a.pattern,
                                                      a.pattern_len);
            if (!res)
            {
                printf(COL_YELLOW "Pattern non trovato.\n" COL_RESET);
                return 1;
            }
            printf(COL_GREEN "Trovato @ 0x%016llX\n" COL_RESET,
                   (unsigned long long)res->base_address);
            free_search_result(res);
        }
        else
        {
            /* Hex dump completo */
            memory_scan_stats *stats = memory_scan(a.pid, print_memory);
            if (!stats)
            {
                printf(COL_RED "Impossibile scansionare PID %lu\n" COL_RESET, a.pid);
                return 1;
            }
            printf("\nRegioni lette : %zu\n", stats->readable_regions);
            printf("Totale        : %llu MB\n",
                   (unsigned long long)MB(stats->total_bytes));
            free(stats);
        }
        break;
    }

    default:
        print_usage();
        return 1;
    }

    return 0;
}