#include "wininternals.h"
#include <stdio.h>

void print_entry(process_entry *e)
{
    printf(COL_BOLD "%-40s" COL_RED " PID: %-6lu" COL_RESET COL_CYAN " RAM: %4zu MB  Peak: %4zu MB  Private: %4zu MB\n" COL_RESET,
           e->exe_file_name,
           e->process_id,
           MB(e->memory.current),
           MB(e->memory.max),
           MB(e->memory.unshared));
}
void print_service(service_entry *e)
{
    printf(COL_BOLD "%s" COL_RESET " - " COL_CYAN "%s" COL_RESET " (PID: %lu)\n",
           e->name, e->display_name, e->pid);
}

void print_memory(memory_region *region, memory_scan_stats *) // le statistiche non sono utilizzate in questa funzione
{
    print_separator('-', 50);
    printf(" Region base address:  %016llX (%llukb)\n", region->base, KB(region->bytes_read));
    print_separator('-', 50);
    SIZE_T i;
    for (i = 0; i < region->bytes_read; i += 16)
    {
        SIZE_T j;
        SIZE_T chunk = (region->bytes_read - i < 16) ? (region->bytes_read - i) : 16;

        /* indirizzo */
        printf("%016llX  ", (unsigned long long)(region->base + i));

        /* hex */
        for (j = 0; j < 16; j++)
        {
            if (j < chunk)
                printf("%02X ", region->data[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }

        /* ascii */
        printf("|");
        for (j = 0; j < chunk; j++)
            printf("%c", isprint(region->data[i + j]) ? region->data[i + j] : '.');
        for (j = chunk; j < 16; j++)
            printf(" ");
        printf("|\n");
    }
}

void print_service_and_memory(service_entry *e)
{
    printf(COL_BOLD "%s" COL_RESET " - " COL_CYAN "%s" COL_RESET " (PID: %lu)\n",
           e->name, e->display_name, e->pid);
    memory_scan_stats *stats = memory_scan(e->pid, print_memory);
    free(stats);
}

char *time_str(time_t t)
{
    char *buf = calloc(32, sizeof(char));
    struct tm *tm_info = localtime(&t);
    strftime(buf, 32, "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

int main(int argc, char *argv[])
{
    enable_ansi();

    /* Se il primo carattere è una cifra trattalo come PID */
    if (argc > 1 && argv[1][0] >= '0' && argv[1][0] <= '9')
    {
        DWORD pid = (DWORD)atoi(argv[1]);
        service_list *services = service_list_create(pid);
        if (!services || services->count == 0)
        {
            printf("Nessun servizio trovato per PID %lu\n", pid);
            return 1;
        }
        printf("Servizi in PID %lu (%d):\n", pid, services->count);
        service_list_apply(services, print_service_and_memory);
        service_list_free(services);
    }
    if (argc > 1 && argv[1][0] == '@')
    {
        DWORD pid = (DWORD)atoi(argv[1] + 1);
        memory_scan_stats *stats = memory_scan(pid, print_memory);
        if (!stats)
        {
            printf("Impossibile scansionare PID %lu\n", pid);
            return 1;
        }
        printf("\nRegioni lette: %zu  Totale: %llu MB\n",
               stats->readable_regions,
               (unsigned long long)MB(stats->total_bytes));
        free(stats);
    }
    else
    {
        char *target = NULL;
        if (argc > 1)
        {
            target = calloc(256, sizeof(char));
            memcpy(target, argv[1], strlen(argv[1]));
        }
        process_list *list = process_list_create(target, 1);
        if (!list)
        {
            printf("Nessun processo trovato\n");
            return 1;
        }
        char *last_update = time_str(list->last_update);
        if (!last_update)
            printf("Processi trovati: %zu\n", list->process_count);
        else
        {
            printf("Processi trovati: %zu (%s)\n", list->process_count, last_update);
            free(last_update);
        }
        process_list_apply(list, print_entry);
        process_list_free(list);
        if (target)
            free(target);
        printf("Done\n");
        getchar();
    }
    return 0;
}