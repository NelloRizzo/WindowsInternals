#include "wininternals.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

process_entry *create_process_entry(PROCESSENTRY32 entry)
{
    process_entry *e = malloc(sizeof(process_entry));
    if (!e)
        return NULL;

    memcpy(e->exe_file_name, entry.szExeFile, MAX_PATH);
    e->next = NULL;
    e->process_id = entry.th32ProcessID;
    e->parent_process_id = entry.th32ParentProcessID;
    e->threads_count = entry.cntThreads;
    return e;
}

int match_name(const char *target, const char *current)
{
    size_t l1, l2, len = ((l1 = strlen(target)) > (l2 = strlen(current))) ? l2 : l1;
    return strncmp(target, current, len) == 0;
}

process_list *process_list_create(char *exe_name, int read_memory_info)
{
    process_list *l = malloc(sizeof(process_list));
    if (!l)
        return NULL;
    l->head = NULL;
    l->tail = NULL;
    l->process_count = 0;
    HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (handle == INVALID_HANDLE_VALUE)
    {
        free(l);
        return NULL;
    }
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(handle, &entry))
    {
        CloseHandle(handle);
        free(l);
        return NULL;
    }
    do
    {
        if (!exe_name || match_name(exe_name, entry.szExeFile))
        {
            process_entry *e = create_process_entry(entry);
            if (!e)
            {
                CloseHandle(handle);
                process_list_free(l);
                return NULL;
            }
            if (read_memory_info)
            {
                read_process_memory_info(entry.th32ProcessID, &e->memory);
            }
            if (!l->head)
            {
                l->head = e;
                l->tail = l->head;
            }
            else
            {
                l->tail->next = e;
                l->tail = e;
            }
            l->process_count++;
        }
    } while (Process32Next(handle, &entry));

    l->last_update = time(NULL);
    return l;
}

void process_list_free(process_list *processes)
{
    process_entry *e = processes->head;
    while (e)
    {
        process_entry *current = e;
        e = e->next;
        free(current);
    }
    free(processes);
}

void process_list_apply(process_list *list, fn function)
{
    process_entry *cursor = list->head;
    while (cursor)
    {
        function(cursor);
        cursor = cursor->next;
    }
}

int read_process_memory_info(DWORD pid, memory_info *mem_info)
{
    if (pid < 1 || !mem_info)
        return 0;
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
    if (!handle)
        return 0;
    PROCESS_MEMORY_COUNTERS_EX mem;
    if (!GetProcessMemoryInfo(handle, (PROCESS_MEMORY_COUNTERS *)&mem, sizeof(PROCESS_MEMORY_COUNTERS_EX)))
    {
        CloseHandle(handle);
        return 0;
    }
    mem_info->current = mem.WorkingSetSize;
    mem_info->max = mem.PeakWorkingSetSize;
    mem_info->max_virtual = mem.PeakPagefileUsage;
    mem_info->page_fault = mem.PageFaultCount;
    mem_info->pagefile = mem.PagefileUsage;
    mem_info->unshared = mem.PrivateUsage;
    CloseHandle(handle);
    return 1;
}

service_list *service_list_create(DWORD pid)
{
    service_list *list = malloc(sizeof(service_list));
    if (!list)
        return NULL;
    list->head = NULL;
    list->tail = NULL;
    list->count = 0;
    SC_HANDLE handle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!handle)
    {
        free(list);
        return NULL;
    }
    DWORD bytes_needed, services_count, resume_handle;
    EnumServicesStatusEx(handle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, NULL, 0, &bytes_needed, &services_count, &resume_handle, NULL);
    if (GetLastError() != ERROR_MORE_DATA)
    {
        CloseServiceHandle(handle);
        free(list);
        return NULL;
    }
    LPBYTE buffer = malloc(bytes_needed);
    if (!buffer)
    {
        CloseServiceHandle(handle);
        free(list);
        return NULL;
    }
    resume_handle = 0;
    if (!EnumServicesStatusEx(handle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buffer, bytes_needed, &bytes_needed, &services_count, &resume_handle, NULL))
    {
        free(buffer);
        CloseServiceHandle(handle);
        free(list);
        return NULL;
    }
    ENUM_SERVICE_STATUS_PROCESS *services = (ENUM_SERVICE_STATUS_PROCESS *)buffer;
    for (DWORD i = 0; i < services_count; ++i)
    {
        if (pid == 0 || services[i].ServiceStatusProcess.dwProcessId == pid)
        {
            service_entry *entry = malloc(sizeof(service_entry));
            if (!entry)
            {
                free(buffer);
                CloseServiceHandle(handle);
                service_list_free(list);
                return NULL;
            }
            strncpy(entry->display_name, services[i].lpDisplayName, 255);
            strncpy(entry->name, services[i].lpServiceName, 255);
            entry->display_name[255] = '\0';
            entry->name[255] = '\0';
            entry->next = NULL;
            entry->pid = services[i].ServiceStatusProcess.dwProcessId;
            entry->status = services[i].ServiceStatusProcess.dwCurrentState;
            entry->type = services[i].ServiceStatusProcess.dwServiceType;
            if (list->head)
            {
                list->tail->next = entry;
                list->tail = entry;
            }
            else
            {
                list->head = entry;
                list->tail = list->head;
            }
            list->count++;
        }
    }
    free(buffer);
    CloseServiceHandle(handle);
    list->last_update = time(NULL);
    return list;
}

void service_list_free(service_list *services)
{
    service_entry *cursor = services->head;
    while (cursor)
    {
        service_entry *current = cursor;
        cursor = cursor->next;
        free(current);
    }
    free(services);
}

void service_list_apply(service_list *list, void (*fn)(service_entry *))
{
    if (!list || !fn)
        return;
    service_entry *cursor = list->head;
    while (cursor)
    {
        fn(cursor);
        cursor = cursor->next;
    }
}

memory_scan_stats *memory_scan(DWORD pid, region_callback callback)
{
    memory_scan_stats *stats = malloc(sizeof(memory_scan_stats));
    if (!stats)
        return NULL;
    stats->total_regions = 0;
    stats->readable_regions = 0;
    stats->total_bytes = 0;
    stats->committed_bytes = 0;
    stats->pid = pid;
    HANDLE handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
    if (!handle)
    {
        free(stats);
        return NULL;
    }
    MEMORY_BASIC_INFORMATION mbi;
    ADDR addr = 0;
    while (VirtualQueryEx(handle, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)) > 0)
    {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD))
        {
            memory_region region;
            region.base = (ADDR)(ULONG_PTR)mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protect = mbi.Protect;
            region.type = mbi.Type;
            region.data = malloc(mbi.RegionSize);
            region.bytes_read = 0;

            if (region.data)
            {
                stats->total_regions++;
                ReadProcessMemory(handle, mbi.BaseAddress,
                                  region.data, mbi.RegionSize,
                                  &region.bytes_read);
                stats->total_bytes += region.bytes_read;
                stats->readable_regions++;
                callback(&region, stats);
                free(region.data);
                region.data = NULL;
            }
        }
        addr += mbi.RegionSize;
        if (mbi.State == MEM_COMMIT)
            stats->committed_bytes += mbi.RegionSize;
    }
    stats->timestamp = time(NULL);
    CloseHandle(handle);
    return stats;
}

void free_search_result(search_result *result)
{
    if (result->search_pattern)
    {
        free(result->search_pattern);
    }
    free(result);
}

search_result *pattern_bytes_search(ADDR start_address, DWORD pid, BYTE8 *pattern, SIZE_T pattern_len)
{
    search_result *result = malloc(sizeof(search_result));
    if (!result)
        return NULL;
    result->base_address = 0;
    result->pattern_len = pattern_len;
    result->pid = pid;
    result->search_pattern = malloc(pattern_len);
    if (!result->search_pattern)
    {
        free(result);
        return NULL;
    }
    result->timestamp = time(NULL);
    memcpy(result->search_pattern, pattern, pattern_len);
    HANDLE handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid);
    if (!handle)
    {
        free_search_result(result);
        return NULL;
    }
    MEMORY_BASIC_INFORMATION mbi;
    ADDR addr = start_address;
    while (VirtualQueryEx(handle, (LPCVOID)(ULONG_PTR)addr, &mbi, sizeof(mbi)) > 0 && result->base_address == 0)
    {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD))
        {
            memory_region region;
            region.base = (ADDR)(ULONG_PTR)mbi.BaseAddress;
            region.size = mbi.RegionSize;
            region.protect = mbi.Protect;
            region.type = mbi.Type;
            region.data = malloc(mbi.RegionSize);
            region.bytes_read = 0;

            ReadProcessMemory(handle, mbi.BaseAddress, region.data, mbi.RegionSize, &region.bytes_read);
            if (region.data && pattern_len <= region.bytes_read)
            {
                for (size_t i = 0; result->base_address == 0 && i < region.bytes_read - pattern_len; ++i)
                {
                    if (memcmp(region.data + i, pattern, pattern_len) == 0)
                    {
                        result->base_address = region.base + i;
                    }
                }
                free(region.data);
                region.data = NULL;
            }
        }
        addr += mbi.RegionSize;
    }
    CloseHandle(handle);
    if (result->base_address == 0)
    {
        free_search_result(result);
        return NULL;
    }
    return result;
}

search_result *pattern_chars_search(ADDR start_address, DWORD pid, char *pattern)
{
    return pattern_bytes_search(start_address, pid, (BYTE8 *)pattern, strlen(pattern));
}

/* Abilita i codici colore ANSI sulla console Windows */
void enable_ansi(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

/* Stampa una riga separatrice di lunghezza len */
void print_separator(char c, int len)
{
    int i;
    for (i = 0; i < len; i++)
        putchar(c);
    putchar('\n');
}