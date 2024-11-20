#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "../detours/include/detours.h" // Include Microsoft Detours header
#include <winreg.h>                     //Include Microsoft Detours header
#include "../include/behavioral_analysis.h"
#include <tlhelp32.h>

// Global variables
FILE *log_file = NULL;                       // Log file
char monitored_file[MAX_PATH_LENGTH] = "";   // File flagged as a virus
char monitored_folder[MAX_PATH_LENGTH] = ""; // Folder containing the virus

// Utility function to log events
void log_event(const char *message)
{
    printf("[EVENT]: %s\n", message); // Display on the terminal
    if (log_file)
    {
        fprintf(log_file, "[EVENT]: %s\n", message);
        fflush(log_file); // Ensure the log is written immediately
    }
}

// Function to monitor and terminate the virus process
void monitor_and_terminate_virus(const char *virus_file)
{
    log_event("Starting process monitoring to terminate the virus...");

    while (1)
    {
        // Take a snapshot of all processes
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            log_event("[ERROR] Failed to take process snapshot.");
            Sleep(5000); // Retry after 5 seconds
            continue;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        // Iterate through the snapshot
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                // Convert the process name to a multi-byte string for comparison
                char processName[MAX_PATH];
// Convert wide characters to multi-byte if UNICODE is defined
#ifdef UNICODE
                wcstombs(processName, pe32.szExeFile, MAX_PATH);
#else
                strncpy(processName, pe32.szExeFile, MAX_PATH);
#endif

                // Compare with the virus executable name
                if (_stricmp(processName, virus_file) == 0)
                {
                    char log_message[256];
                    snprintf(log_message, sizeof(log_message), "[ALERT] Virus process detected: %s (PID: %u)", processName, pe32.th32ProcessID);
                    log_event(log_message);

                    // Open the process to get its handle
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess)
                    {
                        // Terminate the process
                        if (TerminateProcess(hProcess, 1))
                        {
                            log_event("[ACTION] Virus process terminated successfully.");
                        }
                        else
                        {
                            log_event("[ERROR] Failed to terminate the virus process.");
                        }
                        CloseHandle(hProcess);
                    }
                    else
                    {
                        log_event("[ERROR] Failed to open process for termination.");
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        else
        {
            log_event("[ERROR] Failed to retrieve process information.");
        }

        CloseHandle(hSnapshot);
        Sleep(5000); // Wait for 5 seconds before the next check
    }
}

// Original function pointers
static HANDLE(WINAPI *OriginalCreateFileW)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) = NULL;

static LONG(WINAPI *OriginalRegSetValueExW)(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData) = NULL;

// Hooked function for CreateFileW
HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    char mbFileName[MAX_PATH_LENGTH];
    wcstombs(mbFileName, lpFileName, MAX_PATH_LENGTH); // Convert wide string to multi-byte

    if (strstr(mbFileName, monitored_file))
    {
        log_event("[ALERT] Monitored virus file is being accessed.");
    }

    // Log the file operation
    printf("[HOOK] CreateFileW called for: %s\n", mbFileName);
    log_event("[HOOK] CreateFileW intercepted.");

    // Call the original CreateFileW function
    if (OriginalCreateFileW)
    {
        return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
                                   lpSecurityAttributes, dwCreationDisposition,
                                   dwFlagsAndAttributes, hTemplateFile);
    }
    else
    {
        log_event("[ERROR] OriginalCreateFileW pointer is NULL.");
        SetLastError(ERROR_FUNCTION_FAILED);
        return INVALID_HANDLE_VALUE;
    }
}

// Hooked function for RegSetValueExW
LONG WINAPI HookedRegSetValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    const BYTE *lpData,
    DWORD cbData)
{
    char mbValueName[MAX_PATH_LENGTH];
    wcstombs(mbValueName, lpValueName, MAX_PATH_LENGTH); // Convert wide string to multi-byte

    if (strstr(mbValueName, monitored_file))
    {
        log_event("[ALERT] Monitored virus file linked to registry modification!");
    }

    log_event("[HOOK] RegSetValueExW intercepted.");

    // Call the original function
    if (OriginalRegSetValueExW)
    {
        return OriginalRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }
    else
    {
        log_event("[ERROR] OriginalRegSetValueExW pointer is NULL.");
        return ERROR_FUNCTION_FAILED;
    }
}

// Monitor system calls
// void monitor_system_calls()
// {
//     log_event("Starting system call monitoring...");

//     // Attach hooks for CreateFileW and RegSetValueExW
//     DetourTransactionBegin();
//     DetourUpdateThread(GetCurrentThread());
//     DetourAttach((PVOID *)&OriginalCreateFileW, HookedCreateFileW);
//     DetourAttach((PVOID *)&OriginalRegSetValueExW, HookedRegSetValueExW);

//     if (DetourTransactionCommit() == NO_ERROR)
//     {
//         log_event("Successfully hooked CreateFileW and RegSetValueExW.");
//     }
//     else
//     {
//         log_event("Failed to hook CreateFileW or RegSetValueExW.");
//         return;
//     }

//     log_event("System call monitoring active. Press Ctrl+C to stop.");

//     // Wait indefinitely to keep the hooks active
//     while (1)
//     {
//         Sleep(1000);
//     }

//     // Detach the hooks (not reached unless the program terminates cleanly)
//     DetourTransactionBegin();
//     DetourUpdateThread(GetCurrentThread());
//     DetourDetach((PVOID *)&OriginalCreateFileW, HookedCreateFileW);
//     DetourDetach((PVOID *)&OriginalRegSetValueExW, HookedRegSetValueExW);
//     DetourTransactionCommit();

//     log_event("System call monitoring stopped.");
// }

// Monitor folder for changes
void monitor_folder(const char *folder_path)
{
    log_event("Starting folder monitoring...");
    HANDLE hDir = CreateFile(
        folder_path,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (hDir == INVALID_HANDLE_VALUE)
    {
        log_event("Failed to open directory handle for monitoring.");
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;

    while (1)
    {
        if (ReadDirectoryChangesW(
                hDir,
                buffer,
                sizeof(buffer),
                TRUE, // Monitor subdirectories
                FILE_NOTIFY_CHANGE_FILE_NAME |
                    FILE_NOTIFY_CHANGE_DIR_NAME |
                    FILE_NOTIFY_CHANGE_ATTRIBUTES |
                    FILE_NOTIFY_CHANGE_SIZE |
                    FILE_NOTIFY_CHANGE_LAST_WRITE,
                &bytesReturned,
                NULL,
                NULL))
        {
            FILE_NOTIFY_INFORMATION *info = (FILE_NOTIFY_INFORMATION *)buffer;
            do
            {
                WCHAR fileName[MAX_PATH_LENGTH];
                wcsncpy(fileName, info->FileName, info->FileNameLength / sizeof(WCHAR));
                fileName[info->FileNameLength / sizeof(WCHAR)] = L'\0';

                char mbFileName[MAX_PATH_LENGTH];
                wcstombs(mbFileName, fileName, MAX_PATH_LENGTH);

                char log_message[512];
                snprintf(log_message, sizeof(log_message), "[MONITOR] File changed: %s", mbFileName);
                log_event(log_message);

                // Check if the virus file is modified
                if (strstr(mbFileName, monitored_file))
                {
                    log_event("[ALERT] Virus file modified in monitored folder.");
                }

                info = info->NextEntryOffset ? (FILE_NOTIFY_INFORMATION *)((BYTE *)info + info->NextEntryOffset) : NULL;
            } while (info);
        }
        else
        {
            log_event("Failed to read directory changes.");
            break;
        }
    }

    CloseHandle(hDir);
    log_event("Folder monitoring stopped.");
}

void monitor_registry_changes()
{
    log_event("Starting registry monitoring...");

    HKEY hKey;
    HANDLE hEvent;

    // Open the registry key to monitor
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_NOTIFY, &hKey) != ERROR_SUCCESS)
    {
        log_event("[ERROR] Failed to open registry key. Check permissions.");
        return;
    }

    // Create an event object for notifications
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent)
    {
        log_event("[ERROR] Failed to create event object.");
        RegCloseKey(hKey);
        return;
    }

    // Set up registry notification
    if (RegNotifyChangeKeyValue(hKey, TRUE,
                                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_ATTRIBUTES,
                                hEvent, TRUE) != ERROR_SUCCESS)
    {
        log_event("[ERROR] Failed to set registry notification.");
        CloseHandle(hEvent);
        RegCloseKey(hKey);
        return;
    }

    log_event("Registry monitoring active. Waiting for changes...");

    // Monitor registry changes indefinitely
    while (1)
    {
        DWORD result = WaitForSingleObject(hEvent, INFINITE);
        if (result == WAIT_OBJECT_0)
        {
            log_event("[ALERT] Registry change detected!");

            // Re-arm the registry notification
            if (RegNotifyChangeKeyValue(hKey, TRUE,
                                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_ATTRIBUTES,
                                        hEvent, TRUE) != ERROR_SUCCESS)
            {
                log_event("[ERROR] Failed to re-arm registry notification. Exiting...");
                break;
            }
        }
        else if (result == WAIT_FAILED)
        {
            log_event("[ERROR] WaitForSingleObject failed. Exiting...");
            break;
        }
        else if (result == WAIT_TIMEOUT)
        {
            log_event("[INFO] Registry monitoring timed out. Re-checking...");
        }
    }

    CloseHandle(hEvent);
    RegCloseKey(hKey);
    log_event("Registry monitoring stopped.");
}

// Thread function prototypes
DWORD WINAPI ThreadMonitorRegistry(LPVOID lpParam);
DWORD WINAPI ThreadMonitorFolder(LPVOID lpParam);

// Thread function for registry monitoring
DWORD WINAPI ThreadMonitorRegistry(LPVOID lpParam)
{
    monitor_registry_changes();
    return 0;
}

// Thread function for folder monitoring
DWORD WINAPI ThreadMonitorFolder(LPVOID lpParam)
{
    const char *folder_path = (const char *)lpParam;
    monitor_folder(folder_path);
    return 0;
}

// Start behavioral analysis
// void start_behavior_analysis(const char *folder_path, const char *virus_file)
// {
//     strncpy(monitored_file, virus_file, MAX_PATH_LENGTH);
//     strncpy(monitored_folder, folder_path, MAX_PATH_LENGTH);

//     log_file = fopen("behavior_analysis.log", "a"); // Open the log file in append mode
//     if (!log_file)
//     {
//         printf("[ERROR]: Failed to open log file for writing.\n");
//         return;
//     }

//     log_event("Starting Behavioral Analysis...");
//     monitor_registry_changes();
//     monitor_folder(folder_path);
//     // monitor_system_calls();
//     fclose(log_file); // Close the log file
// }

void start_behavior_analysis(const char *folder_path, const char *virus_file)
{
    strncpy_s(monitored_file, sizeof(monitored_file), virus_file, MAX_PATH_LENGTH);
    strncpy_s(monitored_folder, sizeof(monitored_folder), folder_path, MAX_PATH_LENGTH);

    log_file = fopen("behavior_analysis.log", "a"); // Open the log file in append mode
    if (!log_file)
    {
        printf("[ERROR]: Failed to open log file for writing.\n");
        return;
    }

    log_event("Starting Behavioral Analysis...");

    // Create threads for monitoring registry and folder
    HANDLE hThreadRegistry = CreateThread(
        NULL, 0, ThreadMonitorRegistry, NULL, 0, NULL);
    if (hThreadRegistry == NULL)
    {
        log_event("[ERROR] Failed to create registry monitoring thread.");
        return;
    }

    HANDLE hThreadFolder = CreateThread(
        NULL, 0, ThreadMonitorFolder, (LPVOID)folder_path, 0, NULL);
    if (hThreadFolder == NULL)
    {
        log_event("[ERROR] Failed to create folder monitoring thread.");
        return;
    }
    HANDLE hThreadTerminateVirus = CreateThread(
        NULL, 0, (LPTHREAD_START_ROUTINE)monitor_and_terminate_virus, (LPVOID)virus_file, 0, NULL);
    if (hThreadTerminateVirus == NULL)
    {
        log_event("[ERROR] Failed to create virus termination thread.");
    }

    // Wait for both threads to finish (if desired)
    WaitForMultipleObjects(3, (HANDLE[]){hThreadRegistry, hThreadFolder, hThreadTerminateVirus}, TRUE, INFINITE);

    fclose(log_file); // Close the log file
    log_event("Behavioral Analysis completed.");
}
