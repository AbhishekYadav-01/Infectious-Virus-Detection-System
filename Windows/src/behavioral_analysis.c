#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "../detours/include/detours.h"
#include <winreg.h> //Include Microsoft Detours header
#include "../include/behavioral_analysis.h"

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
void monitor_system_calls()
{
    log_event("Starting system call monitoring...");

    // Attach hooks for CreateFileW and RegSetValueExW
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID *)&OriginalCreateFileW, HookedCreateFileW);
    DetourAttach((PVOID *)&OriginalRegSetValueExW, HookedRegSetValueExW);

    if (DetourTransactionCommit() == NO_ERROR)
    {
        log_event("Successfully hooked CreateFileW and RegSetValueExW.");
    }
    else
    {
        log_event("Failed to hook CreateFileW or RegSetValueExW.");
        return;
    }

    log_event("System call monitoring active. Press Ctrl+C to stop.");

    // Wait indefinitely to keep the hooks active
    while (1)
    {
        Sleep(1000);
    }

    // Detach the hooks (not reached unless the program terminates cleanly)
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((PVOID *)&OriginalCreateFileW, HookedCreateFileW);
    DetourDetach((PVOID *)&OriginalRegSetValueExW, HookedRegSetValueExW);
    DetourTransactionCommit();

    log_event("System call monitoring stopped.");
}

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

    // Open the key to monitor (e.g., Startup entries)
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_NOTIFY, &hKey) != ERROR_SUCCESS)
    {
        log_event("Failed to open registry key.");
        return;
    }

    // Create an event object for notifications
    hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hEvent)
    {
        log_event("Failed to create event object.");
        RegCloseKey(hKey);
        return;
    }

    // Set up registry notification
    if (RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE) != ERROR_SUCCESS)
    {
        log_event("Failed to set registry notification.");
        CloseHandle(hEvent);
        RegCloseKey(hKey);
        return;
    }

    log_event("Registry monitoring active...");

    // Monitor registry changes indefinitely
    while (1)
    {
        DWORD result = WaitForSingleObject(hEvent, INFINITE);
        if (result == WAIT_OBJECT_0)
        {
            log_event("[ALERT] Registry change detected in monitored key!");

            // Re-arm the registry notification
            if (RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET, hEvent, TRUE) != ERROR_SUCCESS)
            {
                log_event("Failed to re-arm registry notification.");
                break;
            }
        }
        else
        {
            log_event("Error or termination detected in registry monitoring.");
            break;
        }
    }

    CloseHandle(hEvent);
    RegCloseKey(hKey);
    log_event("Registry monitoring stopped.");
}

// Start behavioral analysis
void start_behavior_analysis(const char *folder_path, const char *virus_file)
{
    strncpy(monitored_file, virus_file, MAX_PATH_LENGTH);
    strncpy(monitored_folder, folder_path, MAX_PATH_LENGTH);

    log_file = fopen("behavior_analysis.log", "a"); // Open the log file in append mode
    if (!log_file)
    {
        printf("[ERROR]: Failed to open log file for writing.\n");
        return;
    }

    log_event("Starting Behavioral Analysis...");
    monitor_folder(folder_path);
    monitor_system_calls();
    fclose(log_file); // Close the log file
}
