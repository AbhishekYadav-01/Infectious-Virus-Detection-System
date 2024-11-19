#ifndef BEHAVIORAL_ANALYSIS_H
#define BEHAVIORAL_ANALYSIS_H

#include <stdbool.h>
#include <windows.h>

// Constants for folder and file monitoring
#define MAX_PATH_LENGTH 1024

// Function prototypes
void start_behavior_analysis(const char *folder_path, const char *virus_file);
void monitor_folder(const char *folder_path);
void monitor_registry_changes();
// void monitor_system_calls();
void log_event(const char *message);
void monitor_and_terminate_virus(const char *virus_file);

// Global variable for log file
extern FILE *log_file;

#endif
