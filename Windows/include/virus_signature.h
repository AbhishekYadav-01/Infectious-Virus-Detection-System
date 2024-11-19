#ifndef VIRUS_SIGNATURE_H
#define VIRUS_SIGNATURE_H

#include <stdbool.h>
#include <windows.h> // For Windows-specific functions

#define HASH_SIZE 33             // MD5 hash size in hexadecimal representation + null terminator
#define MAX_SIGNATURES 1000      // Adjust as needed based on your data
#define MAX_FILENAME_LENGTH 1000 // Maximum length for file names
#define MAX_LINE_LENGTH 1033     // Maximum length for a line in the CSV file
#define num_threads 4

// Structure to hold a single virus signature entry
typedef struct
{
    char hash[HASH_SIZE];
    char reported_file[MAX_FILENAME_LENGTH];
} VirusSignature;

// Structure to hold the virus signature database
typedef struct
{
    VirusSignature signatures[MAX_SIGNATURES];
    int count;
} VirusSignatureDB;

// Function prototypes
void load_virus_signatures(VirusSignatureDB *db, const char *csv_file);
bool check_file_signature(const char *file_path, VirusSignatureDB *db);
void compute_md5(const char *file_path, char *output_buffer);

#endif
