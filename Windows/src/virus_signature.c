#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <wincrypt.h> // For MD5 hashing
#include "../include/virus_signature.h"

// Structure for passing thread arguments
typedef struct
{
    char *file_hash;
    VirusSignatureDB *db;
    int start_idx;
    int end_idx;
    bool *found;         // Shared flag to indicate if a match was found
    char *detected_file; // Buffer to store the detected file name
    char *reported_file; // Buffer to store the reported file name
} ThreadArgs;

// Function to load virus signatures from a .csv file
void load_virus_signatures(VirusSignatureDB *db, const char *csv_file)
{
    FILE *file = fopen(csv_file, "r");
    if (!file)
    {
        perror("Failed to open virus signature file");
        exit(EXIT_FAILURE);
    }

    db->count = 0;
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file))
    {
        if (db->count >= MAX_SIGNATURES)
        {
            fprintf(stderr, "Reached maximum number of virus signatures.\n");
            break;
        }

        // Remove newline characters
        line[strcspn(line, "\r\n")] = '\0';

        char *hash = strtok(line, ",");
        char *reported_file = strtok(NULL, ",");

        if (hash && reported_file)
        {
            strncpy(db->signatures[db->count].hash, hash, HASH_SIZE - 1);
            db->signatures[db->count].hash[HASH_SIZE - 1] = '\0';
            strncpy(db->signatures[db->count].reported_file, reported_file, MAX_FILENAME_LENGTH - 1);
            db->signatures[db->count].reported_file[MAX_FILENAME_LENGTH - 1] = '\0';
            db->count++;
        }
    }

    fclose(file);
    printf("Loaded %d virus signatures from %s.\n", db->count, csv_file);
}

// Function to compute MD5 hash of a file
void compute_md5(const char *file_path, char *output_buffer)
{
    HANDLE file = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "Failed to open file for hashing: %s\n", file_path);
        exit(EXIT_FAILURE);
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[16];
    DWORD hash_len = 16;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        fprintf(stderr, "CryptAcquireContext failed.\n");
        CloseHandle(file);
        exit(EXIT_FAILURE);
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        fprintf(stderr, "CryptCreateHash failed.\n");
        CryptReleaseContext(hProv, 0);
        CloseHandle(file);
        exit(EXIT_FAILURE);
    }

    BYTE buffer[8192];
    DWORD bytes_read;
    while (ReadFile(file, buffer, sizeof(buffer), &bytes_read, NULL) && bytes_read > 0)
    {
        if (!CryptHashData(hHash, buffer, bytes_read, 0))
        {
            fprintf(stderr, "CryptHashData failed.\n");
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(file);
            exit(EXIT_FAILURE);
        }
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0))
    {
        fprintf(stderr, "CryptGetHashParam failed.\n");
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(file);
        exit(EXIT_FAILURE);
    }

    CloseHandle(file);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    // Convert hash to hexadecimal string
    for (DWORD i = 0; i < hash_len; i++)
    {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[HASH_SIZE - 1] = '\0'; // Null-terminate the string
}

// Thread function for parallel hash comparison
DWORD WINAPI compare_hashes(LPVOID args)
{
    ThreadArgs *thread_args = (ThreadArgs *)args;

    for (int i = thread_args->start_idx; i < thread_args->end_idx; i++)
    {
        if (*thread_args->found)
            return 0; // Exit if a match has already been found

        if (strcmp(thread_args->file_hash, thread_args->db->signatures[i].hash) == 0)
        {
            *thread_args->found = TRUE;
            strncpy(thread_args->detected_file, thread_args->db->signatures[i].reported_file, MAX_FILENAME_LENGTH - 1);
            thread_args->detected_file[MAX_FILENAME_LENGTH - 1] = '\0';
            strncpy(thread_args->reported_file, thread_args->db->signatures[i].reported_file, MAX_FILENAME_LENGTH - 1);
            thread_args->reported_file[MAX_FILENAME_LENGTH - 1] = '\0';
            return 0;
        }
    }

    return 0;
}

// Function to check file signature against the virus signature database
bool check_file_signature(const char *file_path, VirusSignatureDB *db)
{
    char file_hash[HASH_SIZE];
    compute_md5(file_path, file_hash);

    HANDLE threads[num_threads];
    ThreadArgs thread_args[num_threads];

    bool found = FALSE;
    char detected_file[MAX_FILENAME_LENGTH] = {0};
    char reported_file[MAX_FILENAME_LENGTH] = {0};

    int signatures_per_thread = db->count / num_threads;
    if (db->count % num_threads != 0)
    {
        signatures_per_thread++;
    }

    // Create threads
    for (int i = 0; i < num_threads; i++)
    {
        thread_args[i].file_hash = file_hash;
        thread_args[i].db = db;
        thread_args[i].start_idx = i * signatures_per_thread;
        thread_args[i].end_idx = (i + 1) * signatures_per_thread;
        if (thread_args[i].end_idx > db->count)
        {
            thread_args[i].end_idx = db->count;
        }
        thread_args[i].found = &found;
        thread_args[i].detected_file = detected_file;
        thread_args[i].reported_file = reported_file;

        threads[i] = CreateThread(NULL, 0, compare_hashes, &thread_args[i], 0, NULL);
    }

    // Wait for all threads to complete
    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

    for (int i = 0; i < num_threads; i++)
    {
        CloseHandle(threads[i]);
    }

    if (found)
    {
        printf("Virus detected in file: %s\n", file_path);
        printf("Detected File: %s\n", detected_file);
        printf("Reported as: %s\n", reported_file);
        return TRUE;
    }

    printf("File is clean: %s\n", file_path);
    return FALSE;
}
