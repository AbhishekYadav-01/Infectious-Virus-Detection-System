#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "scan.h"
#include <openssl/evp.h>
#define THREAD_COUNT 4

typedef struct {
    char *hash;
    char *filename;
    int start_line;
    int end_line;
    int *found;
    pthread_mutex_t *mutex;
} ThreadArgs;


void hash_file(char *filename, unsigned char *outputBuffer) {
    unsigned char hash[EVP_MAX_MD_SIZE]; // MD5 hash size is smaller, but EVP_MAX_MD_SIZE is safe
    unsigned int hash_length = 0;
    FILE *file = fopen(filename, "rb");
    unsigned char data[1024];
    int bytes;

    if (file == NULL) {
        printf("Cannot open file: %s\n", filename);
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        printf("Failed to create EVP_MD_CTX\n");
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        printf("Failed to initialize digest\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    while ((bytes = fread(data, 1, 1024, file)) != 0) {
        if (EVP_DigestUpdate(mdctx, data, bytes) != 1) {
            printf("Failed to update digest\n");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hash_length) != 1) {
        printf("Failed to finalize digest\n");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return;
    }

    for (unsigned int i = 0; i < hash_length; i++) {
        sprintf(&outputBuffer[i * 2], "%02x", hash[i]);
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
}


// Thread function to search for the hash in a portion of the file
void *search_in_file(void *args) {
    ThreadArgs *data = (ThreadArgs *)args;
    FILE *file = fopen(data->filename, "r");
    if (!file) {
        perror("Error opening signatures file");
        pthread_exit(NULL);
    }

    char line[MD5_DIGEST_LENGTH * 2 + 1];
    int current_line = 0;

    while (fgets(line, sizeof(line), file)) {
        if (current_line >= data->start_line && current_line <= data->end_line) {
            line[strcspn(line, "\n")] = 0; 
            if (strcmp(line, data->hash) == 0) {
                pthread_mutex_lock(data->mutex);
                *(data->found) = 1; // Mark virus as found
                pthread_mutex_unlock(data->mutex);
                fclose(file);
                pthread_exit(NULL);
            }
        }
        current_line++;
        if (current_line > data->end_line) {
            break;
        }
    }

    fclose(file);
    pthread_exit(NULL);
}

// Multithreaded implementation of is_virus
int is_virus(char *hash) {
    FILE *file = fopen("signatures.txt", "r");
    if (!file) {
        perror("Cannot open signatures file");
        return 0;
    }

    // Count the total number of lines in the file
    int total_lines = 0;
    char temp[MD5_DIGEST_LENGTH * 2 + 1];
    while (fgets(temp, sizeof(temp), file)) {
        total_lines++;
    }
    fclose(file);

    // Split the lines among threads
    pthread_t threads[THREAD_COUNT];
    ThreadArgs args[THREAD_COUNT];
    int lines_per_thread = total_lines / THREAD_COUNT;
    int found = 0;
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);

    for (int i = 0; i < THREAD_COUNT; i++) {
        args[i].hash = hash;
        args[i].filename = "signatures.txt";
        args[i].start_line = i * lines_per_thread;
        args[i].end_line = (i == THREAD_COUNT - 1) ? total_lines - 1 : (i + 1) * lines_per_thread - 1;
        args[i].found = &found;
        args[i].mutex = &mutex;

        pthread_create(&threads[i], NULL, search_in_file, &args[i]);
    }

    // Wait for all threads to complete
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&mutex);
     return found;
 }

// Function to scan a file and check if it matches a virus signature
void scan_file(char *filename) {
    unsigned char hash[MD5_DIGEST_LENGTH * 2 + 1];
    hash_file(filename, hash);
    printf("File: %s\nHash: %s\n", filename, hash);

    if (is_virus(hash)) {
        printf("Virus detected in file: %s\n", filename);
    } else {
        printf("File is clean: %s\n", filename);
    }

}
