#include <stdio.h>
#include <string.h>
#include "../include/virus_signature.h"
#include "../include/behavioral_analysis.h"
#include "virus_signature.c"
#include "behavioral_analysis.c"

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <virus_signatures.csv> <file_to_scan>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *csv_file = argv[1];
    const char *file_to_scan = argv[2];

    VirusSignatureDB db;
    load_virus_signatures(&db, csv_file);

    if (check_file_signature(file_to_scan, &db))
    {
        printf("Virus detected in %s!\n", file_to_scan);

        // Extract folder path from the file path
        char folder_path[MAX_PATH_LENGTH];
        strncpy(folder_path, file_to_scan, MAX_PATH_LENGTH);
        char *last_slash = strrchr(folder_path, '\\');
        if (last_slash)
            *last_slash = '\0'; // Trim to folder path

        // Start behavioral analysis on the folder
        // Extract the virus name from the file path
        char virus_name[MAX_PATH_LENGTH];
        strncpy(virus_name, file_to_scan, MAX_PATH_LENGTH);
        char *last_slash_virus = strrchr(virus_name, '\\');
        if (last_slash_virus)
        {
            memmove(virus_name, last_slash_virus + 1, strlen(last_slash_virus));
        }
        printf("Virus name: %s\n", virus_name);

        // Start behavioral analysis with the virus name
        start_behavior_analysis(folder_path, virus_name);
    }
    else
    {
        printf("No threats detected in %s.\n", file_to_scan);
    }
    return EXIT_SUCCESS;
}
