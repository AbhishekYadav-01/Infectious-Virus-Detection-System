#include <stdlib.h>

// Function to send email notification by calling the Python script
void send_email_notification(const char *virus_name, const char *folder_path, const char *hash)
{
    char command[512];
    snprintf(command, sizeof(command), "python send_email.py \"%s\" \"%s\" \"%s\"", virus_name, folder_path, hash);

    int result = system(command);
    if (result == 0)
    {
        printf("Email notification script executed successfully.\n");
    }
    else
    {
        printf("Failed to execute email notification script. Error code: %d\n", result);
    }
}
