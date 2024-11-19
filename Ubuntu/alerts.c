#include "alerts.h"
#include <stdlib.h>
#include <string.h>



void log_suspicious_activity(const char *activity_type, const char *details) {
    FILE *log_file = fopen("suspicious_activity.log", "a");
    if (log_file == NULL) {
        perror("Unable to open log file");
        return;
    }
    time_t now;
    time(&now);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';  // Remove newline character

    fprintf(log_file, "[%s] %s: %s\n", timestamp, activity_type, details);
    fclose(log_file);
}

void display_alert(const char *activity_type, const char *details) {
    printf("ALERT: %s detected - %s\n", activity_type, details);
}
