#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <ctype.h>
#include <libnotify/notify.h>
#include "alerts.h"
#include <libnotify/notification.h>

#define EVENT_SIZE  (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

// Whitelisted IPs and Ports
const char *whitelisted_ips[] = {
    "0DADBD14", 
    "BC76FDAC",
    "BC447D4A",
    NULL    
};
const int whitelisted_ports[] = {443, 80, 0,5228}; // 443 : HTTPS, 80 : HTTP

// Initialize notifications
void init_notifications() {
    if (!notify_init("Suspicious Activity Monitor")) {
        fprintf(stderr, "Failed to initialize notifications\n");
        exit(1);
    }
}

// Send desktop notification
void send_notification(const char *title, const char *message) {
    NotifyNotification *n = notify_notification_new(title, message, NULL);
    notify_notification_set_timeout(n, 5000); // Show for 5 seconds
    if (!notify_notification_show(n, NULL)) {
        fprintf(stderr, "Failed to send notification\n");
    }
    g_object_unref(G_OBJECT(n));
}

int is_ip_whitelisted(const char *remote_address) {
    for (int i = 0; whitelisted_ips[i] != NULL; i++) {
        if (strcmp(remote_address, whitelisted_ips[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_port_whitelisted(int remote_port) {
    for (int i = 0; whitelisted_ports[i] != 0; i++) {
        if (remote_port == whitelisted_ports[i]) {
            return 1;
        }
    }
    return 0;
}

// Function to monitor unusual network activity
void monitor_network_activity(const char *pid) {
    char path[1024];
    snprintf(path, sizeof(path), "/proc/%s/net/tcp", pid);
    FILE *tcp_file = fopen(path, "r");

    if (!tcp_file) {
        return; 
    }

    char line[256];
    fgets(line, sizeof(line), tcp_file); 

    while (fgets(line, sizeof(line), tcp_file)) {
        char local_address[128], remote_address[128];
        int local_port, remote_port, state;

        // Parse the line for network details
        sscanf(line, " %*d: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%x %x",
               local_address, &local_port, remote_address, &remote_port, &state);

        if (state != 1) {
            continue;
        }

        if (!is_ip_whitelisted(remote_address) && !is_port_whitelisted(remote_port)) {
            char details[512];
            snprintf(details, sizeof(details),
                     "PID: %s\nLocal Address: %s:%d\nRemote Address: %s:%d",
                     pid, local_address, local_port, remote_address, remote_port);
            display_alert("Unusual Network Activity", details);
            log_suspicious_activity("Unusual Network Activity", details);

            // Send desktop notification
            char notification_message[512];
            snprintf(notification_message, sizeof(notification_message),
                     "Local Address: %s:%d\nRemote Address: %s:%d",
                     local_address, local_port, remote_address, remote_port);
            send_notification("Unusual Network Activity", notification_message);
        }
    }

    fclose(tcp_file);
}

// Function to monitor file changes
void monitor_files(const char *path) {
    int length, i = 0;
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init failed");
        return;
    }

    int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_MODIFY);
    if (wd == -1) {
        perror("inotify_add_watch failed");
        close(fd);
        return;
    }

    char buffer[EVENT_BUF_LEN];
    while (1) {
        length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read failed");
            break;
        }

        i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            char details[256];

            if (event->len) {
                if (event->mask & IN_CREATE) {
                    snprintf(details, sizeof(details), "File created: %s", event->name);
                    display_alert("File Creation", details);
                    log_suspicious_activity("File Creation", details);
                    send_notification("File Creation", details);
                }
                if (event->mask & IN_DELETE) {
                    snprintf(details, sizeof(details), "File deleted: %s", event->name);
                    display_alert("File Deletion", details);
                    log_suspicious_activity("File Deletion", details);
                    send_notification("File Deletion", details);
                }
                if (event->mask & IN_MODIFY) {
                    snprintf(details, sizeof(details), "File modified: %s", event->name);
                    display_alert("File Modification", details);
                    log_suspicious_activity("File Modification", details);
                    send_notification("File Modification", details);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}

// Function to check if a command is suspicious
int is_suspicious_process(const char *command) {
    return (strstr(command, "sleep") != NULL);
}

int is_numeric(const char *str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit(str[i])) return 0;
    }
    return 1;
}

void monitor_processes() {
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        perror("opendir failed");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // Checking if the directory name is numeric (indicating a PID directory)
        if (is_numeric(entry->d_name)) {
            int pid = atoi(entry->d_name);
            char cmdline_path[256];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);

            FILE *cmdline_file = fopen(cmdline_path, "r");
            if (cmdline_file) {
                char command[256];
                if (fgets(command, sizeof(command), cmdline_file)) {
                    if (is_suspicious_process(command)) {
                        char details[512];
                        snprintf(details, sizeof(details), "PID: %d, Command: %.200s", pid, command);
                        display_alert("Suspicious Process", details);
                        log_suspicious_activity("Suspicious Process", details);
                        send_notification("Suspicious Process", details);
                    }

                    monitor_network_activity(entry->d_name);
                }
                fclose(cmdline_file);
            }
        }
    }

    closedir(proc_dir);
}

int main() {
    const char *path = "/home/abhishek/Desktop/OS/FolderForTask2";
  //     const char *path = "/home/abhishek/Desktop/OS/Project/Infectious_Virus_Detection_System";
    init_notifications(); // Initialize notifications

    if (fork() == 0) {
        monitor_files(path);
    } else {
        monitor_processes();
    }

    notify_uninit(); // Uninitialize notifications
    return 0;
}
