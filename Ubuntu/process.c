//////////////////////////// task1      ///////////////////////////////

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CPU_THRESHOLD 5.0

void check_processes()
{
    DIR *d = opendir("/proc");
    struct dirent *dir;
    struct stat st;

    if (d == NULL)
    {
        perror("opendir");
        return;
    }

    while ((dir = readdir(d)) != NULL)
    {
        char path[1024];
        snprintf(path, sizeof(path), "/proc/%s", dir->d_name);

        // Use stat to check if it's a directory
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode) && atoi(dir->d_name) > 0)
        {
            snprintf(path, sizeof(path), "/proc/%s/cmdline", dir->d_name);
            FILE *cmdline = fopen(path, "r");

            if (cmdline)
            {
                char command[256];
                fgets(command, sizeof(command), cmdline);
                printf("PID: %s, Command: %s\n", dir->d_name, command); // Print raw command

                if (strstr(command, "sleep") != NULL)
                {
                    printf("Suspicious process detected: PID %s, Command: %s\n", dir->d_name, command);
                }
                fclose(cmdline);
            }

            // Monitor CPU usage
            snprintf(path, sizeof(path), "/proc/%s/stat", dir->d_name);
            FILE *stat_file = fopen(path, "r");
            if (stat_file)
            {
                char buffer[1024];
                if (fgets(buffer, sizeof(buffer), stat_file))
                {
                    unsigned long utime, stime;
                    char comm[256];
                    int pid;
                    sscanf(buffer, "%d %s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %lu %lu",
                           &pid, comm, &utime, &stime);

                    // Calculating CPU usage (utime + stime converted to seconds)
                    double cpu_time = (double)(utime + stime) / sysconf(_SC_CLK_TCK);

                    if (cpu_time > CPU_THRESHOLD)
                    {
                        printf("High CPU usage detected: PID %d, Command: %s, CPU Time: %.2f seconds\n",
                               pid, comm, cpu_time);
                    }
                }
                fclose(stat_file);
            }
        }
    }
    closedir(d);
}



// For running task 2 comment out the first task and remove comment from sencond task

// ///////////////////////////// task 2 //////////////////////////


// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <dirent.h>
// #include <sys/stat.h>
// #include <unistd.h>

// // These are whitelist of common IPs and ports
// const char *whitelisted_ips[] = {
//     "0DADBD14", 
//     "BC76FDAC", 
//     NULL       
// };
// const int whitelisted_ports[] = {443, 80, 0}; // HTTPS, HTTP, (end with 0)


// // Function to check if an IP is in the whitelist
// int is_ip_whitelisted(const char *remote_address) {
//     for (int i = 0; whitelisted_ips[i] != NULL; i++) {
//         if (strcmp(remote_address, whitelisted_ips[i]) == 0) {
//             return 1; 
//         }
//     }
//     return 0;
// }

// // Function to check if a port is in the whitelist
// int is_port_whitelisted(int remote_port) {
//     for (int i = 0; whitelisted_ports[i] != 0; i++) {
//         if (remote_port == whitelisted_ports[i]) {
//             return 1; 
//         }
//     }
//     return 0; 
// }

// void check_network_activity(const char *pid) {
//     char path[1024];
//     snprintf(path, sizeof(path), "/proc/%s/net/tcp", pid);
//     FILE *tcp_file = fopen(path, "r");

//     if (!tcp_file) {
//         return; // Skip if the file doesn't exist (not all processes have network activity)
//     }

//     char line[256];
//     fgets(line, sizeof(line), tcp_file); 
//     while (fgets(line, sizeof(line), tcp_file)) {
//         char local_address[128], remote_address[128];
//         int local_port, remote_port, state;

//         // Parsing the line for network details
//         sscanf(line, " %*d: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%x %x",
//                local_address, &local_port, remote_address, &remote_port, &state);

//         // Skipping the connections that are not established
//         if (state != 1) { // State 1 = ESTABLISHED
//             continue;
//         }

//         // Checking if the remote IP or port is whitelisted
//         if (is_ip_whitelisted(remote_address) || is_port_whitelisted(remote_port)) {
//             continue; 
//         }

//         printf("Unusual network activity detected:\n");
//         printf("  PID: %s\n", pid);
//         printf("  Local Address: %s:%d\n", local_address, local_port);
//         printf("  Remote Address: %s:%d\n", remote_address, remote_port);
//     }

//     fclose(tcp_file);
// }
// void check_processes() {
//     DIR *d = opendir("/proc");
//     struct dirent *dir;
//     struct stat st;

//     if (d == NULL) {
//         perror("opendir");
//         return;
//     }

//     while ((dir = readdir(d)) != NULL) {
//         char path[1024];
//         snprintf(path, sizeof(path), "/proc/%s", dir->d_name);

//         if (stat(path, &st) == 0 && S_ISDIR(st.st_mode) && atoi(dir->d_name) > 0) {
//             snprintf(path, sizeof(path), "/proc/%s/cmdline", dir->d_name);
//             FILE *cmdline = fopen(path, "r");

//             if (cmdline) {
//                 char command[256];
//                 fgets(command, sizeof(command), cmdline);
//                 printf("PID: %s, Command: %s\n", dir->d_name, command);
//                 fclose(cmdline);

//                 if (strstr(command, "sleep") != NULL) {
//                     printf("Suspicious process detected: PID %s, Command: %s\n", dir->d_name, command);
//                 }

//                 // Checking for unusual network activity
//                 check_network_activity(dir->d_name);
//             }
//         }
//     }
//     closedir(d);
// }
