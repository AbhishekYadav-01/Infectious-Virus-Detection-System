//////////// Task 1 ///////////

#include <stdio.h>
#include "scan.h"
#include "process.h"

int main() {
    printf("Starting file scan...\n");
    scan_file("/home/abhishek/Desktop/OS/Datasets/eicar.com");  
    printf("\nStarting process scan...\n");
    check_processes();

    return 0;
}
// For running task 2 comment out the first task and remove comment from sencond task
// ///////////////////////////// task 2 //////////////////////////


// #include <stdio.h>
// #include <stdlib.h>
// #include <unistd.h>
// #include <sys/types.h>
// #include <sys/wait.h>

// void monitor_directory(const char *path);
// void check_processes();

// int main() {
//     const char *path = "/home/abhishek/Desktop/OS/FolderForTask2"; 
//     if (fork() == 0) {
//         monitor_directory(path);
//         exit(0);
//     }

//     while (1) {
//     printf("Starting process and network activity scan...\n");
//         check_processes();
//         sleep(30);
//     }

//     return 0;
// }


