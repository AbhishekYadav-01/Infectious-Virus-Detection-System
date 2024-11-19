#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <limits.h>
#include "alerts.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

void monitor_directory(const char *path) {
    int fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        exit(EXIT_FAILURE);
    }

    int wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE | IN_MODIFY);
    if (wd == -1) {
        printf("Could not watch : %s\n", path);
        return;
    } else {
        printf("Monitoring %s for changes...\n", path);
    }

    // Event loop
    char buffer[EVENT_BUF_LEN];
    while (1) {
        int length = read(fd, buffer, EVENT_BUF_LEN);
        if (length < 0) {
            perror("read");
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                if (event->mask & IN_CREATE) {
                    printf("File created: %s\n", event->name);
                } else if (event->mask & IN_DELETE) {
                    printf("File deleted: %s\n", event->name);
                } else if (event->mask & IN_MODIFY) {
                    printf("File modified: %s\n", event->name);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
}
