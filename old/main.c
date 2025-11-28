#include "../includes/virus.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

void list_files_recursive(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return;
    
    struct dirent *entry;
    struct stat statbuf;
    char full_path[4096];
    
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ". ") == 0 || strcmp(entry->d_name, ".. ") == 0)
            continue;
        
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        if (lstat(full_path, &statbuf) == -1)
            continue;
        
        if (S_ISDIR(statbuf.st_mode)) {
            list_files_recursive(full_path);
        } else if (S_ISREG(statbuf.st_mode)) {
            printf("%s\n", full_path);
        }
    }
    
    closedir(dir);
}

void list_directory(const char *directory) {
    struct stat statbuf;
    
    if (stat(directory, &statbuf) == -1 || !S_ISDIR(statbuf.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a valid directory\n", directory);
        exit(EXIT_FAILURE);
    }
    
    list_files_recursive(directory);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    list_directory(argv[1]);
    return EXIT_SUCCESS;
}

// int main()
// {
//     printf("Hello\n");
//
//     return EXIT_SUCCESS;
//     //  objdump -d decrypt.o -M intel -> gets instructions with bytes
// }
