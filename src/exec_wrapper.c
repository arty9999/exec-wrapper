/*
 *  MIT License
 *
 *  Copyright (c) 2019 Art Perry
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>

#define CONF_FILE_PREFIX "/etc/exec_wrapper"
#define MAX_PATH_LEN 128

static int (*rl_execl)(const char *path, const char *arg, ...);
static int (*rl_execlp)(const char *file, const char *arg, ...);
static int (*rl_execle)(const char *path, const char *arg, ...);
static int (*rl_execv)(const char *path, char *const argv[]);
static int (*rl_execvp)(const char *file, char *const argv[]);
static int (*rl_execvpe)(const char *file, char *const argv[], char *const envp[]);
static int (*rl_execve)(const char *filename, char *const argv[], char *const envp[]);
static int (*rl_execveat)(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
static int (*rl_fexecve)(int fd, char *const argv[], char *const envp[]);


static bool validate(const char* full_path)
{
    openlog(__FILE__, LOG_PID | LOG_PERROR | LOG_ODELAY, LOG_USER);
    bool retval = true;
    struct passwd* pw = NULL;
    uid_t uid = getuid();
    if ((pw = getpwuid(uid)) == NULL) {
        syslog(LOG_NOTICE, "exec_wrapper: Unknown user %i. Disallowing access to %s\n", uid, full_path);
        closelog();
        return false;
    }

    char conffile[75];
    snprintf(conffile, sizeof(conffile), "%s/%s.conf", CONF_FILE_PREFIX, pw->pw_name);

    FILE* fl = fopen(conffile, "r");
    if (!fl) {
        // syslog(LOG_NOTICE, "exec_wrapper: no conf file %s, granting access.", conffile);
        closelog();
        return true; // if no config file, then grant access to all
    }

    const char* basename;
    basename = strrchr(full_path, '/');
    if (basename == NULL)
        basename = full_path;
    else
        basename++;

    if (strcmp(basename, "bash") == 0) {
        full_path = "/usr/local/bin/cbash";
        return true;
    }

    enum Mode {
        MODE_ALLOW, MODE_DENY
    } mode = MODE_DENY;

    char lbuf[MAX_PATH_LEN];
    while (fgets(lbuf, sizeof(lbuf), fl)) {
        if ((lbuf[0] == '#') || (lbuf[0] == '\n')) continue;
        if (strcmp("allow:\n", lbuf) == 0) {
            mode = MODE_ALLOW;
            retval = false; // default policy is now to deny
            continue;
        }
        if (strcmp("deny:\n", lbuf) == 0) {
            mode = MODE_DENY;
            retval = true; // default policy is now to allow
            continue;
        }
        size_t lbuf_len = strlen(lbuf);
        if (lbuf[lbuf_len-1] == '\n') lbuf_len--;
        if ((mode == MODE_ALLOW) && (strncmp(lbuf, basename, lbuf_len) == 0)) {
            retval = true;
            break;
        }
        if ((mode == MODE_DENY) && (strncmp(lbuf, basename, lbuf_len) == 0)) {
            retval = false;
            break;
        }
    }
    fclose(fl);
    if (retval == false) {
        errno = EACCES;
        syslog(LOG_NOTICE, "exec_wrapper: BZZZ!! User %s is not allowed to execute %s\n", pw->pw_name, full_path);
    }
    closelog();
    return retval;
}


int execl(const char *path, const char *arg, ...)
{
    char* lpath = strndup(path, MAX_PATH_LEN);
    if (!validate(lpath)) {
        free(lpath);
        return -1;
    }
    va_list aptr;
    va_start(aptr, arg);
    rl_execv = dlsym(RTLD_NEXT, "execl");
    int retval = rl_execl(lpath, arg, aptr);
    va_end(aptr);
    free(lpath);
    return retval;
}

int execlp(const char *file, const char *arg, ...)
{
    char* lfile = strndup(file, MAX_PATH_LEN);
    if (!validate(lfile)) {
        free(lfile);
        return -1;
    }
    va_list aptr;
    va_start(aptr, arg);
    rl_execlp = dlsym(RTLD_NEXT, "execlp");
    int retval = rl_execlp(lfile, arg, aptr);
    va_end(aptr);
    free(lfile);
    return retval;
}

int execle(const char *path, const char *arg, ...)
{
    char* lpath = strndup(path, MAX_PATH_LEN);
    if (!validate(lpath)) {
        free(lpath);
        return -1;
    }
    va_list aptr;
    va_start(aptr, arg);
    rl_execle = dlsym(RTLD_NEXT, "execle");
    int retval = rl_execle(lpath, arg, aptr);
    va_end(aptr);
    free(lpath);
    return retval;
}

int execv(const char *path, char *const argv[])
{
    char* lpath = strndup(path, MAX_PATH_LEN);
    if (!validate(lpath)) {
        free(lpath);
        return -1;
    }
    rl_execv = dlsym(RTLD_NEXT, "execv");
    int retval = rl_execv(lpath, argv);
    free(lpath);
    return retval;
}

int execvp(const char *file, char *const argv[])
{
    char* lfile = strndup(file, MAX_PATH_LEN);
    if (!validate(lfile)) {
        free(lfile);
        return -1;
    }
    rl_execvp = dlsym(RTLD_NEXT, "execvp");
    int retval = rl_execvp(lfile, argv);
    free(lfile);
    return retval;
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    char* lfile = strndup(file, MAX_PATH_LEN);
    if (!validate(lfile)) {
        free(lfile);
        return -1;
    }
    rl_execvpe = dlsym(RTLD_NEXT, "execvpe");
    int retval = rl_execvpe(lfile, argv, envp);
    free(lfile);
    return retval;
}

int execve(const char *filename, char *const argv[], char *const envp[])
{
    char* lfilename = strndup(filename, MAX_PATH_LEN);
    if (!validate(lfilename)) {
        free(lfilename);
        return -1;
    }
    rl_execve = dlsym(RTLD_NEXT, "execve");
    int retval = rl_execve(lfilename, argv, envp);
    free(lfilename);
    return retval;
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
{
    char* lpathname = strndup(pathname, MAX_PATH_LEN);
    if (!validate(lpathname)) {
        free(lpathname);
        return -1;
    }
    rl_execveat = dlsym(RTLD_NEXT, "execveat");
    int retval = rl_execveat(dirfd, lpathname, argv, envp, flags);
    free(lpathname);
    return retval;
}

// TODO:This needs filtering on fd.
int fexecve(int fd, char *const argv[], char *const envp[])
{
    char* lpath = strndup(argv[0], MAX_PATH_LEN);
    if (!validate(lpath)) {
        free(lpath);
        return -1;
    }
    rl_fexecve = dlsym(RTLD_NEXT, "fexecve");
    int retval = rl_fexecve(fd, argv, envp);
    free(lpath);
    return retval;
}

