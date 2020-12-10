
#include "uidmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <libproc.h>
#include <pwd.h>

/* UID Mapping 
   To do UID mapping (i.e. find the home directory for a particular UID) we 
   use a scoreboard of symlinks that obuilder generates during a build and 
   updates at the beginning of each build phase.

   So if user mac800 with uid 800 makes a request to mkdir /usr/local/foo then
   we use the scoreboard to lookup the home directory: 

     0. Get the calling Uid from FUSE context 
     1. Readlink "/scoreboard/<uid>" to get "/Volumes/tank..."
     2. Redirect to "/Volumes/tank.../foo"
*/

int get_user(uid_t uid, char *sb_path, char *result)
{
    /* AFAICT the handling of root and the default user is subtle. 
     * The problem is that if the FUSE filesystem internally tries to access 
     * either it's own mount point OR a file that doesn't exist and it fails 
     * then everything hangs, so instead we keep track of the last place to 
     * be successfully read and redirect these users there where they may 
     * not find what they are looking for but it doesn't break FUSE. 
     */
    if (uid == 0)
    {
        // For root
        return uid_root;
    }
    else if (uid <= 501)
    {
        return uid_other;
    }

    char buff[2048];
    char scoreboard[2048];

    // Uid to string
    char uid_num[10];
    snprintf(uid_num, 10, "%d", uid);
    printf("SB PATHS! %s\n", sb_path);
    // Create scoreboard symbolic link location
    strcpy(scoreboard, sb_path);
    strcat(scoreboard, "/");
    strcat(scoreboard, uid_num);
    printf("READING LINK! %s\n", scoreboard);
    // Read the link
    ssize_t len = readlink(scoreboard, buff, sizeof(buff) - 1);
    if (len != -1)
    {
        buff[len] = '\0';
        printf("RESULT: %s", buff);
        strcpy(result, buff);
        return uid_ok;
    }

    // printf("STRING TOO LONG!\n");
    return -errno;
}