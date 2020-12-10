
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

int get_user(uid_t uid, char *result)
{
    // Handle root and default user
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

    // Create scoreboard symbolic link location
    strcpy(scoreboard, "/Users/patrickferris/scoreboard/");
    strcat(scoreboard, uid_num);

    printf("READING LINK %s", scoreboard);

    // Read the link
    ssize_t len = readlink(scoreboard, buff, sizeof(buff) - 1);
    if (len != -1)
    {
        buff[len] = '\0';
        printf("RETURNING %s\n", buff);
        strcpy(result, buff);
        return uid_ok;
    }

    printf("STRING TOO LONG!\n");
    return -errno;
}