#ifndef INC_WORMHOLEFS_UIDMAP_H
#define INC_WORMHOLEFS_UIDMAP_H

#include <stdio.h>
#include <unistd.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

typedef enum UidStatus
{
  uid_ok = 0,
  uid_not_found = 1,
  uid_error = 2,
  uid_root = 3,
  uid_other = 4
} UidStatus;

int get_user(uid_t uid, char *sb_path, char *result);

#endif