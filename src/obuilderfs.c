/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 */

#define FUSE_USE_VERSION 26
#define HAVE_SETXATTR 1
#define _DARWIN_BETTER_REALPATH

#define DEBUG

// Enable this along with the -d option to get more path-related printing
#ifdef DEBUG
#define DEBUG_PRINT(x) printf x
#else
#define DEBUG_PRINT(x) \
	do                   \
	{                    \
	} while (0)
#endif

#include "uidmap.h"
#include <sys/syslimits.h>
#include <fcntl.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#else
#define _GNU_SOURCE
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <sys/file.h> /* flock(2) */

#include <sys/param.h>

#ifdef __APPLE__

#include <fcntl.h>
#include <sys/vnode.h>

#if defined(_POSIX_C_SOURCE)
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
and
#endif

#include <sys/attr.h>

#define G_PREFIX "org"
#define G_KAUTH_FILESEC_XATTR G_PREFIX ".apple.system.Security"
#define A_PREFIX "com"
#define A_KAUTH_FILESEC_XATTR A_PREFIX ".apple.system.Security"
#define XATTR_APPLE_PREFIX "com.apple."

#endif /* __APPLE__ */
/* Apple Structs */
#ifdef __APPLE__
#include <sys/param.h>
#define G_PREFIX "org"
#define G_KAUTH_FILESEC_XATTR G_PREFIX ".apple.system.Security"
#define A_PREFIX "com"
#define A_KAUTH_FILESEC_XATTR A_PREFIX ".apple.system.Security"
#define XATTR_APPLE_PREFIX "com.apple."
		int
		flock(int fd, int operation);
#endif

static char root_dest[1024];

static struct Conf
{
	char *scoreboard; // The path to the readlink scoreboard
} conf;

char *process_path(const char *path, bool resolve_symlinks)
{
	char result[256];
	struct fuse_context *fc = fuse_get_context();
	int status = get_user(fc->uid, conf.scoreboard, result);
	DEBUG_PRINT(("RESULT %s for UID %i (status: %i)\n", result, fc->uid, status));

	// Status 5 -- readlink failed, return a directory we are sure exists
	if (status == no_link)
	{
		return strdup(conf.scoreboard);
	}

	if (status == uid_error || status == uid_not_found)
	{
		fuse_exit(fuse_get_context()->fuse);
	}

	if (status == uid_ok)
	{
		// There's probably a defined length to be using somewhere
		char userpath[2048];
		DEBUG_PRINT(("Initial path is: %s\n Path is: %s\n", userpath, path));
		strcpy(userpath, result);
		DEBUG_PRINT(("Userpath is: %s\n", userpath));
		strcat(userpath, "/local");

		// Record this in the settings
		strcpy(root_dest, userpath);

		// Resolve symlinks
		if (resolve_symlinks)
		{
			DEBUG_PRINT(("PATH IS %s\n", path));

			strcat(userpath, path);
			DEBUG_PRINT(("Processed path is: %s\n", userpath));
			char *resolved;

			resolved = realpath(userpath, NULL);
			// Add the resolved path
			if (resolved == NULL)
			{
				if (errno == ENOENT)
				{
					DEBUG_PRINT(("Processed path is: %s\n", userpath));
					return strdup(userpath);
				}
			}
			else
			{
				DEBUG_PRINT(("Processed path is: %s\n", userpath));
				free(resolved);
				return strdup(resolved);
			}
		}

		// No symlink resolution -- Add the rest of the path
		DEBUG_PRINT(("PATH IS %s\n", path));

		strcat(userpath, path);
		DEBUG_PRINT(("Processed path is: %s\n", userpath));
		return strdup(userpath);
	}
	else
	{
		// HACK: Copy what hopefully was the last calling User location
		char userpath[2048];
		DEBUG_PRINT(("Root destination path is: %s\n", root_dest));
		strcpy(userpath, root_dest);
		strcat(userpath, path);
		DEBUG_PRINT(("Together destination path is: %s\n", userpath));

		// Double check it still exists
		int res = access(userpath, R_OK);

		// Doesn't exist -- return null
		if (res < 0)
		{
			printf("Doesn't exist (obuilderfs): %s\n", userpath);
			return NULL;
		}

		return strdup(userpath);
	}
}

static int obuilder_getattr(const char *path, struct stat *stbuf)
{
	int res;

	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to resolve attr for %s\n", path));
		return -errno;
	}

	DEBUG_PRINT(("Getting attributes for %s but really %s\n", path, new_path));

	res = lstat(new_path, stbuf);

	if (res == -1)
	{
		free(new_path);
		DEBUG_PRINT(("lstat failed for %s but really %s\n", path, new_path));
		return -errno;
	}

	free(new_path);
	return 0;
}

static int obuilder_fgetattr(const char *path, struct stat *stbuf,
														 struct fuse_file_info *fi)
{
	int res;
	char *real_path;

	real_path = process_path(path, false);
	if (real_path == NULL)
		return -errno;

	res = fstat(fi->fh, stbuf);

	if (res == -1)
	{
		free(real_path);
		return -errno;
	}
	free(real_path);
	return res;
}

static int obuilder_access(const char *path, int mask)
{
	int res;
	char *new_path = process_path(path, false);
	res = access(new_path, mask);
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return 0;
}

static int obuilder_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char *new_path = process_path(path, false);
	DEBUG_PRINT(("READING LINK %s and got %s\n", path, new_path));
	res = readlink(new_path, buf, size - 1);
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	buf[res] = '\0';
	free(new_path);
	return 0;
}

struct obuilder_dirp
{
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static inline struct obuilder_dirp *get_dirp(struct fuse_file_info *fi)
{
	return (struct obuilder_dirp *)(uintptr_t)fi->fh;
}

static int obuilder_opendir(const char *path, struct fuse_file_info *fi)
{
	int res;

	char *new_path = process_path(path, false);

	struct obuilder_dirp *d = malloc(sizeof(struct obuilder_dirp));
	if (d == NULL)
		return -ENOMEM;

	d->dp = opendir(new_path);
	if (d->dp == NULL)
	{
		res = -errno;
		free(d);
		free(new_path);
		return res;
	}
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (unsigned long)d;
	free(new_path);
	return 0;
}

static int obuilder_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
														off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void)offset;
	(void)fi;

	char *new_path = process_path(path, false);

	dp = opendir(new_path);
	if (dp == NULL)
	{
		free(new_path);
		return -errno;
	}

	while ((de = readdir(dp)) != NULL)
	{
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	free(new_path);
	return 0;
}

static int obuilder_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct obuilder_dirp *d = get_dirp(fi);
	(void)path;
	closedir(d->dp);
	free(d);
	return 0;
}

static int obuilder_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char *new_path = process_path(path, false);

	if (S_ISFIFO(mode))
		res = mkfifo(new_path, mode);
	else
		res = mknod(new_path, mode, rdev);

	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return 0;
}

static int obuilder_mkdir(const char *path, mode_t mode)
{
	int res;
	char *new_path = process_path(path, false);
	res = mkdir(new_path, mode);
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return 0;
}

static int delete_file(const char *path, int (*target_delete_func)(const char *))
{
	int res;
	char *real_path;
	struct stat st;
	char *also_try_delete = NULL;
	// char *unlink_first = NULL;
	int (*main_delete_func)(const char *) = target_delete_func;

	real_path = process_path(path, false);
	if (real_path == NULL)
	{
		DEBUG_PRINT(("FAILED TO GET REAL PATH %s\n", path));
		return -errno;
	}

	if (lstat(real_path, &st) == -1)
	{
		free(real_path);
		return -errno;
	}

	if (S_ISLNK(st.st_mode))
	{
		main_delete_func = &unlink;
	}

	res = main_delete_func(real_path);
	free(real_path);
	if (res == -1)
	{
		free(also_try_delete);
		return -errno;
	}

	if (also_try_delete != NULL)
	{
		(void)target_delete_func(also_try_delete);
		free(also_try_delete);
	}

	return 0;
}

static int obuilder_unlink(const char *path)
{
	return delete_file(path, &unlink);
}

static int obuilder_rmdir(const char *path)
{
	return delete_file(path, &rmdir);
}

static int obuilder_symlink(const char *from, const char *to)
{
	int res;

	char *new_to = process_path(to, false);
	if (new_to == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for symlinking\n", new_to));
		return -errno;
	}

	res = symlink(from, new_to);
	if (res == -1)
	{
		free(new_to);
		return -errno;
	}
	free(new_to);
	return 0;
}

static int obuilder_rename(const char *from, const char *to)
{
	int res;

	char *new_from = process_path(from, false);
	if (new_from == NULL)
		return -errno;

	char *new_to = process_path(to, false);
	if (new_to == NULL)
	{
		free(new_from);
		return -errno;
	}

	res = rename(new_from, new_to);

	if (res == -1)
	{
		free(new_from);
		free(new_to);
		return -errno;
	}

	free(new_from);
	free(new_to);
	return 0;
}

#ifdef __APPLE__

static int obuilder_setvolname(const char *volname)
{
	(void)volname;
	return 0;
}

static int obuilder_exchange(const char *path1, const char *path2,
														 unsigned long options)
{
	int res;
	char *new_path1 = process_path(path1, false);
	char *new_path2 = process_path(path2, false);

	if (new_path1 == NULL || new_path2 == NULL)
	{
		DEBUG_PRINT(("Failed to get %s or %s for exchanging\n", path1, path2));
		return -errno;
	}

	res = exchangedata(new_path1, new_path2, options);
	if (res == -1)
	{
		free(new_path1);
		free(new_path2);
		return -errno;
	}

	free(new_path1);
	free(new_path2);

	return 0;
}

#endif /* __APPLE__ */

static int obuilder_link(const char *from, const char *to)
{
	int res;

	char *new_from = process_path(from, false);
	char *new_to = process_path(to, false);

	if (new_from == NULL || new_to == NULL)
	{
		DEBUG_PRINT(("Failed to get %s or %s for linking\n", new_from, new_to));
		return -errno;
	}

	res = link(new_from, new_to);
	if (res == -1)
	{
		free(new_from);
		free(new_to);
		return -errno;
	}

	free(new_from);
	free(new_to);

	return 0;
}

static int obuilder_chmod(const char *path, mode_t mode)
{
	int res;
	char *new_path = process_path(path, false);
	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for chmoding\n", new_path));
		return -errno;
	}

#ifdef __APPLE__
	res = lchmod(new_path, mode);
#else
	res = chmod(new_path, mode);
#endif
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return 0;
}

static int obuilder_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char *new_path = process_path(path, false);
	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for chowning\n", new_path));
		return -errno;
	}

	res = lchown(new_path, uid, gid);
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}
	free(new_path);
	return 0;
}

static int obuilder_truncate(const char *path, off_t size)
{
	int res;
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for truncating\n", new_path));
		return -errno;
	}

	res = truncate(new_path, size);
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	return 0;
}

static int obuilder_ftruncate(const char *path, off_t size,
															struct fuse_file_info *fi)
{
	int res;

	(void)path;

	// Using a file handle okay?
	res = ftruncate(fi->fh, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int obuilder_utimens(const char *path, const struct timespec ts[2])
{
	// int res;
	return 0;

	// char *new_path = process_path(path, true);

	// struct timeval tv[2];
	// tv[0].tv_sec = ts[0].tv_sec;
	// tv[0].tv_usec = ts[0].tv_nsec / 1000;
	// tv[1].tv_sec = ts[1].tv_sec;
	// tv[1].tv_usec = ts[1].tv_nsec / 1000;
	// res = lutimes(new_path, tv);
	// if (res == -1)
	// {
	// 	free(new_path);
	// 	return -errno;
	// }

	// free(new_path);
	return 0;
}

static int obuilder_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for creating\n", new_path));
		return -errno;
	}

	fd = open(new_path, fi->flags, mode);
	if (fd == -1)
	{
		free(new_path);
		return -errno;
	}

	fi->fh = fd;
	free(new_path);
	return 0;
}

static int obuilder_open(const char *path, struct fuse_file_info *fi)
{
	int fd;
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for opening\n", new_path));
		return -errno;
	}

	fd = open(new_path, fi->flags);
	if (fd == -1)
	{
		free(new_path);
		return -errno;
	}

	fi->fh = fd;
	free(new_path);
	return 0;
}

static int obuilder_read(const char *path, char *buf, size_t size, off_t offset,
												 struct fuse_file_info *fi)
{
	int res;

	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for reading\n", new_path));
		return -errno;
	}

	int fd = open(new_path, fi->flags);
	// File handle okay?
	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	free(new_path);

	return res;
}

static int obuilder_read_buf(const char *path, struct fuse_bufvec **bufp,
														 size_t size, off_t offset, struct fuse_file_info *fi)
{
	struct fuse_bufvec *src;

	(void)path;

	src = malloc(sizeof(struct fuse_bufvec));
	if (src == NULL)
		return -ENOMEM;

	*src = FUSE_BUFVEC_INIT(size);

	src->buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	src->buf[0].fd = fi->fh;
	src->buf[0].pos = offset;

	*bufp = src;

	return 0;
}

static int obuilder_write(const char *path, const char *buf, size_t size,
													off_t offset, struct fuse_file_info *fi)
{
	int res;

	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for writing\n", new_path));
		return -errno;
	}

	int fd = open(new_path, fi->flags);

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
	{
	}
	res = -errno;

	close(fd);
	free(new_path);

	return res;
}

static int obuilder_write_buf(const char *path, struct fuse_bufvec *buf,
															off_t offset, struct fuse_file_info *fi)
{
	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

	(void)path;

	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = offset;

	return fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
}

static int obuilder_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for statfs-ing\n", new_path));
		return -errno;
	}

	res = statvfs(new_path, stbuf);
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return 0;
}

static int obuilder_flush(const char *path, struct fuse_file_info *fi)
{
	int res;

	(void)path;
	/* This is called from every close on an open file, so call the
	   close on the underlying filesystem.	But since flush may be
	   called multiple times for an open file, this must not really
	   close the file.  This is important if used on a network
	   filesystem like NFS which flush the data/metadata on close() */
	res = close(dup(fi->fh));
	if (res == -1)
		return -errno;

	return 0;
}

static int obuilder_release(const char *path, struct fuse_file_info *fi)
{
	(void)path;
	close(fi->fh);

	return 0;
}

static int obuilder_fsync(const char *path, int isdatasync,
													struct fuse_file_info *fi)
{
	int res;
	(void)path;

#ifndef HAVE_FDATASYNC
	(void)isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
	res = fsync(fi->fh);
	if (res == -1)
		return -errno;

	return 0;
}

#if defined(HAVE_POSIX_FALLOCATE) || defined(__APPLE__)
static int obuilder_fallocate(const char *path, int mode,
															off_t offset, off_t length, struct fuse_file_info *fi)
{
#ifdef __APPLE__
	fstore_t fstore;

	if (!(mode & PREALLOCATE))
		return -ENOTSUP;

	fstore.fst_flags = 0;
	if (mode & ALLOCATECONTIG)
		fstore.fst_flags |= F_ALLOCATECONTIG;
	if (mode & ALLOCATEALL)
		fstore.fst_flags |= F_ALLOCATEALL;

	if (mode & ALLOCATEFROMPEOF)
		fstore.fst_posmode = F_PEOFPOSMODE;
	else if (mode & ALLOCATEFROMVOL)
		fstore.fst_posmode = F_VOLPOSMODE;

	fstore.fst_offset = offset;
	fstore.fst_length = length;

	if (fcntl(fi->fh, F_PREALLOCATE, &fstore) == -1)
		return -errno;
	else
		return 0;
#else
	(void)path;

	if (mode)
		return -EOPNOTSUPP;

	return -posix_fallocate(fi->fh, offset, length);
#endif
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
#ifdef __APPLE__
static int obuilder_setxattr(const char *path, const char *name, const char *value,
														 size_t size, int flags, uint32_t position)
#else
static int obuilder_setxattr(const char *path, const char *name, const char *value,
														 size_t size, int flags)
#endif
{
#ifdef __APPLE__
	int res;
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for setattrx-ing\n", new_path));
		return -errno;
	}

	if (!strncmp(name, XATTR_APPLE_PREFIX, sizeof(XATTR_APPLE_PREFIX) - 1))
	{
		flags &= ~(XATTR_NOSECURITY);
	}
	if (!strcmp(name, A_KAUTH_FILESEC_XATTR))
	{
		char new_name[MAXPATHLEN];
		memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
		memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
		res = setxattr(new_path, new_name, value, size, position, flags);
	}
	else
	{
		res = setxattr(new_path, name, value, size, position, flags);
	}
#else
	int res = lsetxattr(new_path, name, value, size, flags);
#endif
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}
	free(new_path);
	return 0;
}

#ifdef __APPLE__
static int obuilder_getxattr(const char *path, const char *name, char *value,
														 size_t size, uint32_t position)
#else
static int obuilder_getxattr(const char *path, const char *name, char *value,
														 size_t size)
#endif
{
#ifdef __APPLE__
	int res;
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for getattrx-ing\n", new_path));
		return -errno;
	}

	if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0)
	{
		char new_name[MAXPATHLEN];
		memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
		memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
		res = getxattr(new_path, new_name, value, size, position, XATTR_NOFOLLOW);
	}
	else
	{
		res = getxattr(new_path, name, value, size, position, XATTR_NOFOLLOW);
	}
#else
	int res = lgetxattr(new_path, name, value, size);
#endif
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return res;
}

static int obuilder_listxattr(const char *path, char *list, size_t size)
{
#ifdef __APPLE__
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for listxattr-ing\n", new_path));
		return -errno;
	}
	ssize_t res = listxattr(new_path, list, size, XATTR_NOFOLLOW);
	if (res > 0)
	{
		if (list)
		{
			size_t len = 0;
			char *curr = list;
			do
			{
				size_t thislen = strlen(curr) + 1;
				if (strcmp(curr, G_KAUTH_FILESEC_XATTR) == 0)
				{
					memmove(curr, curr + thislen, res - len - thislen);
					res -= thislen;
					break;
				}
				curr += thislen;
				len += thislen;
			} while (len < res);
		}
		else
		{
			/*
			ssize_t res2 = getxattr(path, G_KAUTH_FILESEC_XATTR, NULL, 0, 0,
						XATTR_NOFOLLOW);
			if (res2 >= 0) {
				res -= sizeof(G_KAUTH_FILESEC_XATTR);
			}
			*/
		}
	}
#else
	int res = llistxattr(new_path, list, size);
#endif
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return res;
}

static int obuilder_removexattr(const char *path, const char *name)
{
#ifdef __APPLE__
	int res;
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for removeattr-ing\n", new_path));
		return -errno;
	}

	if (strcmp(name, A_KAUTH_FILESEC_XATTR) == 0)
	{
		char new_name[MAXPATHLEN];
		memcpy(new_name, A_KAUTH_FILESEC_XATTR, sizeof(A_KAUTH_FILESEC_XATTR));
		memcpy(new_name, G_PREFIX, sizeof(G_PREFIX) - 1);
		res = removexattr(new_path, new_name, XATTR_NOFOLLOW);
	}
	else
	{
		res = removexattr(new_path, name, XATTR_NOFOLLOW);
	}
#else
	int res = lremovexattr(new_path, name);
#endif
	if (res == -1)
	{
		free(new_path);
		return -errno;
	}

	free(new_path);
	return 0;
}
#endif /* HAVE_SETXATTR */

static int obuilder_lock(const char *path, struct fuse_file_info *fi, int cmd,
												 struct flock *lock)
{
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for locking\n", new_path));
		return -errno;
	}

	int fd = open(new_path, fi->flags);

	int res;
	res = fcntl(fd, cmd);
	if (res == -1)
	{
		close(fd);
		free(new_path);
		return -errno;
	}
	close(fd);
	free(new_path);
	return res;
}

static int obuilder_flock(const char *path, struct fuse_file_info *fi, int op)
{
	char *new_path = process_path(path, false);

	if (new_path == NULL)
	{
		DEBUG_PRINT(("Failed to get %s for flocking\n", new_path));
		return -errno;
	}

	int fd = open(new_path, fi->flags);

	int res;
	res = flock(fd, op);

	if (res == -1)
	{
		close(fd);
		free(new_path);
		return -errno;
	}

	close(fd);
	free(new_path);
	return res;
}

void *
obuilder_init(struct fuse_conn_info *conn)
{
#ifdef __APPLE__
	FUSE_ENABLE_SETVOLNAME(conn);
	FUSE_ENABLE_XTIMES(conn);
#endif
	return NULL;
}

void obuilder_destroy(void *userdata)
{
}

static struct fuse_operations obuilder_oper = {
		.init = obuilder_init,
		.destroy = obuilder_destroy,
		.getattr = obuilder_getattr,
		.fgetattr = obuilder_fgetattr,
		.access = obuilder_access,
		.readlink = obuilder_readlink,
		.opendir = obuilder_opendir,
		.readdir = obuilder_readdir,
		.releasedir = obuilder_releasedir,
		.mknod = obuilder_mknod,
		.mkdir = obuilder_mkdir,
		.symlink = obuilder_symlink,
		.unlink = obuilder_unlink,
		.rmdir = obuilder_rmdir,
		.rename = obuilder_rename,
		.link = obuilder_link,
		.chmod = obuilder_chmod,
		.chown = obuilder_chown,
		.truncate = obuilder_truncate,
		.ftruncate = obuilder_ftruncate,
		.utimens = obuilder_utimens,
		.create = obuilder_create,
		.open = obuilder_open,
		.read = obuilder_read,
		.read_buf = obuilder_read_buf,
		.write = obuilder_write,
		.write_buf = obuilder_write_buf,
		.statfs = obuilder_statfs,
		.flush = obuilder_flush,
		.release = obuilder_release,
		.fsync = obuilder_fsync,
#if defined(HAVE_POSIX_FALLOCATE) || defined(__APPLE__)
		.fallocate = obuilder_fallocate,
#endif
#ifdef HAVE_SETXATTR
		.setxattr = obuilder_setxattr,
		.getxattr = obuilder_getxattr,
		.listxattr = obuilder_listxattr,
		.removexattr = obuilder_removexattr,
#endif
		// NOT IMPLEMENTED BUT LEAVING ANYWAY
		.lock = obuilder_lock,
		.flock = obuilder_flock,

		// These were causing issues: cp : lutimes ...
		// Removed for now, might need to bring them back in the future
		// .setvolname = obuilder_setvolname,
		// .exchange = obuilder_exchange,
		// .getxtimes = obuilder_getxtimes,
		// .setbkuptime = obuilder_setbkuptime,
		// .setchgtime = obuilder_setchgtime,
		// .setcrtime = obuilder_setcrtime,
		// .chflags = obuilder_chflags,
		// .setattr_x = obuilder_setattr_x,
		// .fsetattr_x = obuilder_fsetattr_x,
		.flag_nullpath_ok = 1,
		.flag_utime_omit_ok = 1};

int main(int argc, char *argv[])
{
	umask(0);

	if (!strcmp(argv[1], "--help"))
	{
		printf("~~~ obuilder-fs version: 0.0.1 ~~~\n Usage:\n obuilderfs <scoreboard-path> <mount-point> <fuse-args-like-allow-other>\n");
		return 0;
	}

	// This is dodgy probably... I'm no C programmer
	conf.scoreboard = strdup(argv[1]);
	printf("%s\n", conf.scoreboard);
	// Replace scoreboard param with program name and pass this to fuse
	*argv[1] = *argv[0];
	return fuse_main(argc - 1, argv + 1, &obuilder_oper, NULL);
}
