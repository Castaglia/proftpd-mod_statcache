/*
 * ProFTPD: mod_statcache -- a module implementing caching of stat(2),
 *                           fstat(2), and lstat(2) calls
 *
 * Copyright (c) 2013 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_statcache, contrib software for proftpd 1.3.x.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"
#ifdef PR_USE_CTRLS
# include "mod_ctrls.h"
#endif /* PR_USE_CTRLS */

#include <sys/ipc.h>
#include <sys/shm.h>

#define MOD_STATCACHE_VERSION			"mod_statcache/0.0"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

#define STATCACHE_PROJ_ID		476

#define STATCACHE_DEFAULT_MAX_AGE	5
#define STATCACHE_MAX_BUCKETS		500
#define STATCACHE_MAX_ITEMS_PER_BUCKET	10

#ifndef HAVE_FLOCK
# define LOCK_SH        1
# define LOCK_EX        2
# define LOCK_UN        8
# define LOCK_NB        4
#endif /* HAVE_FLOCK */

/* From src/main.c */
extern pid_t mpid;

module statcache_module;

#ifdef PR_USE_CTRLS
static ctrls_acttab_t statcache_acttab[];
#endif

/* Pool for this module's use */
static pool *statcache_pool = NULL;

/* Copied from src/fsio.c. */
struct statcache_entry {
  uint32_t sce_hash;
  char sce_path[PR_TUNABLE_PATH_MAX+1];
  size_t sce_pathlen;
  struct stat sce_stat;
  int sce_errno;
  int sce_op;
  time_t sce_ts;
};

struct statcache_data {
  struct statcache_entry entries[STATCACHE_MAX_BUCKETS][STATCACHE_MAX_ITEMS_PER_BUCKET];
};

static struct statcache_data *statcache_table = NULL;
static int statcache_engine = FALSE;
static unsigned int statcache_max_age = STATCACHE_DEFAULT_MAX_AGE;

static int statcache_shmid = -1;
static char *statcache_table_path = NULL;
static pr_fh_t *statcache_tabfh = NULL;

static const char *trace_channel = "statcache";

static int statcache_lock_shm(int);

/* Functions for marshalling key/value data to/from local cache (SysV shm). */
static struct statcache_data *statcache_get_shm(pr_fh_t *tabfh) {
  int shmid;
  int shm_existed = FALSE;
  struct statcache_data *data = NULL;
  key_t key;

  /* If we already have a shmid, no need to do anything. */
  if (statcache_shmid >= 0) {
    errno = EEXIST;
    return NULL;
  }

  /* Get a key for this path. */
  key = ftok(tabfh->fh_path, STATCACHE_PROJ_ID);
  if (key == (key_t) -1) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
      ": unable to get shared memory key for '%s': %s", tabfh->fh_path,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Try first using IPC_CREAT|IPC_EXCL, to check if there is an existing
   * shm for this key.  If there is, try again, using a flag of zero.
   */

  shmid = shmget(key, sizeof(struct statcache_data), IPC_CREAT|IPC_EXCL|0666);
  if (shmid < 0) {
    if (errno == EEXIST) {
      shm_existed = TRUE;

      shmid = shmget(key, 0, 0);

    } else {
      int xerrno = errno;

      /* XXX If we get EINVAL here, it is probably because the requested
       * allocation size is larger than the max allowed to the process.
       * This indicates that we should have some way of better determining
       * that limit, and/or tuning it, to Do The Right Thing(tm).
       */

      pr_trace_msg(trace_channel, 1,
        "unable to allocate %lu bytes of shared memory: %s",
        (unsigned long) sizeof(struct statcache_data), strerror(xerrno));

      errno = xerrno;
      return NULL;
    }
  }

  pr_trace_msg(trace_channel, 9,
    "allocated %lu bytes of shared memory for %u buckets (%u items per bucket)",
    (unsigned long) sizeof(struct statcache_data), STATCACHE_MAX_BUCKETS,
    STATCACHE_MAX_ITEMS_PER_BUCKET);

  /* Attach to the shm. */
  data = (struct statcache_data *) shmat(shmid, NULL, 0);
  if (data == NULL) {
    int xerrno = errno;

    pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
      ": unable to attach to shared memory: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  if (!shm_existed) {
    /* Make sure the memory is initialized. */
    if (statcache_lock_shm(LOCK_EX) < 0) {
      pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
        ": error write-locking shared memory: %s", strerror(errno));
    }

    memset(data, '\0', sizeof(struct statcache_data));

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
        ": error unlocking shared memory: %s", strerror(errno));
    }
  }

  statcache_shmid = shmid;
  pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION
    ": obtained shared memory ID %d for StatCacheTable '%s'", statcache_shmid,
    tabfh->fh_path);

  return data;
}

static int statcache_lock_shm(int flags) {
  static unsigned int statcache_nlocks = 0;

#ifndef HAVE_FLOCK
  int lock_flag;
  struct flock lock;
#endif /* HAVE_FLOCK */

  if (statcache_nlocks &&
      ((flags & LOCK_SH) || (flags & LOCK_EX))) {
    statcache_nlocks++;
    return 0;
  }

  if (statcache_nlocks == 0 &&
      (flags & LOCK_UN)) {
    return 0;
  }

#ifdef HAVE_FLOCK
  while (flock(statcache_tabfh->fh_fd, flags) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    return -1;
  }

  if ((flags & LOCK_SH) ||
      (flags & LOCK_EX)) {
    statcache_nlocks++;

  } else if (flags & LOCK_UN) {
    statcache_nlocks--;
  }

  return 0;
#else
  lock_flag = F_SETLKW;

  lock.l_whence = 0;
  lock.l_start = lock.l_len = 0;

  if (flags & LOCK_SH) {
    lock.l_type = F_RDLCK;

  } else if (flags & LOCK_EX) {
    lock.l_type = F_WRLCK;

  } else if (flags & LOCK_UN) {
    lock.l_type= F_UNLCK;

  } else {
    errno = EINVAL;
    return -1;
  }

  if (flags & LOCK_NB) {
    lock_flag = F_SETLK;
  }

  while (fcntl(statcache_tabfh->fh_fd, lock_flag, &lock) < 0) {
    if (errno == EINTR) {
      pr_signals_handle();
      continue;
    }

    return -1;
  }

  if ((flags & LOCK_SH) ||
      (flags & LOCK_EX)) {
    statcache_nlocks++;

  } else if (flags & LOCK_UN) {
    statcache_nlocks--;
  }

  return 0;
#endif /* HAVE_FLOCK */
}

/* Table manipulation routines */

/* See http://www.cse.yorku.ca/~oz/hash.html */
static uint32_t statcache_hash(const char *path, size_t pathlen) {
  register unsigned int i;
  uint32_t h = 5381;

  for (i = 0; i < pathlen; i++) {
    h = ((h << 5) + h) + path[i];
  }

  /* Strip off the high bit. */
  h &= ~(1 << 31);

  return h;
}

/* Add an entry to the table. */
static int statcache_table_add(const char *path, struct stat *st, int xerrno,
    int op) {
  register unsigned int i;
  uint32_t h, idx;
  size_t pathlen;
  int found_slot = FALSE;
  time_t now;
  struct statcache_entry *sce = NULL;

  if (statcache_table == NULL) {
    errno = EPERM;
    return -1;
  }

  pathlen = strlen(path);
  h = statcache_hash(path, pathlen);
  idx = h % STATCACHE_MAX_BUCKETS;

  /* Find an open slot in the list for this new entry. */
  now = time(NULL);

  for (i = 0; i < STATCACHE_MAX_ITEMS_PER_BUCKET; i++) {
    pr_signals_handle();

    sce = &(statcache_table->entries[idx][i]);
    if (sce->sce_ts == 0) {
      /* Empty slot */
      found_slot = TRUE;
      break;
    }

    /* If existing item is too old, use this slot.  Note that there
     * are different expiry rules for negative cache entries (i.e.
     * errors) than for positive cache entries.
     */
    if (sce->sce_errno != 0 &&
        (now > (sce->sce_ts + 1))) {
      found_slot = TRUE;
      break;
    }

    if (now > (sce->sce_ts + statcache_max_age)) {
      found_slot = TRUE;
      break;
    }
  }

  if (found_slot == FALSE) {
    errno = ENOSPC;
    return -1;
  }

  pr_trace_msg(trace_channel, 9,
    "adding entry for path '%s' (hash %lu) at index %lu, item #%u "
    "(op %s, type %s, errno %d)", path,
    (unsigned long) h, (unsigned long) idx, i + 1,
    op == FSIO_FILE_LSTAT ? "LSTAT" : "STAT",
    S_ISLNK(st->st_mode) ? "symlink" :
      S_ISDIR(st->st_mode) ? "dir" : "file", xerrno);

  sce->sce_hash = h;
  sce->sce_pathlen = pathlen;
  memcpy(sce->sce_path, path, pathlen);
  if (st != NULL) {
    memcpy(&(sce->sce_stat), st, sizeof(struct stat));
  }
  sce->sce_errno = xerrno;
  sce->sce_ts = now;
  sce->sce_op = op;

  return 0;
}

static int statcache_table_get(const char *path, struct stat *st, int *xerrno,
    int op) {
  register unsigned int i;
  uint32_t h, idx;
  size_t pathlen;
  time_t now;

  if (statcache_table == NULL) {
    errno = EPERM;
    return -1;
  }

  pathlen = strlen(path);
  h = statcache_hash(path, pathlen);
  idx = h % STATCACHE_MAX_BUCKETS;

  /* Find the matching entry for this path. */
  now = time(NULL);
  for (i = 0; i < STATCACHE_MAX_ITEMS_PER_BUCKET; i++) {
    struct statcache_entry *sce;

    pr_signals_handle();

    sce = &(statcache_table->entries[idx][i]);
    if (sce->sce_ts > 0) {
      /* Check the age.  If it's aged out, clear it now, for later use. */
      if (sce->sce_errno != 0 &&
          (now > (sce->sce_ts + 1))) {
        pr_trace_msg(trace_channel, 17,
          "clearing expired negative cache entry for path '%s' (hash %lu) "
          "at index %lu, item #%u: aged %lu secs",
          sce->sce_path, (unsigned long) h, (unsigned long) idx, i + 1,
          (unsigned long) (now - sce->sce_ts));
        sce->sce_ts = 0;
        continue;
      }

      if (now > (sce->sce_ts + statcache_max_age)) {
        pr_trace_msg(trace_channel, 17,
          "clearing expired cache entry for path '%s' (hash %lu) "
          "at index %lu, item #%u: aged %lu secs",
          sce->sce_path, (unsigned long) h, (unsigned long) idx, i + 1,
          (unsigned long) (now - sce->sce_ts));
        sce->sce_ts = 0;
        continue;
      }

      if (sce->sce_hash == h) {
        /* Possible collision; check paths. */
        if (sce->sce_pathlen == pathlen) {
          if (strncmp(sce->sce_path, path, pathlen) == 0) {

            /* If the ops match, OR if the entry is from a LSTAT AND the entry
             * is NOT a symlink, we can use it.
             */
            if (sce->sce_op == op ||
                (sce->sce_op == FSIO_FILE_LSTAT &&
                 S_ISLNK(sce->sce_stat.st_mode) == FALSE)) {
              /* Found matching entry. */
              pr_trace_msg(trace_channel, 9,
                "found entry for path '%s' (hash %lu) at index %lu, item #%u",
                path, (unsigned long) h, (unsigned long) idx, i + 1);

              *xerrno = sce->sce_errno;
              if (sce->sce_errno == 0) {
                memcpy(st, &(sce->sce_stat), sizeof(struct stat));
              }

              return 0;
            }
          }
        }
      }
    }
  }

  errno = ENOENT;
  return -1;
}

static int statcache_table_remove(const char *path) {
  register unsigned int i;
  uint32_t h, idx;
  size_t pathlen;
  int removed = FALSE;

  if (statcache_table == NULL) {
    errno = EPERM;
    return -1;
  }

  pathlen = strlen(path);
  h = statcache_hash(path, pathlen);
  idx = h % STATCACHE_MAX_BUCKETS;

  /* Find the matching entry for this path. */
  for (i = 0; i < STATCACHE_MAX_ITEMS_PER_BUCKET; i++) {
    struct statcache_entry *sce;

    pr_signals_handle();

    sce = &(statcache_table->entries[idx][i]);
    if (sce->sce_ts > 0) {
      if (sce->sce_hash == h) {
        /* Possible collision; check paths. */
        if (sce->sce_pathlen == pathlen) {
          if (strncmp(sce->sce_path, path, pathlen) == 0) {
            /* Found matching entry.  Clear it by zeroing timestamp field. */

            pr_trace_msg(trace_channel, 9,
              "removing entry for path '%s' (hash %lu) at index %lu, item #%u",
              path, (unsigned long) h, (unsigned long) idx, i + 1);

            sce->sce_ts = 0;
            removed = TRUE;

            /* Rather than returning now, we finish iterating through
             * the bucket, in order to clear out multiple entries for
             * the same path (e.g. one for LSTAT, and another for STAT).
             */
          }
        }
      }
    }
  }

  if (removed == TRUE) {
    return 0;
  }

  errno = ENOENT;
  return -1;
}

/* FSIO callbacks
 */

static int statcache_fsio_stat(pr_fs_t *fs, const char *path,
    struct stat *st) {
  int res, xerrno = 0;
  char *canon_path = NULL;

  if (statcache_lock_shm(LOCK_EX) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  canon_path = dir_canonical_path(fs->fs_pool, path);
  res = statcache_table_get(canon_path, st, &xerrno, FSIO_FILE_STAT);

  if (statcache_lock_shm(LOCK_UN) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    if (xerrno != 0) {
      res = -1;

    } else {
      pr_trace_msg(trace_channel, 11,
        "using cached stat for path '%s'", canon_path);
    }

    return res;
  }

  res = stat(path, st);
  xerrno = errno;

  if (res < 0) {
    /* Negatively cache the failed stat(2). */
    (void) statcache_table_add(canon_path, NULL, xerrno, FSIO_FILE_STAT);

  } else {
    (void) statcache_table_add(canon_path, st, 0, FSIO_FILE_STAT);
  }

  return res;
}

static int statcache_fsio_fstat(pr_fh_t *fh, int fd, struct stat *st) {
  int res, xerrno = 0;

  if (statcache_lock_shm(LOCK_EX) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  res = statcache_table_get(fh->fh_path, st, &xerrno, FSIO_FILE_STAT);

  if (statcache_lock_shm(LOCK_UN) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    if (xerrno != 0) {
      res = -1;

    } else {
      pr_trace_msg(trace_channel, 11,
        "using cached stat for path '%s'", fh->fh_path);
    }

    return res;
  }

  res = fstat(fd, st);
  xerrno = errno;

  if (res < 0) {
    /* Negatively cache the failed fstat(2). */
    (void) statcache_table_add(fh->fh_path, NULL, xerrno, FSIO_FILE_STAT);

  } else {
    (void) statcache_table_add(fh->fh_path, st, 0, FSIO_FILE_STAT);
  }

  return res;
}

static int statcache_fsio_lstat(pr_fs_t *fs, const char *path,
    struct stat *st) {
  int res, xerrno = 0;
  char *canon_path = NULL;

  if (statcache_lock_shm(LOCK_EX) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error write-locking shared memory: %s", strerror(errno));
  }

  canon_path = dir_canonical_path(fs->fs_pool, path);
  res = statcache_table_get(canon_path, st, &xerrno, FSIO_FILE_LSTAT);

  if (statcache_lock_shm(LOCK_UN) < 0) {
    pr_trace_msg(trace_channel, 3,
      "error unlocking shared memory: %s", strerror(errno));
  }

  if (res == 0) {
    if (xerrno != 0) {
      res = -1;

    } else {
      pr_trace_msg(trace_channel, 11,
        "using cached lstat for path '%s'", canon_path);
    }

    return res;
  }

  res = lstat(path, st);
  xerrno = errno;

  if (res < 0) {
    /* Negatively cache the failed lstat(2). */
    (void) statcache_table_add(canon_path, NULL, xerrno, FSIO_FILE_LSTAT);

  } else {
    (void) statcache_table_add(canon_path, st, 0, FSIO_FILE_LSTAT);
  }

  return res;
}

static int statcache_fsio_rename(pr_fs_t *fs, const char *rnfm,
    const char *rnto) {
  int res;

  res = rename(rnfm, rnto);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }   

    (void) statcache_table_remove(rnfm);
    (void) statcache_table_remove(rnto);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }
  }

  return res;
}

static int statcache_fsio_unlink(pr_fs_t *fs, const char *path) {
  int res;

  res = unlink(path);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }

    (void) statcache_table_remove(path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    }
  }

  return res;
}

static int statcache_fsio_open(pr_fh_t *fh, const char *path, int flags) {
  int res;

  res = open(path, flags);
  if (res == 0) {
    /* Clear the cache for this patch, but only if O_CREAT is present. */
    if (flags & O_CREAT) {
      if (statcache_lock_shm(LOCK_SH) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error write-locking shared memory: %s", strerror(errno));
      } 
    
      (void) statcache_table_remove(path);
    
      if (statcache_lock_shm(LOCK_UN) < 0) {
        pr_trace_msg(trace_channel, 3,
          "error unlocking shared memory: %s", strerror(errno));
      } 
    }
  } 
  
  return res;
}

static int statcache_fsio_write(pr_fh_t *fh, int fd, const char *buf,
    size_t buflen) {
  int res;

  res = write(fd, buf, buflen);
  if (res > 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
  
    (void) statcache_table_remove(fh->fh_path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }
 
  return res;
}

static int statcache_fsio_truncate(pr_fs_t *fs, const char *path, off_t len) {
  int res;

  res = truncate(path, len);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }
  
  return res;
}

static int statcache_fsio_ftruncate(pr_fh_t *fh, int fd, off_t len) {
  int res;

  res = ftruncate(fd, len);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(fh->fh_path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }
 
  return res;
}

static int statcache_fsio_chmod(pr_fs_t *fs, const char *path, mode_t mode) {
  int res;

  res = chmod(path, mode);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
}

static int statcache_fsio_fchmod(pr_fh_t *fh, int fd, mode_t mode) {
  int res;

  res = fchmod(fd, mode);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(fh->fh_path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
}

static int statcache_fsio_chown(pr_fs_t *fs, const char *path, uid_t uid,
    gid_t gid) {
  int res;

  res = chown(path, uid, gid);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
}

static int statcache_fsio_fchown(pr_fh_t *fh, int fd, uid_t uid, gid_t gid) {
  int res;

  res = fchown(fd, uid, gid);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(fh->fh_path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
}

static int statcache_fsio_lchown(pr_fs_t *fs, const char *path, uid_t uid,
    gid_t gid) {
  int res;

  res = lchown(path, uid, gid);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
}

static int statcache_fsio_utimes(pr_fs_t *fs, const char *path,
    struct timeval *tvs) {
  int res;

  res = utimes(path, tvs);
  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
}

static int statcache_fsio_futimes(pr_fh_t *fh, int fd, struct timeval *tvs) {
#ifdef HAVE_FUTIMES
  int res;

  /* Check for an ENOSYS errno; if so, fallback to using fsio_utimes.  Some
   * platforms will provide a futimes(2) stub which does not actually do
   * anything.
   */
  res = futimes(fd, tvs);
  if (res < 0 &&
      errno == ENOSYS) {
    return statcache_fsio_utimes(fh->fh_fs, fh->fh_path, tvs);
  }

  if (res == 0) {
    if (statcache_lock_shm(LOCK_SH) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error write-locking shared memory: %s", strerror(errno));
    }
 
    (void) statcache_table_remove(fh->fh_path);

    if (statcache_lock_shm(LOCK_UN) < 0) {
      pr_trace_msg(trace_channel, 3,
        "error unlocking shared memory: %s", strerror(errno));
    } 
  }

  return res;
#else
  return statcache_fsio_utimes(fh->fh_fs, fh->fh_path, tvs);
#endif /* HAVE_FUTIMES */
}

#ifdef PR_USE_CTRLS
/* Controls handlers
 */

static int statcache_handle_statcache(pr_ctrls_t *ctrl, int reqargc,
    char **reqargv) {
  register unsigned int i;
  int optc, verbose = FALSE;
  const char *reqopts = "v";

  /* Check for options. */
  pr_getopt_reset();

  while ((optc = getopt(reqargc, reqargv, reqopts)) != -1) {
    switch (optc) {
      case 'v':
        verbose = TRUE;
        break;

      case '?':
        pr_ctrls_add_response(ctrl, "unsupported parameter: '%s'",
          reqargv[0]);
        return -1;
    }
  }

  if (statcache_lock_shm(LOCK_SH) < 0) {
    pr_ctrls_add_response(ctrl, "error locking shared memory: %s",
      strerror(errno));
    return -1;
  }

  pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION ": showing cache table");

  statcache_lock_shm(LOCK_UN);

  return 0;
}

#endif /* PR_USE_CTRLS */

/* Configuration handlers
 */

/* usage: StatCacheControlsACLs actions|all allow|deny user|group list */
MODRET set_statcachectrlsacls(cmd_rec *cmd) {
#ifdef PR_USE_CTRLS
  char *bad_action = NULL, **actions = NULL;

  CHECK_ARGS(cmd, 4);
  CHECK_CONF(cmd, CONF_ROOT);

  /* We can cheat here, and use the ctrls_parse_acl() routine to
   * separate the given string...
   */
  actions = ctrls_parse_acl(cmd->tmp_pool, cmd->argv[1]);

  /* Check the second parameter to make sure it is "allow" or "deny" */
  if (strcmp(cmd->argv[2], "allow") != 0 &&
      strcmp(cmd->argv[2], "deny") != 0) {
    CONF_ERROR(cmd, "second parameter must be 'allow' or 'deny'");
  }

  /* Check the third parameter to make sure it is "user" or "group" */
  if (strcmp(cmd->argv[3], "user") != 0 &&
      strcmp(cmd->argv[3], "group") != 0) {
    CONF_ERROR(cmd, "third parameter must be 'user' or 'group'");
  }

  bad_action = pr_ctrls_set_module_acls(statcache_acttab, statcache_pool,
    actions, cmd->argv[2], cmd->argv[3], cmd->argv[4]);
  if (bad_action != NULL) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown action: '",
      bad_action, "'", NULL));
  }

  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "requires Controls support (use --enable-ctrls)");
#endif /* PR_USE_CTRLS */
}

/* usage: StatCacheEngine on|off */
MODRET set_statcacheengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  statcache_engine = engine;

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: StatCacheMaxAge secs */
MODRET set_statcachemaxage(cmd_rec *cmd) {
  int age;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  age = atoi(cmd->argv[1]);
  if (age <= 0) {
    CONF_ERROR(cmd, "parameter must be 1 or greater");
  }

  statcache_max_age = age;
  return PR_HANDLED(cmd);
}

/* usage: StatCacheTable path */
MODRET set_statcachetable(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, "must be an absolute path");
  }

  statcache_table_path = pstrdup(statcache_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET statcache_post_pass(cmd_rec *cmd) {
  pr_fs_t *fs;

  /* Unmount the default/system FS, so that our FS is used for relative
   * paths, too.
   */
  (void) pr_unmount_fs("/", NULL);

  fs = pr_register_fs(statcache_pool, "statcache", "/");
  if (fs == NULL) {
    pr_log_debug(DEBUG3, MOD_STATCACHE_VERSION
      ": error registering 'statcache' fs: %s", strerror(errno));
    statcache_engine = FALSE;
    return PR_DECLINED(cmd);
  }

  /* Add the module's custom FS callbacks here. */
  fs->stat = statcache_fsio_stat;
  fs->fstat = statcache_fsio_fstat;
  fs->lstat = statcache_fsio_lstat;
  fs->rename = statcache_fsio_rename;
  fs->unlink = statcache_fsio_unlink;
  fs->open = statcache_fsio_open;;
  fs->truncate = statcache_fsio_truncate;
  fs->ftruncate = statcache_fsio_ftruncate;
  fs->write = statcache_fsio_write;
  fs->chmod = statcache_fsio_chmod;
  fs->fchmod = statcache_fsio_fchmod;
  fs->chown = statcache_fsio_chown;
  fs->fchown = statcache_fsio_fchown;
  fs->lchown = statcache_fsio_lchown;
  fs->utimes = statcache_fsio_utimes;
  fs->futimes = statcache_fsio_futimes;

  pr_fs_setcwd(pr_fs_getvwd());
  pr_fs_clear_cache();

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

static void statcache_shutdown_ev(const void *event_data, void *user_data) {

  /* Remove the shm from the system.  We can only do this reliably
   * when the standalone daemon process exits; if it's an inetd process,
   * there many be other proftpd processes still running.
   */

  if (getpid() == mpid &&
      ServerType == SERVER_STANDALONE &&
      statcache_shmid >= 0) {
    struct shmid_ds ds;
    int res, xerrno;

#if !defined(_POSIX_SOURCE)
    res = shmdt((char *) statcache_table);
#else
    res = shmdt((const void *) statcache_table);
#endif

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_STATCACHE_VERSION
        ": error detaching shared memory: %s", strerror(errno));

    } else {
      pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION
        ": detached shared memory ID %d for StatCacheTable '%s'",
        statcache_shmid, statcache_table_path);
    }

    memset(&ds, 0, sizeof(ds));

    PRIVS_ROOT
    res = shmctl(statcache_shmid, IPC_RMID, &ds);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res < 0) {
      pr_log_debug(DEBUG1, MOD_STATCACHE_VERSION
        ": error removing shared memory ID %d: %s", statcache_shmid,
        strerror(xerrno));

    } else {
      pr_log_debug(DEBUG7, MOD_STATCACHE_VERSION
        ": removed shared memory ID %d for StatCacheTable '%s'",
        statcache_shmid, statcache_table_path);
    }
  }
}

#if defined(PR_SHARED_MODULE)
static void statcache_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_statcache.c", (const char *) event_data) == 0) {
#ifdef PR_USE_CTRLS
    register unsigned int i;

    for (i = 0; statcache_acttab[i].act_action; i++) {
      (void) pr_ctrls_unregister(&statcache_module,
        statcache_acttab[i].act_action);
    }
#endif /* PR_USE_CTRLS */

    pr_event_unregister(&statcache_module, NULL, NULL);

    if (statcache_tabfh) {
      (void) pr_fsio_close(statcache_tabfh);
      statcache_tabfh = NULL;
    }

    if (statcache_pool) {
      destroy_pool(statcache_pool);
      statcache_pool = NULL;
    }

    statcache_engine = FALSE;
  }
}
#endif /* PR_SHARED_MODULE */

static void statcache_postparse_ev(const void *event_data, void *user_data) {
  struct statcache_data *table;
  int xerrno;

  if (statcache_engine == FALSE) {
    return;
  }

  /* Make sure the StatCacheTable exists. */
  if (statcache_table_path == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": missing required StatCacheTable configuration");
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  PRIVS_ROOT
  statcache_tabfh = pr_fsio_open(statcache_table_path, O_RDWR|O_CREAT); 
  xerrno = errno;
  PRIVS_RELINQUISH

  if (statcache_tabfh == NULL) {
    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": unable to open StatCacheTable '%s': %s", statcache_table_path,
      strerror(xerrno));
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  if (statcache_tabfh->fh_fd <= STDERR_FILENO) {
    int usable_fd;

    usable_fd = pr_fs_get_usable_fd(statcache_tabfh->fh_fd);
    if (usable_fd < 0) {
      pr_log_debug(DEBUG0, MOD_STATCACHE_VERSION
        "warning: unable to find good fd for StatCacheTable %s: %s",
        statcache_table_path, strerror(errno));

    } else {
      close(statcache_tabfh->fh_fd);
      statcache_tabfh->fh_fd = usable_fd;
    }
  } 

  /* Get the shm for storing all of our stat info. */
  table = statcache_get_shm(statcache_tabfh);
  if (table == NULL &&
      errno != EEXIST) {
    pr_log_pri(PR_LOG_NOTICE, MOD_STATCACHE_VERSION
      ": unable to get shared memory for StatCacheTable '%s': %s",
      statcache_table_path, strerror(errno));
    pr_session_disconnect(&statcache_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      NULL);
  }

  if (table)
    statcache_table = table;

  return;
}

static void statcache_restart_ev(const void *event_data, void *user_data) {
#ifdef PR_USE_CTRLS
  register unsigned int i;
#endif /* PR_USE_CTRLS */

  if (statcache_pool) {
    destroy_pool(statcache_pool);
    statcache_pool = NULL;
  }

  statcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(statcache_pool, MOD_STATCACHE_VERSION);

#ifdef PR_USE_CTRLS
  /* Register the control handlers */
  for (i = 0; statcache_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    statcache_acttab[i].act_acl = pcalloc(statcache_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(statcache_acttab[i].act_acl);
  }
#endif /* PR_USE_CTRLS */

  /* Close the StatCacheTable file descriptor; it will be reopened by the
   * postparse event listener.
   */
  if (statcache_tabfh != NULL) {
    pr_fsio_close(statcache_tabfh);
    statcache_tabfh = NULL;
  }

  return;
}

/* Initialization routines
 */

static int statcache_init(void) {
#ifdef PR_USE_CTRLS
  register unsigned int i = 0;
#endif /* PR_USE_CTRLS */

  /* Allocate the pool for this module's use. */
  statcache_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(statcache_pool, MOD_STATCACHE_VERSION);

#ifdef PR_USE_CTRLS
  /* Register the control handlers */
  for (i = 0; statcache_acttab[i].act_action; i++) {

    /* Allocate and initialize the ACL for this control. */
    statcache_acttab[i].act_acl = pcalloc(statcache_pool, sizeof(ctrls_acl_t));
    pr_ctrls_init_acl(statcache_acttab[i].act_acl);

    if (pr_ctrls_register(&statcache_module, statcache_acttab[i].act_action,
        statcache_acttab[i].act_desc, statcache_acttab[i].act_cb) < 0) {
      pr_log_pri(PR_LOG_INFO, MOD_STATCACHE_VERSION
        ": error registering '%s' control: %s",
        statcache_acttab[i].act_action, strerror(errno));
    }
  }
#endif /* PR_USE_CTRLS */

#if defined(PR_SHARED_MODULE)
  pr_event_register(&statcache_module, "core.module-unload",
    statcache_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&statcache_module, "core.postparse",
    statcache_postparse_ev, NULL);
  pr_event_register(&statcache_module, "core.restart",
    statcache_restart_ev, NULL);
  pr_event_register(&statcache_module, "core.shutdown",
    statcache_shutdown_ev, NULL);

  return 0;
}

static int statcache_sess_init(void) {
  config_rec *c;

  /* Check to see if the BanEngine directive is set to 'off'. */
  c = find_config(main_server->conf, CONF_PARAM, "StatCacheEngine", FALSE);
  if (c != NULL) {
    statcache_engine = *((int *) c->argv[0]);
  }

  return 0;
}

#ifdef PR_USE_CTRLS

/* Controls table
 */
static ctrls_acttab_t statcache_acttab[] = {
  { "statcache",	"display cache stats", NULL,
    statcache_handle_statcache },

  { NULL, NULL, NULL, NULL }
};
#endif /* PR_USE_CTRLS */

/* Module API tables
 */

static conftable statcache_conftab[] = {
  { "StatCacheControlsACLs",	set_statcachectrlsacls,	NULL },
  { "StatCacheEngine",		set_statcacheengine,	NULL },
  { "StatCacheMaxAge",		set_statcachemaxage,	NULL },
  { "StatCacheTable",		set_statcachetable,	NULL },
  { NULL }
};

static cmdtable statcache_cmdtab[] = {
  { POST_CMD,   C_PASS, G_NONE, statcache_post_pass,  FALSE,  FALSE },
  { 0, NULL }
};

module statcache_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "statcache",

  /* Module configuration handler table */
  statcache_conftab,

  /* Module command handler table */
  statcache_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  statcache_init,

  /* Session initialization function */
  statcache_sess_init,

  /* Module version */
  MOD_STATCACHE_VERSION
};
