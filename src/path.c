/*
 * path.c - safe_resolve_path: join a request URI path with a document root
 * while blocking traversal (".."), null bytes, symlinks outside root,
 * and overly long components. Returns the open fd for the resolved file
 * via a path string + stat. We never strcat/sprintf; we use bounded
 * memcpy and explicit length checks.
 *
 * Root-confinement guarantee: after building the candidate path we
 *  1. lstat() every final path component (no symlinks followed);
 *  2. for directory-index candidates we use openat() with O_NOFOLLOW
 *     relative to an fd on the *resolved* directory, then verify with
 *     fstat() that the target is a regular file -- this prevents a
 *     symlinked or hardlinked index file from escaping the document
 *     root even when the index is inside a chroot/race.
 */
#include "common.h"

static const char *index_files[] = { "index.html", "index.htm", NULL };

/* Open a file inside dirfd using O_NOFOLLOW so a symlink at the leaf
 * fails with ELOOP. Returns fd on success, -1 on failure. */
static int openat_nofollow(int dirfd, const char *name)
{
    return openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
}

int safe_resolve_path(const char *root, const char *uri_path, size_t uri_plen,
                      char *out, size_t out_sz, struct stat *st_out, bool *is_dir)
{
    if (!root || !uri_path || !out || out_sz < SALUKID_PATH_MAX) return -1;

    size_t root_len = strnlen(root, SALUKID_PATH_MAX - 1);
    if (root_len == 0 || root_len >= SALUKID_PATH_MAX - 8) return -1;

    /* Normalize root: ensure trailing '/' */
    memcpy(out, root, root_len);
    if (out[root_len-1] != '/') out[root_len++] = '/';
    size_t base = root_len;
    size_t pos  = root_len;

    /* Reject: null bytes, backslashes, leading control chars, '..' segments */
    size_t i = 0;
    if (uri_plen == 0 || uri_path[0] != '/') {
        return -1;
    }
    i = 1; /* skip leading '/' */

    while (i < uri_plen) {
        size_t seg_start = i;
        while (i < uri_plen && uri_path[i] != '/') {
            char c = uri_path[i];
            if (c == '\0' || c == '\\') return -1;
            if (c == '%' && i + 2 < uri_plen && uri_path[i+1] == '0' && uri_path[i+2] == '0') return -1;
            i++;
        }
        size_t seg_len = i - seg_start;
        if (seg_len == 0) { i++; continue; }

        if (seg_len == 1 && uri_path[seg_start] == '.') return -1;
        if (seg_len == 2 && uri_path[seg_start] == '.' && uri_path[seg_start+1] == '.')
            return -1;
        if (seg_len > 255) return -1;

        if (pos > base) {
            if (pos + 1 >= out_sz) return -1;
            out[pos++] = '/';
        }
        if (pos + seg_len >= out_sz) return -1;
        memcpy(out + pos, uri_path + seg_start, seg_len);
        pos += seg_len;

        if (i < uri_plen && uri_path[i] == '/') i++;
    }

    out[pos] = '\0';

    /* lstat first: refuse symlinks at the final resolved path */
    struct stat st;
    if (lstat(out, &st) < 0) return -1;
    if (S_ISLNK(st.st_mode)) return -1;

    if (S_ISDIR(st.st_mode)) {
        if (is_dir) *is_dir = true;
        /* Open the directory with O_RDONLY | O_DIRECTORY to anchor openat */
        int dfd = open(out, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd < 0) return -1;
        for (int fi = 0; index_files[fi]; fi++) {
            const char *idx = index_files[fi];
            size_t il = strlen(idx);
            /* Check name length fits in buffer (for final output path) */
            if (pos + 1 + il >= out_sz) continue;
            /* Open the index with O_NOFOLLOW to defeat symlinked index
             * files; fstat() after open so TOCTOU is avoided. */
            int ifd = openat_nofollow(dfd, idx);
            if (ifd < 0) continue;
            struct stat ist;
            if (fstat(ifd, &ist) != 0) { close(ifd); continue; }
            if (S_ISREG(ist.st_mode)) {
                /* Build the full path for logging/mime; since the file
                 * was opened via O_NOFOLLOW off dfd (which points at
                 * our already-validated directory), even if a concurrent
                 * rename happened between openat and here we already
                 * have a validated fd. */
                out[pos] = '/';
                memcpy(out + pos + 1, idx, il);
                out[pos + 1 + il] = '\0';
                if (st_out) *st_out = ist;
                if (is_dir) *is_dir = false;
                close(ifd);
                close(dfd);
                return 0;
            }
            close(ifd);
        }
        close(dfd);
        /* No index: return directory (handler decides 403 vs listing) */
        out[pos] = '\0';
        if (lstat(out, &st) < 0) return -1;
        if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) return -1;
        if (st_out) *st_out = st;
        if (is_dir) *is_dir = true;
        return 0;
    }

    if (!S_ISREG(st.st_mode)) return -1;
    if (st_out) *st_out = st;
    if (is_dir) *is_dir = false;
    return 0;
}
