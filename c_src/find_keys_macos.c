/*
 * find_all_keys_macos.c - macOS WeChat memory key scanner
 *
 * Scans WeChat process memory for SQLCipher encryption keys. It supports both
 * the legacy x'<key_hex><salt_hex>' keyspec and the SQLCipher codec/cipher
 * context layouts used before and after SQLCipher removed that text keyspec.
 *
 * Prerequisites:
 *   - WeChat must be ad-hoc signed (or SIP disabled)
 *   - Must run as root (sudo)
 *
 * Build:
 *   cc -O2 -o find_all_keys_macos find_all_keys_macos.c -framework Foundation
 *
 * Usage:
 *   sudo ./find_all_keys_macos [pid]
 *   If pid is omitted, automatically finds WeChat PID.
 *
 * Output: JSON file at ./all_keys.json (compatible with decrypt_db.py)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ftw.h>
#include <limits.h>
#include <fcntl.h>
#include <stddef.h>
#include <pwd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

#define MAX_KEYS 256
#define KEY_SIZE 32
#define SALT_SIZE 16
#define HEX_PATTERN_LEN 96  /* 64 hex (key) + 32 hex (salt) */
#define CHUNK_SIZE (2 * 1024 * 1024)
#define STRUCT_SCAN_ALIGNMENT 8
#define STRUCT_SCAN_OVERLAP 135

typedef struct {
    char key_hex[65];
    char salt_hex[33];
} key_entry_t;

/*
 * SQLCipher layouts from upstream. Version 4.1 retained a 99-byte text
 * keyspec; current SQLCipher removed it and shifted the codec pointers. These
 * views are used only as structural anchors. Every recovered salt must match a
 * real database header here, and Python authenticates page 1 before accepting
 * any staged candidate.
 *
 * https://github.com/sqlcipher/sqlcipher/blob/v4.1.0/src/crypto_impl.c
 * https://github.com/sqlcipher/sqlcipher/blob/v4.17.0/src/sqlcipher.c
 */
typedef struct {
    int32_t derive_key;
    int32_t pass_sz;
    uint64_t key;
    uint64_t hmac_key;
    uint64_t pass;
} sqlcipher_cipher_ctx_view_t;

typedef struct {
    int32_t store_pass;
    int32_t kdf_iter;
    int32_t fast_kdf_iter;
    int32_t kdf_salt_sz;
    int32_t key_sz;
    int32_t iv_sz;
    int32_t block_sz;
    int32_t page_sz;
    int32_t keyspec_sz;
    int32_t reserve_sz;
    int32_t hmac_sz;
    int32_t plaintext_header_sz;
    int32_t hmac_algorithm;
    int32_t kdf_algorithm;
    uint32_t skip_read_hmac;
    uint32_t need_kdf_salt;
    uint32_t flags;
    uint32_t padding;
    uint64_t kdf_salt;
    uint64_t hmac_kdf_salt;
    uint64_t buffer;
    uint64_t p_btree;
    uint64_t read_ctx;
    uint64_t write_ctx;
    uint64_t provider;
    uint64_t provider_ctx;
} sqlcipher41_codec_ctx_view_t;

typedef struct {
    int32_t store_pass;
    int32_t kdf_iter;
    int32_t fast_kdf_iter;
    int32_t kdf_salt_sz;
    int32_t key_sz;
    int32_t iv_sz;
    int32_t block_sz;
    int32_t page_sz;
    int32_t reserve_sz;
    int32_t hmac_sz;
    int32_t plaintext_header_sz;
    int32_t hmac_algorithm;
    int32_t kdf_algorithm;
    int32_t error;
    uint32_t flags;
    uint32_t padding;
    uint64_t kdf_salt;
    uint64_t hmac_kdf_salt;
    uint64_t buffer;
    uint64_t p_btree;
    uint64_t read_ctx;
    uint64_t write_ctx;
    uint64_t provider;
    uint64_t provider_ctx;
} sqlcipher_modern_codec_ctx_view_t;

_Static_assert(offsetof(sqlcipher41_codec_ctx_view_t, kdf_salt) == 72,
               "unexpected SQLCipher 4.1 codec layout");
_Static_assert(offsetof(sqlcipher41_codec_ctx_view_t, read_ctx) == 104,
               "unexpected SQLCipher 4.1 read context offset");
_Static_assert(offsetof(sqlcipher_modern_codec_ctx_view_t, kdf_salt) == 64,
               "unexpected modern SQLCipher codec layout");
_Static_assert(offsetof(sqlcipher_modern_codec_ctx_view_t, read_ctx) == 96,
               "unexpected modern SQLCipher read context offset");
_Static_assert(offsetof(sqlcipher_cipher_ctx_view_t, key) == 8,
               "unexpected SQLCipher key offset");

/* Forward declaration */
static int read_db_salt(const char *path, char *salt_hex_out);
static int is_hex_char(unsigned char c);

/* nftw callback state for collecting DB files */
#define MAX_DBS 256
static char g_db_salts[MAX_DBS][33];
static char g_db_names[MAX_DBS][256];
static int g_db_count = 0;
static char g_db_root[1024] = {0};

static void bin_to_hex(const unsigned char *value, size_t length, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        out[i * 2] = hex[value[i] >> 4];
        out[i * 2 + 1] = hex[value[i] & 0x0f];
    }
    out[length * 2] = '\0';
}

static int known_salt_index(const unsigned char salt[SALT_SIZE]) {
    char salt_hex[SALT_SIZE * 2 + 1];
    bin_to_hex(salt, SALT_SIZE, salt_hex);
    for (int i = 0; i < g_db_count; i++) {
        if (strcmp(salt_hex, g_db_salts[i]) == 0) return i;
    }
    return -1;
}

static int add_key(key_entry_t keys[MAX_KEYS], int *key_count,
                   const unsigned char key[KEY_SIZE],
                   const unsigned char salt[SALT_SIZE]) {
    char key_hex[KEY_SIZE * 2 + 1];
    char salt_hex[SALT_SIZE * 2 + 1];
    bin_to_hex(key, KEY_SIZE, key_hex);
    bin_to_hex(salt, SALT_SIZE, salt_hex);

    for (int i = 0; i < *key_count; i++) {
        if (strcmp(keys[i].key_hex, key_hex) == 0 &&
            strcmp(keys[i].salt_hex, salt_hex) == 0) return 0;
    }
    if (*key_count >= MAX_KEYS) return 0;

    strcpy(keys[*key_count].key_hex, key_hex);
    strcpy(keys[*key_count].salt_hex, salt_hex);
    (*key_count)++;
    return 1;
}

static int read_task_exact(mach_port_t task, uint64_t address,
                           void *out, size_t length) {
    if (address == 0 || length == 0) return 0;
    mach_vm_size_t copied = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        task, (mach_vm_address_t)address, (mach_vm_size_t)length,
        (mach_vm_address_t)out, &copied);
    return kr == KERN_SUCCESS && copied == length;
}

static int looks_like_sqlcipher41_codec(
        const sqlcipher41_codec_ctx_view_t *ctx) {
    return (ctx->store_pass == 0 || ctx->store_pass == 1) &&
           ctx->kdf_iter >= 1000 && ctx->kdf_iter <= 10000000 &&
           ctx->fast_kdf_iter == 2 &&
           ctx->kdf_salt_sz == SALT_SIZE &&
           ctx->key_sz == KEY_SIZE &&
           ctx->iv_sz == 16 &&
           ctx->block_sz == 16 &&
           ctx->page_sz == 4096 &&
           ctx->keyspec_sz == 99 &&
           ctx->reserve_sz == 80 &&
           ctx->hmac_sz == 64 &&
           ctx->plaintext_header_sz == 0 &&
           ctx->kdf_salt != 0 &&
           ctx->read_ctx != 0;
}

static int looks_like_modern_sqlcipher_codec(
        const sqlcipher_modern_codec_ctx_view_t *ctx) {
    return (ctx->store_pass == 0 || ctx->store_pass == 1) &&
           ctx->kdf_iter >= 1000 && ctx->kdf_iter <= 10000000 &&
           ctx->fast_kdf_iter == 2 &&
           ctx->kdf_salt_sz == SALT_SIZE &&
           ctx->key_sz == KEY_SIZE &&
           ctx->iv_sz == 16 &&
           ctx->block_sz == 16 &&
           ctx->page_sz == 4096 &&
           ctx->reserve_sz == 80 &&
           ctx->hmac_sz == 64 &&
           ctx->plaintext_header_sz == 0 &&
           ctx->kdf_salt != 0 &&
           ctx->read_ctx != 0;
}

static int recover_context_keys(
        mach_port_t task, uint64_t salt_address,
        uint64_t read_context, uint64_t write_context,
        key_entry_t keys[MAX_KEYS], int *key_count) {
    unsigned char salt[SALT_SIZE];
    if (!read_task_exact(task, salt_address, salt, sizeof(salt))) return 0;
    if (known_salt_index(salt) < 0) return 0;

    int found = 0;
    uint64_t context_addresses[2] = {read_context, write_context};
    for (size_t i = 0; i < 2; i++) {
        sqlcipher_cipher_ctx_view_t cipher;
        if (!read_task_exact(task, context_addresses[i], &cipher, sizeof(cipher))) continue;
        if (cipher.derive_key != 0 || cipher.key == 0 ||
            cipher.pass_sz < 0 || cipher.pass_sz > 4096) continue;

        unsigned char key[KEY_SIZE];
        if (!read_task_exact(task, cipher.key, key, sizeof(key))) continue;
        found += add_key(keys, key_count, key, salt);
    }
    return found;
}

static int scan_sqlcipher_codecs(
        mach_port_t task, const unsigned char *buf, size_t length,
        mach_vm_address_t base, key_entry_t keys[MAX_KEYS], int *key_count,
        int *sqlcipher41_count, int *modern_count) {
    int found = 0;
    size_t offset = (size_t)((STRUCT_SCAN_ALIGNMENT -
        (base & (STRUCT_SCAN_ALIGNMENT - 1))) & (STRUCT_SCAN_ALIGNMENT - 1));

    for (; offset + sizeof(sqlcipher_modern_codec_ctx_view_t) <= length;
         offset += STRUCT_SCAN_ALIGNMENT) {
        if (offset + sizeof(sqlcipher41_codec_ctx_view_t) <= length) {
            sqlcipher41_codec_ctx_view_t ctx;
            memcpy(&ctx, buf + offset, sizeof(ctx));
            if (looks_like_sqlcipher41_codec(&ctx)) {
                int recovered = recover_context_keys(
                    task, ctx.kdf_salt, ctx.read_ctx, ctx.write_ctx,
                    keys, key_count);
                found += recovered;
                *sqlcipher41_count += recovered;
            }
        }

        sqlcipher_modern_codec_ctx_view_t modern;
        memcpy(&modern, buf + offset, sizeof(modern));
        if (looks_like_modern_sqlcipher_codec(&modern)) {
            int recovered = recover_context_keys(
                task, modern.kdf_salt, modern.read_ctx, modern.write_ctx,
                keys, key_count);
            found += recovered;
            *modern_count += recovered;
        }
    }
    return found;
}

static int path_has_db_storage(const char *fpath) {
    return strstr(fpath, "/db_storage/") != NULL || strstr(fpath, "db_storage/") == fpath;
}

static int nftw_collect_db(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    if (!path_has_db_storage(fpath)) return 0;
    size_t len = strlen(fpath);
    if (len < 3 || strcmp(fpath + len - 3, ".db") != 0) return 0;
    if (g_db_count >= MAX_DBS) return 0;

    char salt[33];
    if (read_db_salt(fpath, salt) != 0) return 0;

    strcpy(g_db_salts[g_db_count], salt);
    /* Extract relative path from db_storage/ */
    const char *rel = NULL;
    if (g_db_root[0] != '\0' && strncmp(fpath, g_db_root, strlen(g_db_root)) == 0) {
        rel = fpath + strlen(g_db_root);
        if (*rel == '/') rel++;
    }
    if (!rel || !rel[0]) {
        rel = strstr(fpath, "db_storage/");
        if (rel) rel += strlen("db_storage/");
    }
    if (!rel || !rel[0]) {
        rel = strrchr(fpath, '/');
        rel = rel ? rel + 1 : fpath;
    }
    strncpy(g_db_names[g_db_count], rel, 255);
    g_db_names[g_db_count][255] = '\0';
    printf("  %s\n", g_db_names[g_db_count]);
    g_db_count++;
    return 0;
}

static int safe_relative_db_name(const char *name) {
    if (!name || !name[0] || name[0] == '/') return 0;
    if (strcmp(name, "..") == 0 || strncmp(name, "../", 3) == 0 ||
        strstr(name, "/../") != NULL) return 0;
    return strchr(name, '\t') == NULL && strchr(name, '\r') == NULL &&
           strchr(name, '\n') == NULL;
}

static int load_db_salt_manifest(const char *path) {
    FILE *manifest = fopen(path, "r");
    if (!manifest) return -1;

    char line[2048];
    int loaded = 0;
    while (g_db_count < MAX_DBS && fgets(line, sizeof(line), manifest)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        const char *salt = line;
        const char *name = tab + 1;
        if (strlen(salt) != SALT_SIZE * 2 || !safe_relative_db_name(name))
            continue;
        int valid_salt = 1;
        for (size_t i = 0; i < SALT_SIZE * 2; i++) {
            if (!is_hex_char((unsigned char)salt[i])) {
                valid_salt = 0;
                break;
            }
        }
        if (!valid_salt) continue;

        for (size_t i = 0; i < SALT_SIZE * 2; i++) {
            unsigned char value = (unsigned char)salt[i];
            g_db_salts[g_db_count][i] =
                (value >= 'A' && value <= 'F') ? (char)(value + 32) : (char)value;
        }
        g_db_salts[g_db_count][SALT_SIZE * 2] = '\0';
        strncpy(g_db_names[g_db_count], name, 255);
        g_db_names[g_db_count][255] = '\0';
        printf("  %s\n", g_db_names[g_db_count]);
        g_db_count++;
        loaded++;
    }
    fclose(manifest);
    return loaded;
}

static int is_hex_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static pid_t run_pgrep_first(const char *cmd) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    char buf[64];
    pid_t pid = -1;
    if (fgets(buf, sizeof(buf), fp))
        pid = atoi(buf);
    pclose(fp);
    return pid;
}

static pid_t find_wechat_pid(void) {
    const char *commands[] = {
        "pgrep -x WeChat",
        "pgrep -x WeChatAppEx",
        "pgrep -x 微信",
        "pgrep -f '/WeChat\\.app/Contents/MacOS/WeChat($| )'",
        "pgrep -f '/WeChatAppEx\\.app/Contents/MacOS/WeChatAppEx($| )'",
        NULL,
    };

    for (int i = 0; commands[i] != NULL; i++) {
        pid_t pid = run_pgrep_first(commands[i]);
        if (pid > 0)
            return pid;
    }

    return -1;
}

/* Read DB salt (first 16 bytes) and return hex string */
static int read_db_salt(const char *path, char *salt_hex_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    unsigned char header[16];
    if (fread(header, 1, 16, f) != 16) { fclose(f); return -1; }
    fclose(f);
    /* Check if unencrypted */
    if (memcmp(header, "SQLite format 3", 15) == 0) return -1;
    for (int i = 0; i < 16; i++)
        sprintf(salt_hex_out + i * 2, "%02x", header[i]);
    salt_hex_out[32] = '\0';
    return 0;
}

static int run_struct_scanner_self_test(void) {
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    for (int i = 0; i < SALT_SIZE; i++) salt[i] = (unsigned char)(0x20 + i);
    for (int i = 0; i < KEY_SIZE; i++) key[i] = (unsigned char)i;

    g_db_count = 1;
    bin_to_hex(salt, SALT_SIZE, g_db_salts[0]);
    strcpy(g_db_names[0], "self-test.db");

    sqlcipher_cipher_ctx_view_t cipher = {0};
    cipher.derive_key = 0;
    cipher.pass_sz = 32;
    cipher.key = (uint64_t)(uintptr_t)key;

    sqlcipher41_codec_ctx_view_t codec = {0};
    codec.kdf_iter = 256000;
    codec.fast_kdf_iter = 2;
    codec.kdf_salt_sz = SALT_SIZE;
    codec.key_sz = KEY_SIZE;
    codec.iv_sz = 16;
    codec.block_sz = 16;
    codec.page_sz = 4096;
    codec.keyspec_sz = 99;
    codec.reserve_sz = 80;
    codec.hmac_sz = 64;
    codec.kdf_salt = (uint64_t)(uintptr_t)salt;
    codec.read_ctx = (uint64_t)(uintptr_t)&cipher;
    codec.write_ctx = (uint64_t)(uintptr_t)&cipher;

    key_entry_t keys[MAX_KEYS] = {0};
    int key_count = 0;
    int sqlcipher41_count = 0;
    int modern_count = 0;
    int found = scan_sqlcipher_codecs(
        mach_task_self(), (const unsigned char *)&codec, sizeof(codec),
        (mach_vm_address_t)(uintptr_t)&codec, keys, &key_count,
        &sqlcipher41_count, &modern_count);
    char expected_key[KEY_SIZE * 2 + 1];
    bin_to_hex(key, KEY_SIZE, expected_key);
    if (found != 1 || sqlcipher41_count != 1 || modern_count != 0 ||
        key_count != 1 ||
        strcmp(keys[0].key_hex, expected_key) != 0 ||
        strcmp(keys[0].salt_hex, g_db_salts[0]) != 0) {
        fprintf(stderr, "SQLCipher 4.1 structural scanner self-test failed\n");
        return 1;
    }
    memset(keys, 0, sizeof(keys));
    key_count = sqlcipher41_count = modern_count = 0;
    sqlcipher_modern_codec_ctx_view_t modern = {0};
    modern.kdf_iter = 256000;
    modern.fast_kdf_iter = 2;
    modern.kdf_salt_sz = SALT_SIZE;
    modern.key_sz = KEY_SIZE;
    modern.iv_sz = 16;
    modern.block_sz = 16;
    modern.page_sz = 4096;
    modern.reserve_sz = 80;
    modern.hmac_sz = 64;
    modern.kdf_salt = (uint64_t)(uintptr_t)salt;
    modern.read_ctx = (uint64_t)(uintptr_t)&cipher;
    modern.write_ctx = (uint64_t)(uintptr_t)&cipher;
    found = scan_sqlcipher_codecs(
        mach_task_self(), (const unsigned char *)&modern, sizeof(modern),
        (mach_vm_address_t)(uintptr_t)&modern, keys, &key_count,
        &sqlcipher41_count, &modern_count);
    if (found != 1 || sqlcipher41_count != 0 || modern_count != 1 ||
        key_count != 1 || strcmp(keys[0].key_hex, expected_key) != 0 ||
        strcmp(keys[0].salt_hex, g_db_salts[0]) != 0) {
        fprintf(stderr, "modern SQLCipher structural scanner self-test failed\n");
        return 1;
    }
    printf("SQLCipher structural scanner self-test passed (4.1 + modern)\n");
    return 0;
}

int main(int argc, char *argv[]) {
    pid_t pid;
    const char *override_home = NULL;
    const char *override_db_root = NULL;
    const char *salt_manifest = NULL;
    if (argc >= 2 && strcmp(argv[1], "--self-test") == 0)
        return run_struct_scanner_self_test();
    if (argc >= 2)
        pid = atoi(argv[1]);
    else
        pid = find_wechat_pid();
    if (argc >= 3 && argv[2][0] != '\0')
        override_home = argv[2];
    if (argc >= 4 && argv[3][0] != '\0')
        override_db_root = argv[3];
    if (argc >= 5 && argv[4][0] != '\0')
        salt_manifest = argv[4];

    if (pid <= 0) {
        fprintf(stderr, "WeChat not running or invalid PID\n");
        return 1;
    }

    printf("============================================================\n");
    printf("  macOS WeChat Memory Key Scanner (C version)\n");
    printf("============================================================\n");
    printf("WeChat PID: %d\n", pid);

    /* Get task port */
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %d\n", kr);
        fprintf(stderr, "Make sure: (1) running as root, (2) WeChat is ad-hoc signed\n");
        return 1;
    }
    printf("Got task port: %u\n", task);

    /* Resolve real user's HOME (sudo may change HOME to /var/root) */
    const char *home = override_home;
    if (!home || !home[0]) {
        home = getenv("HOME");
        const char *sudo_user = getenv("SUDO_USER");
        if (sudo_user) {
            struct passwd *pw = getpwnam(sudo_user);
            if (pw && pw->pw_dir)
                home = pw->pw_dir;
        }
    }
    if (!home) home = "/root";
    printf("User home: %s\n", home);

    /* Collect DB salts by recursively walking db_storage directories.
     * Note: POSIX glob() does not support ** recursive matching on macOS,
     * so we use nftw() to walk the directory tree instead. */
    printf("\nScanning for DB files...\n");
    if (salt_manifest) {
        int loaded = load_db_salt_manifest(salt_manifest);
        if (loaded >= 0)
            printf("  Loaded %d DB salts from user-staged manifest\n", loaded);
        else
            printf("  Unable to read user-staged DB salt manifest\n");
    }
    if (g_db_count == 0 && override_db_root && override_db_root[0]) {
        char resolved[PATH_MAX];
        const char *db_root = realpath(override_db_root, resolved);
        if (!db_root) db_root = override_db_root;
        strncpy(g_db_root, db_root, sizeof(g_db_root) - 1);
        g_db_root[sizeof(g_db_root) - 1] = '\0';

        struct stat st;
        if (stat(db_root, &st) == 0 && S_ISDIR(st.st_mode)) {
            printf("  Searching configured db_dir: %s\n", db_root);
            nftw(db_root, nftw_collect_db, 20, FTW_PHYS);
        } else {
            printf("  Configured db_dir missing: %s\n", db_root);
        }
    }

    char search_roots[3][512];
    snprintf(search_roots[0], sizeof(search_roots[0]),
        "%s/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
        home);
    snprintf(search_roots[1], sizeof(search_roots[1]),
        "%s/Library/Containers/com.tencent.xinWeChat/Data/Documents",
        home);
    snprintf(search_roots[2], sizeof(search_roots[2]),
        "%s/Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support",
        home);

    if (g_db_count == 0) {
        for (int i = 0; i < 3; i++) {
            struct stat st;
            if (stat(search_roots[i], &st) == 0 && S_ISDIR(st.st_mode)) {
                printf("  Searching: %s\n", search_roots[i]);
                nftw(search_roots[i], nftw_collect_db, 20, FTW_PHYS);
            }
        }
    }
    printf("Found %d encrypted DBs\n", g_db_count);

    /* Scan memory for legacy text keyspecs and SQLCipher 4.1 contexts. */
    printf("\nScanning memory for keys...\n");
    key_entry_t keys[MAX_KEYS];
    int key_count = 0;
    size_t total_scanned = 0;
    int region_count = 0;
    int legacy_count = 0;
    int sqlcipher41_count = 0;
    int modern_count = 0;

    mach_vm_address_t addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;

        kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &info_count, &obj_name);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) { addr++; continue; }  /* guard against infinite loop */

        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) ==
            (VM_PROT_READ | VM_PROT_WRITE)) {
            region_count++;

            mach_vm_address_t ca = addr;
            while (ca < addr + size) {
                mach_vm_size_t cs = addr + size - ca;
                if (cs > CHUNK_SIZE) cs = CHUNK_SIZE;

                vm_offset_t data;
                mach_msg_type_number_t dc;
                kr = mach_vm_read(task, ca, cs, &data, &dc);
                if (kr == KERN_SUCCESS) {
                    unsigned char *buf = (unsigned char *)data;
                    total_scanned += dc;

                    scan_sqlcipher_codecs(
                        task, buf, dc, ca, keys, &key_count,
                        &sqlcipher41_count, &modern_count);

                    for (size_t i = 0; i + HEX_PATTERN_LEN + 3 < dc; i++) {
                        if (buf[i] == 'x' && buf[i + 1] == '\'') {
                            /* Check if followed by 96 hex chars and closing ' */
                            int valid = 1;
                            for (int j = 0; j < HEX_PATTERN_LEN; j++) {
                                if (!is_hex_char(buf[i + 2 + j])) { valid = 0; break; }
                            }
                            if (!valid) continue;
                            if (buf[i + 2 + HEX_PATTERN_LEN] != '\'') continue;

                            /* Extract key and salt hex */
                            char key_hex[65], salt_hex[33];
                            memcpy(key_hex, buf + i + 2, 64);
                            key_hex[64] = '\0';
                            memcpy(salt_hex, buf + i + 2 + 64, 32);
                            salt_hex[32] = '\0';

                            /* Convert to lowercase for comparison */
                            for (int j = 0; key_hex[j]; j++)
                                if (key_hex[j] >= 'A' && key_hex[j] <= 'F')
                                    key_hex[j] += 32;
                            for (int j = 0; salt_hex[j]; j++)
                                if (salt_hex[j] >= 'A' && salt_hex[j] <= 'F')
                                    salt_hex[j] += 32;

                            unsigned char key[KEY_SIZE], salt[SALT_SIZE];
                            for (int j = 0; j < KEY_SIZE; j++) {
                                unsigned int byte;
                                sscanf(key_hex + j * 2, "%2x", &byte);
                                key[j] = (unsigned char)byte;
                            }
                            for (int j = 0; j < SALT_SIZE; j++) {
                                unsigned int byte;
                                sscanf(salt_hex + j * 2, "%2x", &byte);
                                salt[j] = (unsigned char)byte;
                            }
                            legacy_count += add_key(keys, &key_count, key, salt);
                        }
                    }
                    mach_vm_deallocate(mach_task_self(), data, dc);
                }
                /* Keep enough overlap for both the 99-byte keyspec and the
                 * 136-byte codec context view. */
                if (cs > STRUCT_SCAN_OVERLAP)
                    ca += cs - STRUCT_SCAN_OVERLAP;
                else
                    ca += cs;
            }
        }
        addr += size;
    }

    printf("\nScan complete: %zuMB scanned, %d regions, %d unique candidates\n",
           total_scanned / 1024 / 1024, region_count, key_count);
    printf("Candidate sources: legacy=%d sqlcipher41=%d modern=%d\n",
           legacy_count, sqlcipher41_count, modern_count);

    /* Match keys to DBs without printing key material. */
    int matched = 0;
    for (int i = 0; i < key_count; i++) {
        const char *db = NULL;
        for (int j = 0; j < g_db_count; j++) {
            if (strcmp(keys[i].salt_hex, g_db_salts[j]) == 0) {
                db = g_db_names[j];
                matched++;
                break;
            }
        }
        if (db) printf("  candidate matched database: %s\n", db);
    }
    printf("\nMatched %d/%d keys to known DBs\n", matched, key_count);

    /* Save JSON: { "rel/path.db": { "enc_key": "hex" }, ... }
     * Uses forward slashes (native macOS paths, valid JSON without escaping).
    */
    const char *out_path = "all_keys.json";
    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    FILE *fp = out_fd >= 0 ? fdopen(out_fd, "w") : NULL;
    if (fp) {
        fprintf(fp, "{\n");
        int first = 1;
        for (int i = 0; i < key_count; i++) {
            const char *db = NULL;
            for (int j = 0; j < g_db_count; j++) {
                if (strcmp(keys[i].salt_hex, g_db_salts[j]) == 0) {
                    db = g_db_names[j];
                    break;
                }
            }
            if (!db) continue;
            fprintf(fp, "%s  \"%s\": {\"enc_key\": \"%s\"}",
                first ? "" : ",\n", db, keys[i].key_hex);
            first = 0;
        }
        fprintf(fp, "\n}\n");
        fclose(fp);
        printf("Saved to %s\n", out_path);
    } else if (out_fd >= 0) {
        close(out_fd);
    }

    return 0;
}
