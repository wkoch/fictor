#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* No provider credential is compiled in or supplied to this process. The host
 * searches these bounded observations and checks independent benign canaries. */
extern char **environ;
static char *volatile memory_control;
static size_t entries, file_bytes, files, fd_files, memory_bytes, memory_regions;
static size_t special_regions, nonreadable_regions, fd_entries;
static char *output_root;
static unsigned char buffer[65536];

static void fail(const char *operation) { perror(operation); exit(90); }
static char *join(const char *root, const char *name) {
    char *path = NULL;
    if (asprintf(&path, "%s/%s", root, name) < 0) fail("path");
    return path;
}
static void emit(int fd, const void *bytes, size_t size) {
    const unsigned char *cursor = bytes;
    while (size) {
        ssize_t count = write(fd, cursor, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail("write");
        cursor += count;
        size -= (size_t)count;
    }
}
static int output(const char *name) {
    char *path = join(output_root, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    free(path);
    if (fd < 0) fail("output");
    return fd;
}
static void copy_file(int source, int target, size_t limit) {
    off_t offset = 0;
    for (;;) {
        ssize_t count = pread(source, buffer, sizeof(buffer), offset);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) fail("file read");
        if (!count) break;
        if ((size_t)offset + (size_t)count > limit ||
            file_bytes + (size_t)count > 8 * 1024 * 1024) {
            errno = EFBIG; fail("file bound");
        }
        emit(target, buffer, (size_t)count);
        offset += count;
        file_bytes += (size_t)count;
    }
}
static void walk(const char *path, unsigned depth, int target) {
    if (!strcmp(path, output_root)) return; /* Never read our growing dumps. */
    if (++entries > 128 || depth > 8) { errno = EFBIG; fail("tree bound"); }
    struct stat metadata;
    if (lstat(path, &metadata)) fail("stat");
    if (S_ISDIR(metadata.st_mode)) {
        DIR *directory = opendir(path);
        if (!directory) fail("directory");
        struct dirent *entry;
        for (;;) {
            errno = 0;
            entry = readdir(directory);
            if (!entry) {
                if (errno) fail("directory read");
                break;
            }
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
            char *child = join(path, entry->d_name);
            walk(child, depth + 1, target);
            free(child);
        }
        closedir(directory);
    } else if (S_ISREG(metadata.st_mode)) {
        int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) fail("file open");
        copy_file(fd, target, 1024 * 1024);
        close(fd);
        files++;
    } else { errno = EINVAL; fail("unexpected fixture entry"); }
}
static void denied(const char *root, const char *suffix) {
    char *path = join(root, suffix);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    int error = errno;
    free(path);
    if (fd >= 0) { close(fd); errno = EACCES; fail("private path was visible"); }
    if (error != ENOENT && error != EACCES && error != ENOTDIR) {
        errno = error; fail("private path");
    }
}
static void model_request(void) {
    const char *proxy = getenv("HTTP_PROXY");
    if (!proxy || strncmp(proxy, "http://", 7)) fail("proxy missing");
    const char *end = strchr(proxy + 7, '@');
    if (!end || end - (proxy + 7) > 128) fail("proxy credentials");
    unsigned char credentials[132] = {0};
    size_t length = (size_t)(end - (proxy + 7));
    memcpy(credentials, proxy + 7, length);
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char basic[180];
    size_t encoded = 0;
    for (size_t i = 0; i < length; i += 3) {
        unsigned value = (unsigned)credentials[i] << 16 |
            (unsigned)credentials[i + 1] << 8 | credentials[i + 2];
        basic[encoded++] = alphabet[(value >> 18) & 63];
        basic[encoded++] = alphabet[(value >> 12) & 63];
        basic[encoded++] = i + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        basic[encoded++] = i + 2 < length ? alphabet[value & 63] : '=';
    }
    basic[encoded] = 0;
    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) fail("socket");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(3128)};
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1 ||
        connect(socket_fd, (struct sockaddr *)&address, sizeof(address))) fail("proxy connect");
    const char body[] = "public-request";
    char request[1024];
    int size = snprintf(request, sizeof(request),
        "POST http://models.fictor.internal/p/i4/v1/messages HTTP/1.1\r\n"
        "Host: models.fictor.internal\r\nProxy-Authorization: Basic %s\r\n"
        "Authorization: extension-placeholder\r\nX-Api-Key: extension-placeholder\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s", basic, strlen(body), body);
    if (size <= 0 || (size_t)size >= sizeof(request)) fail("request bound");
    emit(socket_fd, request, (size_t)size);
    char response[65536];
    size_t used = 0;
    for (;;) {
        ssize_t count = read(socket_fd, response + used, sizeof(response) - 1 - used);
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) fail("response read");
        if (!count) break;
        used += (size_t)count;
        if (used == sizeof(response) - 1) { errno = EFBIG; fail("response bound"); }
    }
    close(socket_fd);
    response[used] = 0;
    if (strncmp(response, "HTTP/1.1 200 ", 13)) fail("model status");
    int wire = output("response-wire");
    emit(wire, response, used);
    close(wire);
}
static void memory_dump(void) {
    FILE *maps = fopen("/proc/self/maps", "re");
    int memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    int dump = output("memory");
    if (!maps || memory < 0) fail("memory access");
    char line[8192], permissions[5];
    unsigned long long begin, end;
    while (fgets(line, sizeof(line), maps)) {
        if (!strchr(line, '\n') || sscanf(line, "%llx-%llx %4s", &begin, &end, permissions) != 3)
            fail("maps format");
        if (permissions[0] != 'r') { nonreadable_regions++; continue; }
        /* Kernel VVAR mappings advertise read permission but /proc/self/mem
         * cannot read them. No ordinary read error is silently skipped. */
        if (strstr(line, "[vvar]") || strstr(line, "[vvar_vclock]")) {
            special_regions++;
            continue;
        }
        memory_regions++;
        for (unsigned long long offset = begin; offset < end;) {
            size_t count = (size_t)(end - offset);
            if (count > sizeof(buffer)) count = sizeof(buffer);
            if (memory_bytes + count > 64 * 1024 * 1024) {
                errno = EFBIG; fail("memory bound");
            }
            ssize_t read_count = pread(memory, buffer, count, (off_t)offset);
            if (read_count < 0 && errno == EINTR) continue;
            if (read_count < 0 || (size_t)read_count != count) fail("memory page");
            emit(dump, buffer, count);
            memory_bytes += count;
            offset += count;
        }
    }
    if (ferror(maps)) fail("maps read");
    fclose(maps);
    close(memory);
    close(dump);
}
int main(int argc, char **argv) {
    if (argc != 4 || !getenv("FICTOR_WORKSPACE") || !getenv("VISIBLE_CONTROL")) return 80;
    alarm(15);
    /* Only the prefix is compiled in. Construct the complete control in a
     * private heap allocation, then disclose it in the report after capture. */
    unsigned char random[16];
    if (getrandom(random, sizeof(random), 0) != (ssize_t)sizeof(random)) fail("random control");
    memory_control = malloc(43);
    if (!memory_control) fail("memory control");
    memcpy(memory_control, "I4_MEMORY_", 10);
    for (size_t i = 0; i < sizeof(random); i++)
        snprintf(memory_control + 10 + 2 * i, 3, "%02x", random[i]);
    char descriptor_control[39];
    memcpy(descriptor_control, "I4_FD_", 6);
    for (size_t i = 0; i < sizeof(random); i++)
        snprintf(descriptor_control + 6 + 2 * i, 3, "%02x", random[i]);
    output_root = join(getenv("FICTOR_WORKSPACE"), "i4-observations");
    if (mkdir(output_root, 0700)) fail("output directory");
    denied(argv[1], "secrets.toml");
    denied(argv[1], "fictor.db");
    denied(argv[2], ".aws/credentials");
    model_request();
    int environment = output("environment");
    for (char **value = environ; *value; value++) emit(environment, *value, strlen(*value) + 1);
    close(environment);
    int observations = output("files");
    char *data_control = join(argv[3], "data-control");
    int data = open(data_control, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (data < 0) fail("ext_data control");
    emit(data, "I4_EXT_DATA_CONTROL", 19);
    close(data);
    free(data_control);
    char *tmp_control = join(getenv("TMPDIR"), "tmp-control");
    int temporary = open(tmp_control, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (temporary < 0) fail("tmp control");
    emit(temporary, "I4_TMP_CONTROL", strlen("I4_TMP_CONTROL"));
    close(temporary);
    free(tmp_control);
    char *descriptor_path = join(getenv("TMPDIR"), "descriptor-control");
    int low_control = open(descriptor_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (low_control < 0 || unlink(descriptor_path)) fail("descriptor control");
    free(descriptor_path);
    emit(low_control, descriptor_control, strlen(descriptor_control));
    int control = fcntl(low_control, F_DUPFD_CLOEXEC, 128);
    if (control < 128) fail("high descriptor control");
    close(low_control);
    walk(getenv("FICTOR_WORKSPACE"), 0, observations);
    walk(argv[3], 0, observations);
    walk(getenv("TMPDIR"), 0, observations);
    close(observations);
    int descriptors = output("descriptors");
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) fail("descriptor directory");
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) {
            if (errno) fail("descriptor directory read");
            break;
        }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (++fd_entries > 128) { errno = EFBIG; fail("descriptor bound"); }
        char *end;
        long value = strtol(entry->d_name, &end, 10);
        if (errno || *end || value < 0 || value > INT_MAX) fail("descriptor format");
        int fd = (int)value;
        if (fd == descriptors || fd == dirfd(directory)) continue;
        struct stat metadata;
        if (fstat(fd, &metadata)) fail("descriptor stat");
        if (!S_ISREG(metadata.st_mode)) continue;
        copy_file(fd, descriptors, 1024 * 1024);
        fd_files++;
    }
    closedir(directory);
    close(control);
    close(descriptors);
    memory_dump();
    int report = output("report.json");
    dprintf(report, "{\"files\":%zu,\"fd_files\":%zu,\"file_bytes\":%zu,"
        "\"memory_bytes\":%zu,\"memory_regions\":%zu,\"special_regions\":%zu,"
        "\"nonreadable_regions\":%zu,\"denied_paths\":3,\"memory_control\":\"%s\","
        "\"fd_control\":\"%s\",\"fd_control_fd\":%d,\"fd_entries\":%zu}\n",
        files, fd_files, file_bytes, memory_bytes, memory_regions, special_regions,
        nonreadable_regions, memory_control, descriptor_control, control, fd_entries);
    close(report);
    return memory_control[0] == 'I' ? 0 : 81;
}
