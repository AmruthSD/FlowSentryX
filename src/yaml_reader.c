#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAP_PATH "/sys/fs/bpf/my_bpf_map"
#define MAP_NAME "my_bpf_map"

union bpf_attr my_map {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100
};

// Function to create a new BPF map
int create_bpf_map() {
    int fd = bpf(BPF_MAP_CREATE, &my_map, sizeof(my_map));
    if (map_fd < 0) {
        perror("Error creating new BPF map");
        return -1;
    }
    
    // Pin the map to a filesystem path for persistent access
    if (bpf_obj_pin(map_fd, MAP_PATH) < 0) {
        perror("Error pinning BPF map");
        close(map_fd);
        return -1;
    }
    
    printf("New BPF map created and pinned at %s\n", MAP_PATH);
    return map_fd;
}

int main() {
    // Attempt to open the existing map
    union bpf_attr attr = {};
    attr.pathname = (uint64_t)path;

    int fd = bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    int map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        if (errno == ENOENT) {
            // Map does not exist, create a new one
            printf("Map not found. Creating a new BPF map...\n");
            map_fd = create_bpf_map();
            if (map_fd < 0) {
                return 1; // Error already printed in create_bpf_map()
            }
        } else {
            // Another error occurred
            perror("Error opening existing BPF map");
            return 1;
        }
    } else {
        printf("Existing BPF map opened successfully.\n");
    }

    // Clear the map if needed (call clear_bpf_map() function from the previous example)
    // clear_bpf_map(map_fd);

    // Close the map file descriptor
    close(map_fd);

    return 0;
}
