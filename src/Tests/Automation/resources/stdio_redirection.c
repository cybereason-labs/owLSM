#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <binary_path> <file_path> <socket_path>\n", argv[0]);
        return 1;
    }

    const char *binary_path = argv[1];
    const char *file_path = argv[2];
    const char *socket_path = argv[3];

    // Check if binary exists and is executable
    if (access(binary_path, X_OK) != 0) {
        fprintf(stderr, "Error: Binary '%s' not found or not executable: %s\n", 
                binary_path, strerror(errno));
        return 1;
    }

    // Check if file exists (we'll open it for writing)
    if (access(file_path, F_OK) != 0) {
        fprintf(stderr, "Error: File '%s' not found: %s\n", file_path, strerror(errno));
        return 1;
    }

    // Check if socket exists
    struct stat st;
    if (stat(socket_path, &st) != 0) {
        fprintf(stderr, "Error: Socket '%s' not found: %s\n", socket_path, strerror(errno));
        return 1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a socket\n", socket_path);
        return 1;
    }

    // Create pipe for stdin
    int pipe_fds[2];
    if (pipe(pipe_fds) != 0) {
        perror("pipe");
        return 1;
    }

    // Open file for stdout
    int file_fd = open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (file_fd < 0) {
        perror("open file");
        return 1;
    }

    // Connect to socket for stderr
    int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("connect");
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {  // Child
        // Redirect stdin to pipe read end
        dup2(pipe_fds[0], STDIN_FILENO);
        close(pipe_fds[0]);
        close(pipe_fds[1]);

        // Redirect stdout to file
        dup2(file_fd, STDOUT_FILENO);
        close(file_fd);

        // Redirect stderr to socket
        dup2(sock_fd, STDERR_FILENO);
        close(sock_fd);

        // Exec the binary
        execl(binary_path, binary_path, NULL);
        perror("execl");
        exit(1);
    }

    // Parent
    close(pipe_fds[0]);
    close(file_fd);
    close(sock_fd);
    close(pipe_fds[1]);

    wait(NULL);
    return 0;
}

