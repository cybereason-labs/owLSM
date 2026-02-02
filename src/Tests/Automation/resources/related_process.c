#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        fprintf(stderr, "Usage: %s <sleep_time> <file_path>\n", argv[0]);
        return 1;
    }

    int sleep_time = atoi(argv[1]);
    const char *path = argv[2];

    sleep(sleep_time);

    FILE *file = fopen(path, "w");
    if(!file)
    {
        perror("Failed to open file");
        return 1;
    }
    fprintf(file, "Starting related_process (PID: %d)\n", getpid());
    fclose(file);

    for(int i = 0; i < 10; i++)
    {
        pid_t pid = fork();
        
        if(pid == 0)
        {
            file = fopen(path, "a");
            if(file)
            {
                fprintf(file, "Child %d (PID: %d)\n", i, getpid());
                fclose(file);
            }
            
            pid_t grandchild_pid = fork();
            if(grandchild_pid == 0)
            {
                // Grandchild process
                file = fopen(path, "a");
                if(file)
                {
                    fprintf(file, "Grandchild %d (PID: %d)\n", i, getpid());
                    fclose(file);
                }
                
                execlp("echo", "echo", "related_process", NULL);
                perror("Exec failed");
                exit(1);
            }
            
            // Child exits after creating grandchild
            exit(0);
        }
        else
        {
            file = fopen(path, "a");
            if(file)
            {
                fprintf(file, "Parent iteration %d (PID: %d)\n", i, getpid());
                fclose(file);
            }
        }
    }
    
    // Parent waits for all children to avoid zombies
    for(int i = 0; i < 10; i++)
    {
        wait(NULL);
    }
    
    return 0;
}

