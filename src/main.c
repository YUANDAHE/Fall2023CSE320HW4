#include <stdlib.h>

#include "deet.h"

void handleKillAll() {
    // Use the system function to execute the "ps" command
    // and check for any processes related to your program
    FILE* psOutput = popen("ps aux | grep your_program_name", "r");
    if (psOutput == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    // Read the output of the "ps" command line by line
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), psOutput) != NULL) {
        // Print or process the information as needed
        printf("%s", buffer);
    }

    // Close the file stream
    if (pclose(psOutput) == -1) {
        perror("pclose");
        exit(EXIT_FAILURE);
    }

    // Now, you can decide whether to terminate these processes using the "kill" command
    // For example, you can use the system function to execute "kill -9 <PID>" for each process
}

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "killall") == 0) {
        // Handle the "killall" command
        handleKillAll();
        return 0;
    }

    // Your main program logic here

    return 0;
}
