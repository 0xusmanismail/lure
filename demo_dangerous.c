#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    FILE *f = fopen("/etc/passwd", "r");
    if (f) {
        char buf[256];
        fgets(buf, sizeof(buf), f);
        fclose(f);
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = inet_addr("93.184.216.34");
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    printf("done\n");
    return 0;
}
