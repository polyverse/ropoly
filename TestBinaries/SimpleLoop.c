#include <stdio.h>
#include <stdlib.h>
int main() {
    int numOverflows = 10;
    int i = -1;
    int j = numOverflows - 1;
    int printCount = 0;
    while (1) {
        i++;
        if (!i) {
            j++;
            if (j == numOverflows) {
                char buffer[40];
                snprintf(buffer, 100, "Infinite loop is running %d\n", printCount);
                printf(buffer);
                printCount++;
                j = 0;
            }
        }
    }
    return i;
}