#include <stdio.h>
#include <string.h>
#include <stdbool.h>

bool isPasswordOK(void) {
    char Password[12];

    gets(Password);
    return 0 == strcmp(Password, "goodpass");
}

int main(void) {
    bool pwStatus;

    puts("Enter Password: ");
    pwStatus = isPasswordOK();
    if (pwStatus == false) {
        puts("Access denied");
        return -1;
    }
    else {
        puts("Access granted!");
        return 0;
    }
}
view rawvulnerable