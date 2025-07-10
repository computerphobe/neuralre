#include <stdio.h>
#include <string.h>

void flag()
{
    printf("Access granted, you did great, here is the flag \n Flag : CTF{rev_engineering_ftw}\n");
}

int main()
{
    char input[100];
    printf("Enter Password : ");
    scanf("%99s", input);

    for (int i = 0; i < strlen(input); i++)
    {
        input[i] ^= 0x55;
    }
    const char correct[] = {'x' ^ 0x55, 'Z' ^ 0x55, 'T' ^ 0x55, 'D' ^ 0x55, '{' ^ 0x55,
                            'r' ^ 0x55, 'e' ^ 0x55, 'v' ^ 0x55, '_' ^ 0x55, '1' ^ 0x55,
                            '2' ^ 0x55, '3' ^ 0x55, '}' ^ 0x55, '\0'};
    if (strcmp(input, correct) == 0)
    {
        flag();
    }
    else{
        printf("Wrong password\n");
    }
    return 0;
}