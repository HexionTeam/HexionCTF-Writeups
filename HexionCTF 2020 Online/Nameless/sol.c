#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

int main()
{
	FILE *out = fopen("out.txt", "r");
    char buff[35] = {0}, test[35] = {0};
	fread(buff, 1, 34, out);
	unsigned int t = 1586541672;
	
	do
	{
		srand(t++);
		for(char i = 0; i < 6; i++)
			test[i] = buff[i] ^ rand() % 0x666 + 1;
	} while(strcmp(test, "hexCTF"));

	srand(t - 1);
	for(char i = 0; i < 34; i++)
		test[i] = buff[i] ^ rand() % 0x666 + 1;

	printf("%s\n", test);

    fclose(out);
}