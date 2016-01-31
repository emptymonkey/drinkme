
/**********************************************************************************************************************
 *
 *	drinkme
 *
 *
 *	emptymonkey's shellcode testing tool
 *	2014-10-31
 *
 *
 *	The drinkme tool takes shellcode as input on stdin, and executes it. This is only intended as a simple framework
 *	for testing shellcode.
 *
 *
 *	The formats supported are:
 *		* "\x##"
 *		* "x##"
 *		* "0x##"
 *		* "##"
 *
 *	The following characters will be ignored:
 *		* All whitespace, including newlines. (If entering directly through a tty, remember to hit ctrl+d to send EOF.)
 *		* '\'
 *		* '"'
 *		* ','
 *		* ';'
 *		* C and C++ style comments will be appropriately handled.
 *
 *
 *	Now you too can cut and paste shellcode straight from the internet with wild abandon!
 *
 **********************************************************************************************************************/



#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>



#define NO_COMMENT			0
#define COMMENT_OPEN		1		// '/' found.
#define COMMENT_C				2		// '/*' found.
#define COMMENT_C_CLOSE	3		// '/* ... *' found.
#define COMMENT_CPP			4		// '//' found.



char *program_invocation_short_name;
char *CALLING_CARD = "@emptymonkey - https://github.com/emptymonkey";



void usage(){
	fprintf(stderr, "\nusage: %s [-p] [-h]\n", program_invocation_short_name);
	fprintf(stderr, "\t-p\tPrint the formatted shellcode. Don't execute it.\n");
	fprintf(stderr, "\t-h\tPrint this help message.\n");
	fprintf(stderr, "\n\tExample:\t%s <hello_world.x86_64\n\n", program_invocation_short_name);
	exit(-1);
}



int main(int argc, char **argv){

	int retval;

	unsigned int i = 0;
	unsigned int j = 0;

	char *sc;
	unsigned int sc_len;

	char byte[5];

	unsigned int comment = 0;

	int opt;
	int execute = 1;



	if((program_invocation_short_name = strrchr(argv[0], '/'))){
		program_invocation_short_name++;
	}else{
		program_invocation_short_name = argv[0];
	}


	while ((opt = getopt(argc, argv, "ph")) != -1) {
		switch (opt) {

			case 'p':
				execute = 0;
				break;

			case 'h':
			default:
				usage();
		}
	}


	memset(byte, 0, sizeof(byte));

	/* Max shellcode size is one page of memory. This is arbitrary. Feel free to change as fits your need. */
	sc_len = getpagesize();


	/* Since we will be changing our mapping later to be executable, I'd prefer not to use malloc() / calloc(),
		 but rather just grab memory directly with mmap(). This also fits our strategy of having a pagesized 
		 buffer. */
	errno = 0;
	sc = (char *) mmap(NULL, sc_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(errno){
		error(-1, errno, "mmap(NULL, %d, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)", sc_len);
	}


	while((retval = read(STDIN_FILENO, &(byte[j]), 1)) == 1){

		/* Handle the comments case. */
		if(byte[j] == '/'){
			switch(comment){

				case NO_COMMENT:
					comment = COMMENT_OPEN;
					byte[j] = '\0';
					continue;

				case COMMENT_OPEN:
					comment = COMMENT_CPP;
					byte[j] = '\0';
					continue;

				case COMMENT_C_CLOSE:
					comment = NO_COMMENT;
					byte[j] = '\0';
					continue;

				case COMMENT_CPP:
				case COMMENT_C:
					break;
			}
		}

		if(byte[j] == '*'){
			switch(comment){

				case COMMENT_OPEN:
					comment = COMMENT_C;
					byte[j] = '\0';
					continue;

				case COMMENT_C:
					comment = COMMENT_C_CLOSE;
					byte[j] = '\0';
					continue;

				case NO_COMMENT:
				case COMMENT_CPP:
				case COMMENT_C_CLOSE:
					break;
			}
		}

		if(byte[j] == '\n'){
			switch(comment){

				case COMMENT_OPEN:
				case COMMENT_CPP:
					comment = NO_COMMENT;
					break;

				case COMMENT_C_CLOSE:
					comment = COMMENT_C;
					break;

				case NO_COMMENT:
				case COMMENT_C:
					break;
			}
		}

		if(comment == COMMENT_C || comment == COMMENT_CPP){
			byte[j] = '\0';
			continue;
		}


		if( \
				isspace(byte[j]) || \
				byte[j] == '"' || \
				byte[j] == ',' || \
				byte[j] == ';' || \
				byte[j] == '\\' \
			){
			byte[j] = '\0';
			continue;
		}

		// Case: 0x## takes care of itself.
		if((j == 1) && !((byte[0] == '0') && (byte[1] == 'x'))){
			if(byte[0] == 'x'){
				byte[0] = '0';
				byte[1] = 'x';
				j = 1;

			}else{
				byte[3] = byte[1];
				byte[2] = byte[0];
				byte[0] = '0';
				byte[1] = 'x';
				j = 3;
			}
		}

		j++;

		if(!(j % 4)){

			if(i == sc_len - 1){
				error(-1, 0, "Shellcode too long. Max size is %d bytes. Quitting.\n", sc_len - 1);
			}

			sc[i] = (char) strtol(byte, NULL, 16);

			i++;
			j = 0;
		}
	}

	if(retval == -1){
		error(-1, errno, "read(%d, %p, %d)", STDIN_FILENO, (void *) &(byte[j]), 1);
	}

	/* Now, politely ask the kernel to make our char array executable. */
	if(mprotect(sc, sc_len, PROT_READ|PROT_EXEC) == -1){
		error(-1, errno, "mprotect(%p, %d, PROT_READ|PROT_EXEC)", (void *) sc, sc_len);
	}


	if(execute){

		/* Let's check if we have a reasonable tty setup. If not, we'll do our best to reset it,
		   just in case the shellcode requires it. */
		if(!isatty(STDIN_FILENO)){
			if(isatty(STDOUT_FILENO)){
			
				if(close(STDIN_FILENO) == -1){
					error(-1, errno, "close(STDIN_FILENO)");
				}
	
				if(dup2(STDOUT_FILENO, STDIN_FILENO) == -1){
					error(-1, errno, "dup2(STDOUT_FILENO, STDIN_FILENO)");
				}
			}
		}

		/*  <3 C  */
		((int (*)()) sc)();

	}else{

		for(j = 0; j < i; j++){
			printf("\\x%02hhx", sc[j]);
		}
		printf("\n");

	}


	/* Shouldn't ever be here. */
	return(-1);
}
