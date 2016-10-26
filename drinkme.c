
/**********************************************************************************************************************
 *
 *  drinkme
 *
 *
 *  emptymonkey's shellcode testing tool
 *  2014-10-31
 *
 *
 *  The drinkme tool takes shellcode as input on stdin, and executes it. This is only intended as a simple framework
 *  for testing shellcode.
 *
 *
 *  The formats supported are:
 *    * "\x##"
 *    * "x##"
 *    * "0x##"
 *    * "##"
 *
 *  The following characters will be ignored:
 *    * All whitespace, including newlines. (If entering directly through a tty, remember to hit ctrl+d to send EOF.)
 *    * '\'
 *    * '"'
 *    * ','
 *    * ';'
 *    * C and C++ style comments will be appropriately handled.
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



/* As we step through the input, we will maintain a state machine to handle comments. */
#define NO_COMMENT       0    /* Base case.                                           */
#define COMMENT_OPEN     1    /* Case: '/'                                            */
#define COMMENT_C        2    /* Case: '/' + '*'                                      */
#define COMMENT_C_CLOSE  3    /* Case: '/' + '*' + ... + '*'                          */
#define COMMENT_CPP      4    /* Case: '/' + '/'                                      */



char *program_invocation_short_name;
char *CALLING_CARD = "@emptymonkey - https://github.com/emptymonkey";



void usage(){
	fprintf(stderr, "\nusage:    %s [-p] [-h]\n", program_invocation_short_name);
	fprintf(stderr, "           -p  Print the formatted shellcode. Don't execute it.\n");
	fprintf(stderr, "           -h  Print this help message.\n");
	fprintf(stderr, "\nExample:  cat hello_world.x86_64 | %s\n\n", program_invocation_short_name);
	exit(-1);
}



int main(int argc, char **argv){

	/* Used for testing return conditions. */
	int retval;

	/* sc is the buffer for holding the raw shellcode. */
	char *sc;
	unsigned int sc_count = 0;

	/* This is a temp buffer to hold a two-byte sequence. Once filled out, it
		 will be used with strtol() to push two bytes to the shellcode buffer. */
	char byte[5];
	unsigned int byte_count = 0;

	/* (pagesize * num_pages) will be the allocated size of the sc buffer. */
	unsigned int pagesize, num_pages;

	/* State machine variable. */
	unsigned int comment = 0;

	/* For cli options. */
	int opt;
	int execute = 1;

	/* Temp variables used in the manual reallocing of space. */
	char *tmp_ptr;
	unsigned int tmp_uint;


	/* Setup a posix version of the GNU program_invocation_short_name. */
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
	pagesize = getpagesize();
	num_pages = 1;


	/* Since we will be changing our mapping later to be executable, I'd prefer not to use malloc() / calloc(),
		 but rather just grab memory directly with mmap(). This also fits our strategy of having a pagesized buffer.  */
	errno = 0;
	sc = (char *) mmap(NULL, (num_pages * pagesize), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(errno){
		error(-1, errno, "mmap(NULL, %d, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)", (num_pages * pagesize));
	}


	/* Step through the input. */
	while((retval = read(STDIN_FILENO, &(byte[byte_count]), 1)) == 1){

		/* Handle the comments case. */
		if(byte[byte_count] == '/'){
			switch(comment){

				case NO_COMMENT:
					comment = COMMENT_OPEN;
					byte[byte_count] = '\0';
					continue;

				case COMMENT_OPEN:
					comment = COMMENT_CPP;
					byte[byte_count] = '\0';
					continue;

				case COMMENT_C_CLOSE:
					comment = NO_COMMENT;
					byte[byte_count] = '\0';
					continue;

				case COMMENT_CPP:
				case COMMENT_C:
					break;
			}
		}

		if(byte[byte_count] == '*'){
			switch(comment){

				case COMMENT_OPEN:
					comment = COMMENT_C;
					byte[byte_count] = '\0';
					continue;

				case COMMENT_C:
					comment = COMMENT_C_CLOSE;
					byte[byte_count] = '\0';
					continue;

				case NO_COMMENT:
				case COMMENT_CPP:
				case COMMENT_C_CLOSE:
					break;
			}
		}

		if(byte[byte_count] == '\n'){
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
			byte[byte_count] = '\0';
			continue;
		}


		/* Filter the characters we explicitly ignore. */
		if( \
				isspace(byte[byte_count]) || \
				byte[byte_count] == '"' || \
				byte[byte_count] == ',' || \
				byte[byte_count] == ';' || \
				byte[byte_count] == '\\' \
			){
			byte[byte_count] = '\0';
			continue;
		}

		if((byte_count == 1) && !((byte[0] == '0') && (byte[1] == 'x'))){
			/* Case: x##
				 Since '\' is ignored, Case \x## devolves to this one. */
			if(byte[0] == 'x'){
				byte[2] = byte[1];
				byte[1] = byte[0];
				byte[0] = '0';
				byte_count = 2;

			/* Case: ## */
			}else{
				byte[3] = byte[1];
				byte[2] = byte[0];
				byte[0] = '0';
				byte[1] = 'x';
				byte_count = 3;
			}
		}
		/* Case: 0x## takes care of itself. */

		byte_count++;

		/* When !(byte_count % 4) then the byte[] array is ready to be processed. */
		if(!(byte_count % 4)){

			/* If the count is bigger than the buffer, time for us to allocate more space. 
				 This is a manual version of realloc using mmap(), memcpy(), and munmap(). */
			if(sc_count == (num_pages * pagesize) - 1){
				tmp_uint = num_pages++;

				errno = 0;
				tmp_ptr = (char *) mmap(NULL, (num_pages * pagesize), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
				if(errno){
					error(-1, errno, "mmap(NULL, %d, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)", (num_pages * pagesize));
				}
				memcpy(tmp_ptr, sc, (tmp_uint * pagesize));
				munmap(sc, (tmp_uint * pagesize));
				sc = tmp_ptr;
			}

			sc[sc_count] = (char) strtol(byte, NULL, 16);

			sc_count++;
			byte_count = 0;
		}
	}

	if(retval == -1){
		error(-1, errno, "read(%d, %p, %d)", STDIN_FILENO, (void *) &(byte[byte_count]), 1);
	}

	/* Now, politely ask the kernel to make our char array executable. */
	if(mprotect(sc, (num_pages * pagesize), PROT_READ|PROT_EXEC) == -1){
		error(-1, errno, "mprotect(%p, %d, PROT_READ|PROT_EXEC)", (void *) sc, (num_pages * pagesize));
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

		for(byte_count = 0; byte_count < sc_count; byte_count++){
			printf("%02hhx", sc[byte_count]);
		}
		printf("\n");

	}


	/* Shouldn't ever be here. */
	return(-1);
}
