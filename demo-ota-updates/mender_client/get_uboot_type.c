#include <stdio.h>                                                              
#include <stdlib.h>                                                             
#include <fcntl.h>                                                              
#include <sys/mman.h>                                                           
#include <unistd.h>                                                             
                                                                                
#define page_base 0x70000000                                                     
                                                                                
int main()                                                
{                          
    size_t pagesize = sysconf(_SC_PAGE_SIZE);
                                                                               
    int fd = open("/dev/mem", O_SYNC | O_RDWR);
    if (fd < 0) {                                                               
        perror ("Can't open /dev/mem ! \n");
        return -1;                                                              
    }                                                                           

    unsigned int *mem = (unsigned int *) mmap (NULL, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, page_base);
    if (mem == MAP_FAILED) {                                                    
        perror ("Can't map memory, maybe the address is not truncated\n");
        return -1;                                                              
     }
   printf("%d", mem[0]);
    FILE *fp;
    fp = fopen("/var/lib/mender/uboot_type.txt", "wb");
    if(fp == NULL)
       return -1;            
    fprintf(fp, "%d", mem[0]);
    return mem[0];
}
