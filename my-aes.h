#ifndef AES_H
#define AES_H

#include <linux/printk.h>
#include <linux/kernel.h>

#define my_aes_info(fmt, ...) \
	pr_info("[my_aes]: "fmt, ##__VA_ARGS__)

#define my_aes_err(fmt, ...) \
	pr_err("[my_aes]: "fmt, ##__VA_ARGS__)

#define my_aes_debug(fmt, ...) \
	pr_debug("[my_aes]: "fmt, ##__VA_ARGS__)

#endif /* AES_H */
