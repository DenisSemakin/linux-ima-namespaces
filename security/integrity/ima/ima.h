/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima.h
 *	internal Integrity Measurement Architecture (IMA) definitions
 */

#ifndef __LINUX_IMA_H
#define __LINUX_IMA_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>
#include <linux/ima.h>
#include <crypto/hash_info.h>

#include "../integrity.h"

#ifdef CONFIG_HAVE_IMA_KEXEC
#include <asm/ima.h>
#endif

enum ima_show_type { IMA_SHOW_BINARY, IMA_SHOW_BINARY_NO_FIELD_LEN,
		     IMA_SHOW_BINARY_OLD_STRING_FMT, IMA_SHOW_ASCII };
enum tpm_pcrs { TPM_PCR0 = 0, TPM_PCR8 = 8 };

/* digest size for IMA, fits SHA1 or MD5 */
#define IMA_DIGEST_SIZE		SHA1_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX	255

#define IMA_HASH_BITS 9
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

#define IMA_TEMPLATE_FIELD_ID_MAX_LEN	16
#define IMA_TEMPLATE_NUM_FIELDS_MAX	15

#define IMA_TEMPLATE_IMA_NAME "ima"
#define IMA_TEMPLATE_IMA_FMT "d|n"

/* set during initialization */
extern int ima_hash_algo;
extern int ima_appraise;

/* IMA event related data */
struct ima_event_data {
	struct integrity_iint_cache *iint;
	struct file *file;
	const unsigned char *filename;
	struct evm_ima_xattr_data *xattr_value;
	int xattr_len;
	const char *violation;
};

/* IMA template field data definition */
struct ima_field_data {
	u8 *data;
	u32 len;
};

/* IMA template field definition */
struct ima_template_field {
	const char field_id[IMA_TEMPLATE_FIELD_ID_MAX_LEN];
	int (*field_init)(struct ima_event_data *event_data,
			  struct ima_field_data *field_data);
	void (*field_show)(struct seq_file *m, enum ima_show_type show,
			   struct ima_field_data *field_data);
};

/* IMA template descriptor definition */
struct ima_template_desc {
	struct list_head list;
	char *name;
	char *fmt;
	int num_fields;
	struct ima_template_field **fields;
};

struct ima_template_entry {
	int pcr;
	u8 digest[TPM_DIGEST_SIZE];	/* sha1 or md5 measurement hash */
	struct ima_template_desc *template_desc; /* template descriptor */
	u32 template_data_len;
	struct ima_field_data template_data[0];	/* template related data */
};

struct ima_queue_entry {
	struct hlist_node hnext;	/* place in hash collision list */
	struct list_head later;		/* place in ima_measurements list */
	struct ima_template_entry *entry;
};

/* Some details preceding the binary serialized measurement list */
struct ima_kexec_hdr {
	u16 version;
	u16 _reserved0;
	u32 _reserved1;
	u64 buffer_size;
	u64 count;
};

#ifdef CONFIG_HAVE_IMA_KEXEC
void ima_load_kexec_buffer(void);
#else
static inline void ima_load_kexec_buffer(void) {}
#endif /* CONFIG_HAVE_IMA_KEXEC */

/*
 * The default binary_runtime_measurements list format is defined as the
 * platform native format.  The canonical format is defined as little-endian.
 */
extern bool ima_canonical_fmt;

struct ns_status {
	struct kref ref;
	struct list_head ns_next;
	struct rb_node rb_node;
	struct integrity_iint_cache *iint;
	struct inode *inode;
	struct ima_namespace *ns;
	ino_t i_ino;
	u32 i_generation;
	unsigned long flags;
	unsigned long measured_pcrs;
};

static inline struct ns_status *ns_status_get(struct ns_status *status)
{
	if (status)
		kref_get(&status->ref);
	return status;
}

void ns_status_free(struct kref *ref);

static inline void ns_status_put(struct ns_status *status)
{
	if (status)
		kref_put(&status->ref, ns_status_free);
}

void ns_status_off_list_free(struct list_head *list);

/* Internal IMA function definitions */
int ima_init(void);
int ima_fs_init(void);
int ima_add_template_entry(struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename,
			   struct ima_namespace *ns);
int ima_calc_file_hash(struct file *file, struct ima_digest_data *hash);
int ima_calc_buffer_hash(const void *buf, loff_t len,
			 struct ima_digest_data *hash);
int ima_calc_field_array_hash(struct ima_field_data *field_data,
			      struct ima_template_desc *desc, int num_fields,
			      struct ima_digest_data *hash);
int __init ima_calc_boot_aggregate(struct ima_digest_data *hash);
void ima_add_violation(struct file *file, const unsigned char *filename,
		       struct integrity_iint_cache *iint,
		       const char *op, const char *cause,
		       struct ima_namespace *ns);
int ima_init_crypto(void);
void ima_putc(struct seq_file *m, void *data, int datalen);
void ima_print_digest(struct seq_file *m, u8 *digest, u32 size);
struct ima_template_desc *ima_template_desc_current(void);
int ima_restore_measurement_entry(struct ima_template_entry *entry,
				  struct ima_namespace *ns);
int ima_restore_measurement_list(loff_t bufsize, void *buf,
				 struct ima_namespace *ns);
int ima_measurements_show(struct seq_file *m, void *v);
unsigned long ima_get_binary_runtime_size(void);
int ima_init_template(void);
void ima_init_template_list(void);

int ima_ns_fs_init(struct ima_namespace *ns, struct dentry *parent);
void ima_ns_fs_free(struct ima_namespace *ns);

/*
 * used to protect h_table and sha_table
 */
extern spinlock_t ima_queue_lock;

static inline unsigned long ima_hash_key(u8 *digest)
{
	return hash_long(*digest, IMA_HASH_BITS);
}

#define __ima_hooks(hook)		\
	hook(NONE)			\
	hook(FILE_CHECK)		\
	hook(MMAP_CHECK)		\
	hook(BPRM_CHECK)		\
	hook(CREDS_CHECK)		\
	hook(POST_SETATTR)		\
	hook(MODULE_CHECK)		\
	hook(FIRMWARE_CHECK)		\
	hook(KEXEC_KERNEL_CHECK)	\
	hook(KEXEC_INITRAMFS_CHECK)	\
	hook(POLICY_CHECK)		\
	hook(MAX_CHECK)
#define __ima_hook_enumify(ENUM)	ENUM,

enum ima_hooks {
	__ima_hooks(__ima_hook_enumify)
};

/* LIM API function definitions */
int ima_get_action(struct inode *inode, const struct cred *cred, u32 secid,
		   int mask, enum ima_hooks func, int *pcr,
		   struct ima_namespace *ns, struct ima_namespace *policy_ns);
int ima_must_measure(struct inode *inode, int mask, enum ima_hooks func);
int ima_collect_measurement(struct integrity_iint_cache *iint,
			    struct ns_status *status,
			    struct file *file, void *buf, loff_t size,
			    enum hash_algo algo);
void ima_store_measurement(struct integrity_iint_cache *iint, struct file *file,
			   const unsigned char *filename,
			   struct evm_ima_xattr_data *xattr_value,
			   int xattr_len, int pcr,
			   struct ns_status *status);
void ima_audit_measurement(struct integrity_iint_cache *iint,
			   const unsigned char *filename,
			   struct ns_status *status);
int ima_alloc_init_template(struct ima_event_data *event_data,
			    struct ima_template_entry **entry);
int ima_store_template(struct ima_template_entry *entry, int violation,
		       struct inode *inode,
		       const unsigned char *filename, int pcr,
		       struct ima_namespace *ns);
void ima_free_template_entry(struct ima_template_entry *entry);
const char *ima_d_path(const struct path *path, char **pathbuf, char *filename);

/* IMA policy related functions */
int ima_match_policy(struct inode *inode, const struct cred *cred, u32 secid,
		     enum ima_hooks func, int mask, int flags, int *pcr,
		     struct ima_namespace *ns, struct ima_namespace *policy_ns,
		     struct user_namespace *user_ns);
void ima_init_policy(void);
void ima_update_policy(struct ima_namespace *ns);
void ima_update_policy_flag(struct ima_namespace *ns);
ssize_t ima_parse_add_rule(char *rule, struct ima_namespace *ns);
void ima_delete_rules(struct list_head *ima_policy_rules);
int ima_check_policy(struct ima_namespace *ns);
void *ima_policy_start(struct seq_file *m, loff_t *pos);
void *ima_policy_next(struct seq_file *m, void *v, loff_t *pos);
void ima_policy_stop(struct seq_file *m, void *v);
int ima_policy_show(struct seq_file *m, void *v);

static inline struct list_head *get_measurements(struct ima_namespace *ns)
{
	return &ns->ima_measurements;
}

static inline struct list_head **get_current_ima_rules(void)
{
	return &current->nsproxy->ima_ns->ima_rules;
}

static inline struct list_head **get_ima_rules(struct ima_namespace *ns)
{
	return &ns->ima_rules;
}

static inline struct list_head *get_ima_policy_rules(struct ima_namespace *ns)
{
	return &ns->ima_policy_rules;
}

static inline struct list_head *get_current_ima_policy_rules(void)
{
	return &current->nsproxy->ima_ns->ima_policy_rules;
}


/* Appraise integrity measurements */
#define IMA_APPRAISE_ENFORCE	0x01
#define IMA_APPRAISE_FIX	0x02
#define IMA_APPRAISE_LOG	0x04
#define IMA_APPRAISE_MODULES	0x08
#define IMA_APPRAISE_FIRMWARE	0x10
#define IMA_APPRAISE_POLICY	0x20
#define IMA_APPRAISE_KEXEC	0x40

#ifdef CONFIG_IMA_APPRAISE
int ima_appraise_measurement(enum ima_hooks func,
			     struct integrity_iint_cache *iint,
			     struct file *file, const unsigned char *filename,
			     struct evm_ima_xattr_data *xattr_value,
			     int xattr_len);
int ima_must_appraise(struct inode *inode, int mask, enum ima_hooks func,
		      struct user_namespace *user_ns);
void ima_update_xattr(struct integrity_iint_cache *iint, struct file *file);
enum integrity_status ima_get_cache_status(struct integrity_iint_cache *iint,
					   enum ima_hooks func);
enum hash_algo ima_get_hash_algo(struct evm_ima_xattr_data *xattr_value,
				 int xattr_len);
int ima_read_xattr(struct dentry *dentry,
		   struct evm_ima_xattr_data **xattr_value);

#else
static inline int ima_appraise_measurement(enum ima_hooks func,
					   struct integrity_iint_cache *iint,
					   struct file *file,
					   const unsigned char *filename,
					   struct evm_ima_xattr_data *xattr_value,
					   int xattr_len)
{
	return INTEGRITY_UNKNOWN;
}

static inline int ima_must_appraise(struct inode *inode, int mask,
				    enum ima_hooks func,
				    struct user_namespace *userns)
{
	return 0;
}

static inline void ima_update_xattr(struct integrity_iint_cache *iint,
				    struct file *file)
{
}

static inline enum integrity_status ima_get_cache_status(struct integrity_iint_cache
							 *iint,
							 enum ima_hooks func)
{
	return INTEGRITY_UNKNOWN;
}

static inline enum hash_algo
ima_get_hash_algo(struct evm_ima_xattr_data *xattr_value, int xattr_len)
{
	return ima_hash_algo;
}

static inline int ima_read_xattr(struct dentry *dentry,
				 struct evm_ima_xattr_data **xattr_value)
{
	return 0;
}

#endif /* CONFIG_IMA_APPRAISE */

#define IMA_NS_STATUS_ACTIONS   (IMA_AUDIT | IMA_MEASURE)
#define IMA_NS_STATUS_FLAGS     (IMA_AUDITED | IMA_MEASURED)

int ima_ns_init(void);
struct ima_namespace;
int ima_init_namespace(struct ima_namespace *ns);

struct ns_status *ima_get_ns_status(struct ima_namespace *ns,
				    struct inode *inode,
				    struct integrity_iint_cache *iint);

#ifdef CONFIG_IMA_NS
unsigned long iint_flags(struct integrity_iint_cache *iint,
			 struct ns_status *status);
unsigned long set_iint_flags(struct integrity_iint_cache *iint,
			     struct ns_status *status, unsigned long flags);
#else
static inline unsigned long iint_flags(struct integrity_iint_cache *iint,
				       struct ns_status *status)
{
	return iint->flags;
}
static inline unsigned long set_iint_flags(struct integrity_iint_cache *iint,
					   struct ns_status *status,
					   unsigned long flags)
{
	iint->flags = flags;
	return flags;
}
#endif /* CONFIG_IMA_NS */

/* LSM based policy rules require audit */
#ifdef CONFIG_IMA_LSM_RULES

#define security_filter_rule_init security_audit_rule_init
#define security_filter_rule_match security_audit_rule_match

#else

static inline int security_filter_rule_init(u32 field, u32 op, char *rulestr,
					    void **lsmrule)
{
	return -EINVAL;
}

static inline int security_filter_rule_match(u32 secid, u32 field, u32 op,
					     void *lsmrule,
					     struct audit_context *actx)
{
	return -EINVAL;
}
#endif /* CONFIG_IMA_LSM_RULES */

static inline struct ima_namespace *to_ima_ns(struct ns_common *ns)
{
	return container_of(ns, struct ima_namespace, ns);
}

#ifdef CONFIG_IMA_NS

extern const struct proc_ns_operations imans_operations;

struct ima_namespace *copy_ima(struct user_namespace *user_ns,
			       struct ima_namespace *old_ns);


static inline struct ima_namespace *get_current_ns(void)
{
	return current->nsproxy->ima_ns;
}

void free_ns_status_cache(struct ima_namespace *ns);

#else

static inline struct ima_namespace *get_current_ns(void)
{
	return &init_ima_ns;
}

#endif /* CONFIG_IMA_NS */

#ifdef	CONFIG_IMA_READ_POLICY
#define	POLICY_FILE_FLAGS	0666 /* rw-rw-rw- */
#else
#define	POLICY_FILE_FLAGS	0222 /* -w--w--w- */
#endif /* CONFIG_IMA_READ_POLICY */

#endif /* __LINUX_IMA_H */
