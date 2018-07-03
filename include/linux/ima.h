/*
 * Copyright (C) 2008 IBM Corporation
 * Author: Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */

#ifndef _LINUX_IMA_H
#define _LINUX_IMA_H

#include <linux/fs.h>
#include <linux/security.h>
#include <linux/kexec.h>
struct linux_binprm;

#ifdef CONFIG_IMA
extern int ima_bprm_check(struct linux_binprm *bprm);
extern int ima_file_check(struct file *file, int mask);
extern void ima_file_free(struct file *file);
extern int ima_file_mmap(struct file *file, unsigned long prot);
extern int ima_load_data(enum kernel_load_data_id id);
extern int ima_read_file(struct file *file, enum kernel_read_file_id id);
extern int ima_post_read_file(struct file *file, void *buf, loff_t size,
			      enum kernel_read_file_id id);
extern void ima_post_path_mknod(struct dentry *dentry);

#ifdef CONFIG_IMA_KEXEC
extern void ima_add_kexec_buffer(struct kimage *image);
#endif

#else
static inline int ima_bprm_check(struct linux_binprm *bprm)
{
	return 0;
}

static inline int ima_file_check(struct file *file, int mask)
{
	return 0;
}

static inline void ima_file_free(struct file *file)
{
	return;
}

static inline int ima_file_mmap(struct file *file, unsigned long prot)
{
	return 0;
}

static inline int ima_load_data(enum kernel_load_data_id id)
{
	return 0;
}

static inline int ima_read_file(struct file *file, enum kernel_read_file_id id)
{
	return 0;
}

static inline int ima_post_read_file(struct file *file, void *buf, loff_t size,
				     enum kernel_read_file_id id)
{
	return 0;
}

static inline void ima_post_path_mknod(struct dentry *dentry)
{
	return;
}

static inline int ima_namespace_set_tpm_chip(struct ima_namespace *ns,
					     struct tpm_provider *tpm_provider,
					     struct tpm_chip *chip)
{
	return -ENODEV;
}
#endif /* CONFIG_IMA */

#ifndef CONFIG_IMA_KEXEC
struct kimage;

static inline void ima_add_kexec_buffer(struct kimage *image)
{}
#endif

#ifdef CONFIG_IMA_APPRAISE
extern void ima_inode_post_setattr(struct dentry *dentry);
extern int ima_inode_setxattr(struct dentry *dentry, const char *xattr_name,
		       const void *xattr_value, size_t xattr_value_len);
extern int ima_inode_removexattr(struct dentry *dentry, const char *xattr_name);
#else
static inline void ima_inode_post_setattr(struct dentry *dentry)
{
	return;
}

static inline int ima_inode_setxattr(struct dentry *dentry,
				     const char *xattr_name,
				     const void *xattr_value,
				     size_t xattr_value_len)
{
	return 0;
}

static inline int ima_inode_removexattr(struct dentry *dentry,
					const char *xattr_name)
{
	return 0;
}
#endif /* CONFIG_IMA_APPRAISE */

#ifndef IMA_HASH_BITS
#define IMA_HASH_BITS 9
#endif
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

struct ima_h_table {
	/* Number of stored measurements in the list */
	atomic_long_t len;
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
};

enum {
	IMAFS_DENTRY_DIR = 0,
	IMAFS_DENTRY_BINARY_RUNTIME_MEASUREMENTS,
	IMAFS_DENTRY_ASCII_RUNTIME_MEASUREMENTS,
	IMAFS_DENTRY_RUNTIME_MEASUREMENTS_COUNT,
	IMAFS_DENTRY_VIOLATIONS,
	IMAFS_DENTRY_IMA_POLICY,
	IMAFS_DENTRY_NAMESPACES,
	IMAFS_DENTRY_UNSHARE,
	IMAFS_DENTRY_LAST
};

struct ima_namespace {
	struct kref kref;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct ima_namespace *parent;
	struct rb_root ns_status_tree;
	rwlock_t ns_status_lock;
	struct kmem_cache *ns_status_cache;

	struct rw_semaphore tpm_chip_lock;
	struct tpm_chip *tpm_chip;
	bool extended_pcr;
	struct tpm_provider *tpm_provider;

	struct list_head ima_measurements;
	struct ima_h_table ima_htable;

	/* securityfs entries */
	struct {
		unsigned long ima_fs_flags;
		struct dentry *dentry[IMAFS_DENTRY_LAST];
		bool dentries_mapped;
	} sfs;

	/* Pointer to ns's current policy */
	struct list_head *ima_rules;
	struct list_head ima_temp_rules;
	/* ns's policy rules */
	struct list_head ima_policy_rules;
	/* for policy quick check */
	int ima_policy_flag;
	struct list_head iint_list;
	int valid_policy;
};

struct tpm_provider {
	void (*release_chip)(struct tpm_chip *chip);
};

extern struct ima_namespace init_ima_ns;
extern struct list_head ima_default_rules;

#ifdef CONFIG_IMA_NS

struct ima_namespace *copy_ima_ns(bool copy, struct user_namespace *user_ns,
				  struct ima_namespace *old_ns);

void free_ima_ns(struct kref *kref);

static inline struct ima_namespace *get_ima_ns(struct ima_namespace *ns)
{
	if (ns)
		kref_get(&ns->kref);
	return ns;
}

static inline void put_ima_ns(struct ima_namespace *ns)
{
	if (ns)
		kref_put(&ns->kref, free_ima_ns);
}

void ima_free_queue_entries(struct ima_namespace *ns);

int ima_namespace_set_tpm_chip(struct ima_namespace *ns,
			       struct tpm_provider *tpm_provider,
			       struct tpm_chip *chip);
#else

static inline struct ima_namespace *copy_ima_ns(bool copy,
						struct user_namespace *user_ns,
						struct ima_namespace *old_ns)
{
	return old_ns;
}

static inline struct ima_namespace *get_ima_ns(struct ima_namespace *ns)
{
	return ns;
}

static inline void put_ima_ns(struct ima_namespace *ns)
{
}

static inline int ima_namespace_set_tpm_chip(struct ima_namespace *ns,
					     struct tpm_provider *tpm_provider,
					     struct tpm_chip *chip)
{
	return -ENODEV;
}
#endif /* CONFIG_IMA_NS */
#endif /* _LINUX_IMA_H */
