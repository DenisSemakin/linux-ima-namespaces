/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Kylene Hall <kjhall@us.ibm.com>
 * Reiner Sailer <sailer@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_fs.c
 *	implemenents security file system for reporting
 *	current measurement list and IMA statistics
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fcntl.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/parser.h>
#include <linux/vmalloc.h>
#include <linux/ima.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/security.h>

#include "ima.h"

static struct vfsmount *imafs_mnt;

static DEFINE_MUTEX(ima_write_mutex);

bool ima_canonical_fmt;
static int __init default_canonical_fmt_setup(char *str)
{
#ifdef __BIG_ENDIAN
	ima_canonical_fmt = true;
#endif
	return 1;
}
__setup("ima_canonical_fmt", default_canonical_fmt_setup);

#define TMPBUFLEN 12
static ssize_t ima_show_htable_value(char __user *buf, size_t count,
				     loff_t *ppos, atomic_long_t *val)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t len;

	len = scnprintf(tmpbuf, TMPBUFLEN, "%li\n", atomic_long_read(val));
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, len);
}

static ssize_t ima_show_htable_violations(struct file *filp,
					  char __user *buf,
					  size_t count, loff_t *ppos)
{
	struct ima_namespace *ns = filp->private_data;

	return ima_show_htable_value(buf, count, ppos,
				     &ns->ima_htable.violations);
}

static const struct file_operations ima_htable_violations_ops = {
	.open = simple_open,
	.read = ima_show_htable_violations,
	.llseek = generic_file_llseek,
};

static ssize_t ima_show_measurements_count(struct file *filp,
					   char __user *buf,
					   size_t count, loff_t *ppos)
{
	struct ima_namespace *ns = filp->private_data;

	return ima_show_htable_value(buf, count, ppos, &ns->ima_htable.len);
}

static const struct file_operations ima_measurements_count_ops = {
	.open = simple_open,
	.read = ima_show_measurements_count,
	.llseek = generic_file_llseek,
};

/* returns pointer to hlist_node */
static void *ima_measurements_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct ima_queue_entry *qe;
	struct ima_namespace *ns = m->file->f_inode->i_private;

	/* we need a lock since pos could point beyond last element */
	rcu_read_lock();
	list_for_each_entry_rcu(qe, get_measurements(ns), later) {
		if (!l--) {
			rcu_read_unlock();
			return qe;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *ima_measurements_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ima_queue_entry *qe = v;
	struct ima_namespace *ns = m->file->f_inode->i_private;

	/* lock protects when reading beyond last element
	 * against concurrent list-extension
	 */
	rcu_read_lock();
	qe = list_entry_rcu(qe->later.next, struct ima_queue_entry, later);
	rcu_read_unlock();
	(*pos)++;

	return (&qe->later == get_measurements(ns)) ? NULL : qe;
}

static void ima_measurements_stop(struct seq_file *m, void *v)
{
}

void ima_putc(struct seq_file *m, void *data, int datalen)
{
	while (datalen--)
		seq_putc(m, *(char *)data++);
}

/* print format:
 *       32bit-le=pcr#
 *       char[20]=template digest
 *       32bit-le=template name size
 *       char[n]=template name
 *       [eventdata length]
 *       eventdata[n]=template specific data
 */
int ima_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	u32 pcr, namelen, template_data_len; /* temporary fields */
	bool is_ima_template = false;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/*
	 * 1st: PCRIndex
	 * PCR used defaults to the same (config option) in
	 * little-endian format, unless set in policy
	 */
	pcr = !ima_canonical_fmt ? e->pcr : cpu_to_le32(e->pcr);
	ima_putc(m, &pcr, sizeof(e->pcr));

	/* 2nd: template digest */
	ima_putc(m, e->digest, TPM_DIGEST_SIZE);

	/* 3rd: template name size */
	namelen = !ima_canonical_fmt ? strlen(template_name) :
		cpu_to_le32(strlen(template_name));
	ima_putc(m, &namelen, sizeof(namelen));

	/* 4th:  template name */
	ima_putc(m, template_name, strlen(template_name));

	/* 5th:  template length (except for 'ima' template) */
	if (strcmp(template_name, IMA_TEMPLATE_IMA_NAME) == 0)
		is_ima_template = true;

	if (!is_ima_template) {
		template_data_len = !ima_canonical_fmt ? e->template_data_len :
			cpu_to_le32(e->template_data_len);
		ima_putc(m, &template_data_len, sizeof(e->template_data_len));
	}

	/* 6th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		enum ima_show_type show = IMA_SHOW_BINARY;
		struct ima_template_field *field = e->template_desc->fields[i];

		if (is_ima_template && strcmp(field->field_id, "d") == 0)
			show = IMA_SHOW_BINARY_NO_FIELD_LEN;
		if (is_ima_template && strcmp(field->field_id, "n") == 0)
			show = IMA_SHOW_BINARY_OLD_STRING_FMT;
		field->field_show(m, show, &e->template_data[i]);
	}
	return 0;
}

static const struct seq_operations ima_measurments_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_measurements_show
};

static int ima_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_measurments_seqops);
}

static const struct file_operations ima_measurements_ops = {
	.open = ima_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

void ima_print_digest(struct seq_file *m, u8 *digest, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		seq_printf(m, "%02x", *(digest + i));
}

/* print in ascii */
static int ima_ascii_measurements_show(struct seq_file *m, void *v)
{
	/* the list never shrinks, so we don't need a lock here */
	struct ima_queue_entry *qe = v;
	struct ima_template_entry *e;
	char *template_name;
	int i;

	/* get entry */
	e = qe->entry;
	if (e == NULL)
		return -1;

	template_name = (e->template_desc->name[0] != '\0') ?
	    e->template_desc->name : e->template_desc->fmt;

	/* 1st: PCR used (config option) */
	seq_printf(m, "%2d ", e->pcr);

	/* 2nd: SHA1 template hash */
	ima_print_digest(m, e->digest, TPM_DIGEST_SIZE);

	/* 3th:  template name */
	seq_printf(m, " %s", template_name);

	/* 4th:  template specific data */
	for (i = 0; i < e->template_desc->num_fields; i++) {
		seq_puts(m, " ");
		if (e->template_data[i].len == 0)
			continue;

		e->template_desc->fields[i]->field_show(m, IMA_SHOW_ASCII,
							&e->template_data[i]);
	}
	seq_puts(m, "\n");
	return 0;
}

static const struct seq_operations ima_ascii_measurements_seqops = {
	.start = ima_measurements_start,
	.next = ima_measurements_next,
	.stop = ima_measurements_stop,
	.show = ima_ascii_measurements_show
};

static int ima_ascii_measurements_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ima_ascii_measurements_seqops);
}

static const struct file_operations ima_ascii_measurements_ops = {
	.open = ima_ascii_measurements_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static ssize_t ima_read_policy(char *path, struct ima_namespace *ns)
{
	void *data;
	char *datap;
	loff_t size;
	int rc, pathlen = strlen(path);

	char *p;

	/* remove \n */
	datap = path;
	strsep(&datap, "\n");

	rc = kernel_read_file_from_path(path, &data, &size, 0, READING_POLICY);
	if (rc < 0) {
		pr_err("Unable to open file: %s (%d)", path, rc);
		return rc;
	}

	datap = data;
	while (size > 0 && (p = strsep(&datap, "\n"))) {
		pr_debug("rule: %s\n", p);
		rc = ima_parse_add_rule(p, ns);
		if (rc < 0)
			break;
		size -= rc;
	}

	vfree(data);
	if (rc < 0)
		return rc;
	else if (size)
		return -EINVAL;
	else
		return pathlen;
}

static ssize_t ima_write_policy(struct file *file, const char __user *buf,
				size_t datalen, loff_t *ppos)
{
	char *data;
	ssize_t result;
	struct ima_namespace *ns = file->private_data;

	if (datalen >= PAGE_SIZE)
		datalen = PAGE_SIZE - 1;

	/* No partial writes. */
	result = -EINVAL;
	if (*ppos != 0)
		goto out;

	data = memdup_user_nul(buf, datalen);
	if (IS_ERR(data)) {
		result = PTR_ERR(data);
		goto out;
	}

	result = mutex_lock_interruptible(&ima_write_mutex);
	if (result < 0)
		goto out_free;

	if (data[0] == '/') {
		result = ima_read_policy(data, ns);
	} else if (ns->ima_appraise & IMA_APPRAISE_POLICY) {
		pr_err("signed policy file (specified as an absolute pathname) required\n");
		integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
				    "policy_update", "signed policy required",
				    1, 0);
		if (ns->ima_appraise & IMA_APPRAISE_ENFORCE)
			result = -EACCES;
	} else {
		result = ima_parse_add_rule(data, ns);
	}
	mutex_unlock(&ima_write_mutex);
out_free:
	kfree(data);
out:
	if (result < 0)
		ns->valid_policy = 0;

	return result;
}

static struct dentry *ima_dir;
static struct dentry *ima_symlink;

enum ima_fs_flags {
	IMA_FS_BUSY,
};

#ifdef	CONFIG_IMA_READ_POLICY
static const struct seq_operations ima_policy_seqops = {
		.start = ima_policy_start,
		.next = ima_policy_next,
		.stop = ima_policy_stop,
		.show = ima_policy_show,
};
#endif

/*
 * ima_open_policy: sequentialize access to the policy file
 */
static int ima_open_policy(struct inode *inode, struct file *filp)
{
	struct ima_namespace *ns = inode->i_private;

	if (!(filp->f_flags & O_WRONLY)) {
#ifndef	CONFIG_IMA_READ_POLICY
		return -EACCES;
#else
		if ((filp->f_flags & O_ACCMODE) != O_RDONLY)
			return -EACCES;
		if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN))
			return -EPERM;
		return seq_open(filp, &ima_policy_seqops);
#endif
	}

	filp->private_data = ns;

	if (test_and_set_bit(IMA_FS_BUSY, &ns->sfs.ima_fs_flags))
		return -EBUSY;
	return 0;
}

/*
 * ima_release_policy - start using the new measure policy rules.
 *
 * Initially, ima_measure points to the default policy rules, now
 * point to the new policy rules, and remove the securityfs policy file,
 * assuming a valid policy.
 */
static int ima_release_policy(struct inode *inode, struct file *file)
{
	struct ima_namespace *ns = inode->i_private;
	const char *cause = ns->valid_policy ? "completed" : "failed";

	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		return seq_release(inode, file);

	if (ns->valid_policy && ima_check_policy(ns) < 0) {
		cause = "failed";
		ns->valid_policy = 0;
	}

	pr_info("policy update %s\n", cause);
	integrity_audit_msg(AUDIT_INTEGRITY_STATUS, NULL, NULL,
			    "policy_update", cause, !ns->valid_policy, 0);

	if (!ns->valid_policy) {
		ima_delete_rules(&ns->ima_temp_rules);
		ns->valid_policy = 1;
		clear_bit(IMA_FS_BUSY, &ns->sfs.ima_fs_flags);
		return 0;
	}

	ima_update_policy(ns);
#if !defined(CONFIG_IMA_WRITE_POLICY) && !defined(CONFIG_IMA_READ_POLICY)
	securityfs_remove(ns->sfs.dentry[IMAFS_DENTRY_IMA_POLICY]);
	ns->sfs.dentry[IMAFS_DENTRY_IMA_POLICY] = NULL;
#elif defined(CONFIG_IMA_WRITE_POLICY)
	clear_bit(IMA_FS_BUSY, &ns->sfs.ima_fs_flags);
#elif defined(CONFIG_IMA_READ_POLICY)
	inode->i_mode &= ~S_IWUSR;
#endif
	return 0;
}

static const struct file_operations ima_measure_policy_ops = {
	.open = ima_open_policy,
	.write = ima_write_policy,
	.read = seq_read,
	.release = ima_release_policy,
	.llseek = generic_file_llseek,
};

#ifdef CONFIG_IMA_NS
static int ima_open_unshare(struct inode *inode, struct file *filp)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

static ssize_t ima_write_unshare(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	ssize_t length;
	char *page;
	bool set;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	page = memdup_user_nul(buf, count);
	if (IS_ERR(page))
		return PTR_ERR(page);

	length = -EINVAL;
	if (kstrtobool(page, &set))
		goto out;

	current->ima_ns_for_child = set;

	length = count;
out:
	kfree(page);

	return length;
}

static const struct file_operations ima_unshare_ops = {
	.open = ima_open_unshare,
	.write = ima_write_unshare,
};
#endif

static void ima_fs_fixup_uid_gid(struct ima_namespace *ns)
{
	unsigned i;
	kuid_t kuid;
	kgid_t kgid;

	if (ns->sfs.dentries_mapped)
		return;

	kuid = make_kuid(current_user_ns(), 0);
	if (__kuid_val(kuid) == 0)
		return;

	kgid = make_kgid(current_user_ns(), 0);
	for (i = 0; i < IMAFS_DENTRY_LAST; i++) {
		ns->sfs.dentry[i]->d_inode->i_uid = kuid;
		ns->sfs.dentry[i]->d_inode->i_gid = kgid;
	}
	ns->sfs.dentries_mapped = true;
}

static const char * ima_symlink_get_link(struct dentry *dentry,
					 struct inode *inode,
					 struct delayed_call *done)
{
	struct path path;
	struct ima_namespace *ns = get_current_ns();

	if (!dentry)
		return ERR_PTR(-ECHILD);

	ima_fs_fixup_uid_gid(ns);
	path.mnt = mntget(imafs_mnt);
	path.dentry = dget(ns->sfs.dentry[IMAFS_DENTRY_DIR]
	                   ? ns->sfs.dentry[IMAFS_DENTRY_DIR]
	                   : ima_dir);
	nd_jump_link(&path);

	return NULL;
}

static int ima_symlink_readlink(struct dentry *dentry, char __user *buffer,
				int buflen)
{
	return readlink_copy(buffer, buflen, ".ima");
}

static const struct inode_operations ima_symlink_link_iops = {
	.readlink = ima_symlink_readlink,
	.get_link = ima_symlink_get_link,
};

void ima_ns_fs_free(struct ima_namespace *ns)
{
	signed i;

	for (i = IMAFS_DENTRY_LAST - 1; i >= 0; i--) {
		securityfs_remove(ns->sfs.dentry[i]);
		ns->sfs.dentry[i] = NULL;
	}
}

int ima_ns_fs_init(struct ima_namespace *ns, struct dentry *parent)
{
	char name[32];
	unsigned i;
	int err;
	struct dentry *dir;
	umode_t mode = (ns->user_ns == &init_user_ns)
			? S_IRUSR | S_IRGRP
			: S_IROTH;

	if (parent) {
		snprintf(name, sizeof(name), "ima:[%u]", ns->ns.inum);

		i = IMAFS_DENTRY_DIR;
		ns->sfs.dentry[i] = securityfs_create_dir(name, parent);
		if (IS_ERR(ns->sfs.dentry[i])) {
			err = PTR_ERR(ns->sfs.dentry[i]);
			goto out;
		}
		dir = ns->sfs.dentry[i];
	} else {
		dir = ima_dir;
	}

	i = IMAFS_DENTRY_BINARY_RUNTIME_MEASUREMENTS;
	ns->sfs.dentry[i] =
	    securityfs_create_file("binary_runtime_measurements",
				   mode, dir, ns,
				   &ima_measurements_ops);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}

	i = IMAFS_DENTRY_ASCII_RUNTIME_MEASUREMENTS;
	ns->sfs.dentry[i] =
	    securityfs_create_file("ascii_runtime_measurements",
				   mode, dir, ns,
				   &ima_ascii_measurements_ops);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}

	i = IMAFS_DENTRY_RUNTIME_MEASUREMENTS_COUNT;
	ns->sfs.dentry[i] =
	    securityfs_create_file("runtime_measurements_count",
				   mode, dir, ns,
				   &ima_measurements_count_ops);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}

	i = IMAFS_DENTRY_VIOLATIONS;
	ns->sfs.dentry[i] =
	    securityfs_create_file("violations", mode,
				   dir, ns,
				   &ima_htable_violations_ops);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}

	i = IMAFS_DENTRY_IMA_POLICY;
	ns->sfs.dentry[i] =
	    securityfs_create_file("policy", POLICY_FILE_FLAGS,
				   dir, ns,
				   &ima_measure_policy_ops);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}

	i = IMAFS_DENTRY_NAMESPACES;
	ns->sfs.dentry[i] = securityfs_create_dir("namespaces", dir);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}

#ifdef CONFIG_IMA_NS
	i = IMAFS_DENTRY_UNSHARE;
	ns->sfs.dentry[i] = securityfs_create_file("unshare", 0200,
						   dir, ns,
						   &ima_unshare_ops);
	if (IS_ERR(ns->sfs.dentry[i])) {
		err = PTR_ERR(ns->sfs.dentry[i]);
		goto out;
	}
#endif

	return 0;
out:
	ima_ns_fs_free(ns);
	return err;
}

static int imafs_show_path(struct seq_file *seq, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);

	seq_printf(seq, "imafs:[%lu]", inode->i_ino);
	return 0;
}

static void imafs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (S_ISLNK(inode->i_mode))
		kfree(inode->i_link);
}

static const struct super_operations imafs_super_ops = {
	.statfs = simple_statfs,
	.evict_inode = imafs_evict_inode,
	.show_path = imafs_show_path,
};

static int fill_super(struct super_block *sb, void *data, int silent)
{
	int error;

	static const struct tree_descr imafs_files[] = {
		/* last one */
		{""}
	};

	error = simple_fill_super(sb, 0x00519730, imafs_files);
	if (error)
		return error;
	sb->s_op = &imafs_super_ops;

	return 0;
}

static struct dentry *imafs_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, fill_super);
}

static struct file_system_type imafs_ops = {
	.owner = THIS_MODULE,
	.name = "imafs",
	.mount = imafs_mount,
	.kill_sb = kill_anon_super,
	.fs_flags = FS_USERNS_MOUNT,
};

int __init ima_fs_init(void)
{
	int ret = 0;
	struct kernfs_node *dotima, *imalink;

	imafs_mnt = kern_mount(&imafs_ops);
	if (IS_ERR(imafs_mnt))
		panic("can't set imafs up\n");
	imafs_mnt->mnt_sb->s_flags &= ~SB_NOUSER;
	imafs_mnt->mnt_sb->s_iflags |= SB_I_USERNS_VISIBLE;

	/* for !init_user_ns: create sysfs .ima dir and ima symlink to it */
	dotima = kernfs_create_empty_dir(security_kernfs, ".ima");
	if (IS_ERR(dotima)) {
		ret = PTR_ERR(dotima);
		goto unmount;
	}

	imalink = kernfs_create_link_iops(security_kernfs, "ima", dotima,
					  &ima_symlink_link_iops);
	if (IS_ERR(imalink)) {
		ret = PTR_ERR(imalink);
		goto kernfs_rmdir;
	}

	/* for init_user_ns: create sysfs .ima dir and ima symlink to it */
	ima_dir = securityfs_create_file(".ima", S_IFDIR | 0000,
					 NULL, NULL, NULL);
	if (IS_ERR(ima_dir)) {
		ret = PTR_ERR(ima_dir);
		goto kernfs_rmlink;
	}

	ima_symlink = securityfs_create_symlink("ima", NULL, NULL,
						&ima_symlink_link_iops);
	if (IS_ERR(ima_symlink)) {
		ret = PTR_ERR(ima_symlink);
		goto securityfs_rm_file;
	}

	return 0;

securityfs_rm_file:
	securityfs_remove(ima_dir);
kernfs_rmlink:
	kernfs_remove(imalink);
kernfs_rmdir:
	kernfs_remove(dotima);
unmount:
	kern_unmount(imafs_mnt);

	return ret;
}
