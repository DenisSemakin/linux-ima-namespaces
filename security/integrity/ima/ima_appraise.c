/*
 * Copyright (C) 2011 IBM Corporation
 *
 * Author:
 * Mimi Zohar <zohar@us.ibm.com>
 * Yuqiong Sun <suny@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 */
#include <linux/module.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/magic.h>
#include <linux/ima.h>
#include <linux/evm.h>

#include "ima.h"

static int __init default_appraise_setup(char *str)
{
#ifdef CONFIG_IMA_APPRAISE_BOOTPARAM
	if (strncmp(str, "off", 3) == 0)
		init_ima_ns.ima_appraise = 0;
	else if (strncmp(str, "log", 3) == 0)
		init_ima_ns.ima_appraise = IMA_APPRAISE_LOG;
	else if (strncmp(str, "fix", 3) == 0)
		init_ima_ns.ima_appraise = IMA_APPRAISE_FIX;
#endif
	return 1;
}

__setup("ima_appraise=", default_appraise_setup);

/*
 * ima_must_appraise - set appraise flag
 *
 * Return 1 to appraise or hash
 */
int ima_must_appraise(struct inode *inode, int mask, enum ima_hooks func,
		      struct user_namespace *user_ns)
{
	u32 secid;
	struct ima_namespace *ns = get_current_ns();

	if (!ns->ima_appraise)
		return 0;

	security_task_getsecid(current, &secid);
	return ima_match_policy(inode, current_cred(), secid, func, mask,
				IMA_APPRAISE | IMA_HASH, NULL, ns, ns,
				user_ns);
}

static int ima_fix_xattr(struct dentry *dentry,
			 struct integrity_iint_cache *iint)
{
	int rc, offset;
	u8 algo = iint->ima_hash->algo;

	if (algo <= HASH_ALGO_SHA1) {
		offset = 1;
		iint->ima_hash->xattr.sha1.type = IMA_XATTR_DIGEST;
	} else {
		offset = 0;
		iint->ima_hash->xattr.ng.type = IMA_XATTR_DIGEST_NG;
		iint->ima_hash->xattr.ng.algo = algo;
	}
	rc = __vfs_setxattr_noperm(dentry, XATTR_NAME_IMA,
				   &iint->ima_hash->xattr.data[offset],
				   (sizeof(iint->ima_hash->xattr) - offset) +
				   iint->ima_hash->length, 0);
	return rc;
}

/* Return specific func appraised cached result */
enum integrity_status ima_get_cache_status(struct ns_status *status,
					   enum ima_hooks func)
{
	switch (func) {
	case MMAP_CHECK:
		return status->ima_mmap_status;
	case BPRM_CHECK:
		return status->ima_bprm_status;
	case CREDS_CHECK:
		return status->ima_creds_status;
	case FILE_CHECK:
	case POST_SETATTR:
		return status->ima_file_status;
	case MODULE_CHECK ... MAX_CHECK - 1:
	default:
		return status->ima_read_status;
	}
}

static void ima_set_cache_status(enum ima_hooks func,
				 enum integrity_status status,
				 struct ns_status *ns_status)
{
	switch (func) {
	case MMAP_CHECK:
		ns_status->ima_mmap_status = status;
		break;
	case BPRM_CHECK:
		ns_status->ima_bprm_status = status;
		break;
	case CREDS_CHECK:
		ns_status->ima_creds_status = status;
	case FILE_CHECK:
	case POST_SETATTR:
		ns_status->ima_file_status = status;
		break;
	case MODULE_CHECK ... MAX_CHECK - 1:
	default:
		ns_status->ima_read_status = status;
		break;
	}
}

static void ima_cache_flags(struct integrity_iint_cache *iint,
			    enum ima_hooks func, struct ns_status *status)
{
	unsigned long flags = iint_flags(iint, status);

	switch (func) {
	case MMAP_CHECK:
		flags |= (IMA_MMAP_APPRAISED | IMA_APPRAISED);
		break;
	case BPRM_CHECK:
		flags |= (IMA_BPRM_APPRAISED | IMA_APPRAISED);
		break;
	case CREDS_CHECK:
		flags |= (IMA_CREDS_APPRAISED | IMA_APPRAISED);
		break;
	case FILE_CHECK:
	case POST_SETATTR:
		flags |= (IMA_FILE_APPRAISED | IMA_APPRAISED);
		break;
	case MODULE_CHECK ... MAX_CHECK - 1:
	default:
		flags |= (IMA_READ_APPRAISED | IMA_APPRAISED);
		break;
	}

	set_iint_flags(iint, status, flags);
}

enum hash_algo ima_get_hash_algo(struct evm_ima_xattr_data *xattr_value,
				 int xattr_len)
{
	struct signature_v2_hdr *sig;
	enum hash_algo ret;

	if (!xattr_value || xattr_len < 2)
		/* return default hash algo */
		return ima_hash_algo;

	switch (xattr_value->type) {
	case EVM_IMA_XATTR_DIGSIG:
		sig = (typeof(sig))xattr_value;
		if (sig->version != 2 || xattr_len <= sizeof(*sig))
			return ima_hash_algo;
		return sig->hash_algo;
		break;
	case IMA_XATTR_DIGEST_NG:
		ret = xattr_value->digest[0];
		if (ret < HASH_ALGO__LAST)
			return ret;
		break;
	case IMA_XATTR_DIGEST:
		/* this is for backward compatibility */
		if (xattr_len == 21) {
			unsigned int zero = 0;
			if (!memcmp(&xattr_value->digest[16], &zero, 4))
				return HASH_ALGO_MD5;
			else
				return HASH_ALGO_SHA1;
		} else if (xattr_len == 17)
			return HASH_ALGO_MD5;
		break;
	}

	/* return default hash algo */
	return ima_hash_algo;
}

int ima_read_xattr(struct dentry *dentry,
		   struct evm_ima_xattr_data **xattr_value)
{
	ssize_t ret;

	ret = vfs_getxattr_alloc(dentry, XATTR_NAME_IMA, (char **)xattr_value,
				 0, GFP_NOFS);
	if (ret == -EOPNOTSUPP)
		ret = 0;
	return ret;
}

/*
 * ima_appraise_measurement - appraise file measurement
 *
 * Call evm_verifyxattr() to verify the integrity of 'security.ima'.
 * Assuming success, compare the xattr hash with the collected measurement.
 *
 * Return 0 on success, error code otherwise
 */
int ima_appraise_measurement(enum ima_hooks func,
			     struct integrity_iint_cache *iint,
			     struct file *file, const unsigned char *filename,
			     struct evm_ima_xattr_data *xattr_value,
			     int xattr_len,
			     struct ima_namespace *ns,
			     struct ns_status *ns_status)
{
	static const char op[] = "appraise_data";
	const char *cause = "unknown";
	struct dentry *dentry = file_dentry(file);
	struct inode *inode = d_backing_inode(dentry);
	enum integrity_status status = INTEGRITY_UNKNOWN;
	int rc = xattr_len, hash_start = 0;
	unsigned long flags = iint_flags(iint, ns_status);

	if (!(inode->i_opflags & IOP_XATTR))
		return INTEGRITY_UNKNOWN;

	if (flags & IMA_APPRAISED)
		return INTEGRITY_PASS;

	if (rc <= 0) {
		if (rc && rc != -ENODATA)
			goto out;

		cause = flags & IMA_DIGSIG_REQUIRED ?
				"IMA-signature-required" : "missing-hash";
		status = INTEGRITY_NOLABEL;
		if (file->f_mode & FMODE_CREATED)
			iint->flags |= IMA_NEW_FILE;
		if ((flags & IMA_NEW_FILE) &&
		    (!(flags & IMA_DIGSIG_REQUIRED) ||
		     (inode->i_size == 0)))
			status = INTEGRITY_PASS;
		goto out;
	}

	status = evm_verifyxattr(dentry, XATTR_NAME_IMA, xattr_value, rc, iint);
	switch (status) {
	case INTEGRITY_PASS:
	case INTEGRITY_PASS_IMMUTABLE:
	case INTEGRITY_UNKNOWN:
		break;
	case INTEGRITY_NOXATTRS:	/* No EVM protected xattrs. */
	case INTEGRITY_NOLABEL:		/* No security.evm xattr. */
		cause = "missing-HMAC";
		goto out;
	case INTEGRITY_FAIL:		/* Invalid HMAC/signature. */
		cause = "invalid-HMAC";
		goto out;
	default:
		WARN_ONCE(true, "Unexpected integrity status %d\n", status);
	}

	switch (xattr_value->type) {
	case IMA_XATTR_DIGEST_NG:
		/* first byte contains algorithm id */
		hash_start = 1;
		/* fall through */
	case IMA_XATTR_DIGEST:
		if (ns_status->flags & IMA_DIGSIG_REQUIRED) {
			cause = "IMA-signature-required";
			status = INTEGRITY_FAIL;
			break;
		}
		clear_bit(IMA_DIGSIG, &iint->atomic_flags);
		if (xattr_len - sizeof(xattr_value->type) - hash_start >=
				iint->ima_hash->length)
			/* xattr length may be longer. md5 hash in previous
			   version occupied 20 bytes in xattr, instead of 16
			 */
			rc = memcmp(&xattr_value->digest[hash_start],
				    iint->ima_hash->digest,
				    iint->ima_hash->length);
		else
			rc = -EINVAL;
		if (rc) {
			cause = "invalid-hash";
			status = INTEGRITY_FAIL;
			break;
		}
		status = INTEGRITY_PASS;
		break;
	case EVM_IMA_XATTR_DIGSIG:
		set_bit(IMA_DIGSIG, &iint->atomic_flags);
		rc = integrity_digsig_verify(ns, INTEGRITY_KEYRING_IMA,
					     (const char *)xattr_value, rc,
					     iint->ima_hash->digest,
					     iint->ima_hash->length);
		if (rc == -EOPNOTSUPP) {
			status = INTEGRITY_UNKNOWN;
		} else if (rc) {
			cause = "invalid-signature";
			status = INTEGRITY_FAIL;
		} else {
			status = INTEGRITY_PASS;
		}
		break;
	default:
		status = INTEGRITY_UNKNOWN;
		cause = "unknown-ima-data";
		break;
	}

out:
	/*
	 * File signatures on some filesystems can not be properly verified.
	 * When such filesystems are mounted by an untrusted mounter or on a
	 * system not willing to accept such a risk, fail the file signature
	 * verification.
	 */
	if ((inode->i_sb->s_iflags & SB_I_IMA_UNVERIFIABLE_SIGNATURE) &&
	    ((inode->i_sb->s_iflags & SB_I_UNTRUSTED_MOUNTER) ||
	     (flags & IMA_FAIL_UNVERIFIABLE_SIGS))) {
		status = INTEGRITY_FAIL;
		cause = "unverifiable-signature";
		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode, filename,
				    op, cause, rc, 0);
	} else if (status != INTEGRITY_PASS) {
		/* Fix mode, but don't replace file signatures. */
		if ((ns->ima_appraise & IMA_APPRAISE_FIX) &&
		    (!xattr_value ||
		     xattr_value->type != EVM_IMA_XATTR_DIGSIG)) {
			if (!ima_fix_xattr(dentry, iint))
				status = INTEGRITY_PASS;
		}

		/* Permit new files with file signatures, but without data. */
		if (inode->i_size == 0 && flags & IMA_NEW_FILE &&
		    xattr_value && xattr_value->type == EVM_IMA_XATTR_DIGSIG) {
			status = INTEGRITY_PASS;
		}

		integrity_audit_msg(AUDIT_INTEGRITY_DATA, inode, filename,
				    op, cause, rc, 0);
	} else {
		ima_cache_flags(iint, func, ns_status);
		flags = set_iint_flags(iint, ns_status, flags | IMA_APPRAISED);
	}

	ima_set_cache_status(func, status, ns_status);

	return status;
}

/*
 * ima_update_xattr - update 'security.ima' hash value
 */
void ima_update_xattr(struct integrity_iint_cache *iint,
		      struct ns_status *status, struct file *file)
{
	struct dentry *dentry = file_dentry(file);
	int rc = 0;

	/* do not collect and update hash for digital signatures */
	if (test_bit(IMA_DIGSIG, &iint->atomic_flags))
		return;

	if ((status->ima_file_status != INTEGRITY_PASS) &&
	    !(iint_flags(iint, status) & IMA_HASH))
		return;

	rc = ima_collect_measurement(iint, status, file, NULL, 0, ima_hash_algo);
	if (rc < 0)
		return;

	inode_lock(file_inode(file));
	ima_fix_xattr(dentry, iint);
	inode_unlock(file_inode(file));
}

/**
 * ima_inode_post_setattr - reflect file metadata changes
 * @dentry: pointer to the affected dentry
 *
 * Changes to a dentry's metadata might result in needing to appraise.
 *
 * This function is called from notify_change(), which expects the caller
 * to lock the inode's i_mutex.
 */
void ima_inode_post_setattr(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	struct integrity_iint_cache *iint;
	int action;

	if (!(get_current_ns()->ima_policy_flag & IMA_APPRAISE) ||
	    !S_ISREG(inode->i_mode) ||
	    !(inode->i_opflags & IOP_XATTR))
		return;

	action = ima_must_appraise(inode, MAY_ACCESS, POST_SETATTR,
				   current_user_ns());
	if (!action)
		__vfs_removexattr(dentry, XATTR_NAME_IMA);

	iint = integrity_iint_find(inode);
	if (iint) {
		set_bit(IMA_CHANGE_ATTR, &iint->atomic_flags);
		if (!action)
			clear_bit(IMA_UPDATE_XATTR, &iint->atomic_flags);
	}
}

/*
 * ima_protect_xattr - protect 'security.ima'
 *
 * Ensure that not just anyone can modify or remove 'security.ima'.
 */
static int ima_protect_xattr(struct dentry *dentry, const char *xattr_name,
			     const void *xattr_value, size_t xattr_value_len)
{
	if (strncmp(xattr_name, XATTR_NAME_IMA,
		    sizeof(XATTR_NAME_IMA) - 1) == 0) {
		struct inode *inode = d_backing_inode(dentry);
		if (inode &&
		    capable_wrt_inode_uidgid(inode, CAP_INTEGRITY_ADMIN))
			return 1;

		if (capable(CAP_SYS_ADMIN))
			return 1;

		return -EPERM;
	}
	return 0;
}

static void ima_reset_appraise_flags(struct inode *inode, int digsig)
{
	struct integrity_iint_cache *iint;
	struct ns_status *status;

	if (!(get_current_ns()->ima_policy_flag & IMA_APPRAISE) ||
	    !S_ISREG(inode->i_mode))
		return;

	iint = integrity_iint_find(inode);
	if (!iint)
		return;

	read_lock(&iint->ns_list_lock);
	list_for_each_entry(status, &iint->ns_list, ns_next)
		status->measured_pcrs = 0;
	read_unlock(&iint->ns_list_lock);

	set_bit(IMA_CHANGE_XATTR, &iint->atomic_flags);
	if (digsig)
		set_bit(IMA_DIGSIG, &iint->atomic_flags);
	else
		clear_bit(IMA_DIGSIG, &iint->atomic_flags);
}

int ima_inode_setxattr(struct dentry *dentry, const char *xattr_name,
		       const void *xattr_value, size_t xattr_value_len)
{
	const struct evm_ima_xattr_data *xvalue = xattr_value;
	int result;

	result = ima_protect_xattr(dentry, xattr_name, xattr_value,
				   xattr_value_len);
	if (result == 1) {
		if (!xattr_value_len || (xvalue->type >= IMA_XATTR_LAST))
			return -EINVAL;
		ima_reset_appraise_flags(d_backing_inode(dentry),
			xvalue->type == EVM_IMA_XATTR_DIGSIG);
		result = 0;
	}
	return result;
}

int ima_inode_removexattr(struct dentry *dentry, const char *xattr_name)
{
	int result;

	result = ima_protect_xattr(dentry, xattr_name, NULL, 0);
	if (result == 1) {
		ima_reset_appraise_flags(d_backing_inode(dentry), 0);
		result = 0;
	}
	return result;
}
