/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE			/* For NI_MAXHOST */
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <net/if.h>
#include <netdb.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef USE_KMOD
#include <libkmod.h>
#endif

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "misc.h"
#include "sysfs.h"
#include "iface.h"
#include "context.h"
#include "idbm.h"

#define ISCSI_MAX_IFACE_LEN			65
#define ISCSI_TRANSPORT_NAME_MAXLEN		16
#define ISCSI_MAX_STR_LEN			80
#define ISCSI_HWADDRESS_BUF_SIZE		18
#define TARGET_NAME_MAXLEN			255
/* ^ TODO(Gris Ge): Above 5 constants are copy from usr/config.h, need to
 *		    verify them in linux kernel code
 */

#define DEFAULT_IFACENAME	"default"
#define DEFAULT_NETDEV		"default"
#define DEFAULT_IPADDRESS	"default"
#define DEFAULT_HWADDRESS	"default"
#define ISCSI_CONFIG_ROOT	"/etc/iscsi/"
#define IFACE_CONFIG_DIR	ISCSI_CONFIG_ROOT"ifaces"
#define ISCSIUIO_PATH		"/sbin/iscsiuio"

struct _iscsi_net_drv {
	const char *net_driver_name;		// Ethernet driver.
	const char *iscsi_driver_name;		// iSCSI offload driver.
	const char *transport_name;		// iSCSI transport name.
};

static struct _iscsi_net_drv _ISCSI_NET_DRVS[] = {
	{"cxgb3", "cxgb3i", "cxgb3i"},
	{"cxgb4", "cxgb4i", "cxgb4i"},
	{"bnx2", "bnx2i" , "bnx2i"},
	{"bnx2x", "bnx2i", "bnx2i"},
};

/* Just copy from `struct iface_rec` from usr/config.h */
struct iscsi_iface {
	/* iscsi iface record name */
	char			iscsi_ifacename[ISCSI_MAX_IFACE_LEN];
	uint32_t		iface_num;
	/* network layer iface name (eth0) */
	char			netdev[IFNAMSIZ];
	char			ipaddress[NI_MAXHOST];
	char			subnet_mask[NI_MAXHOST];
	char			gateway[NI_MAXHOST];
	char			bootproto[ISCSI_MAX_STR_LEN];
	char			ipv6_linklocal[NI_MAXHOST];
	char			ipv6_router[NI_MAXHOST];
	char			ipv6_autocfg[NI_MAXHOST];
	char			linklocal_autocfg[NI_MAXHOST];
	char			router_autocfg[NI_MAXHOST];
	uint16_t		vlan_id;
	uint8_t			vlan_priority;
	char			vlan_state[ISCSI_MAX_STR_LEN];
	char			state[ISCSI_MAX_STR_LEN]; /* 0 = disable,
							   * 1 = enable */
	uint16_t		mtu;
	uint16_t		port;
	char			delayed_ack[ISCSI_MAX_STR_LEN];
	char			nagle[ISCSI_MAX_STR_LEN];
	char			tcp_wsf_state[ISCSI_MAX_STR_LEN];
	uint8_t			tcp_wsf;
	uint8_t			tcp_timer_scale;
	char			tcp_timestamp[ISCSI_MAX_STR_LEN];
	char			dhcp_dns[ISCSI_MAX_STR_LEN];
	char			dhcp_slp_da[ISCSI_MAX_STR_LEN];
	char			tos_state[ISCSI_MAX_STR_LEN];
	uint8_t			tos;
	char			gratuitous_arp[ISCSI_MAX_STR_LEN];
	char			dhcp_alt_client_id_state[ISCSI_MAX_STR_LEN];
	char			dhcp_alt_client_id[ISCSI_MAX_STR_LEN];
	char			dhcp_req_vendor_id_state[ISCSI_MAX_STR_LEN];
	char			dhcp_vendor_id_state[ISCSI_MAX_STR_LEN];
	char			dhcp_vendor_id[ISCSI_MAX_STR_LEN];
	char			dhcp_learn_iqn[ISCSI_MAX_STR_LEN];
	char			fragmentation[ISCSI_MAX_STR_LEN];
	char			incoming_forwarding[ISCSI_MAX_STR_LEN];
	uint8_t			ttl;
	char			gratuitous_neighbor_adv[ISCSI_MAX_STR_LEN];
	char			redirect[ISCSI_MAX_STR_LEN];
	char			mld[ISCSI_MAX_STR_LEN];
	uint32_t		flow_label;
	uint32_t		traffic_class;
	uint8_t			hop_limit;
	uint32_t		nd_reachable_tmo;
	uint32_t		nd_rexmit_time;
	uint32_t		nd_stale_tmo;
	uint8_t			dup_addr_detect_cnt;
	uint32_t		router_adv_link_mtu;
	uint16_t		def_task_mgmt_tmo;
	char			header_digest[ISCSI_MAX_STR_LEN];
	char			data_digest[ISCSI_MAX_STR_LEN];
	char			immediate_data[ISCSI_MAX_STR_LEN];
	char			initial_r2t[ISCSI_MAX_STR_LEN];
	char			data_seq_inorder[ISCSI_MAX_STR_LEN];
	char			data_pdu_inorder[ISCSI_MAX_STR_LEN];
	uint8_t			erl;
	uint32_t		max_recv_dlength;
	uint32_t		first_burst_len;
	uint16_t		max_out_r2t;
	uint32_t		max_burst_len;
	char			chap_auth[ISCSI_MAX_STR_LEN];
	char			bidi_chap[ISCSI_MAX_STR_LEN];
	char			strict_login_comp[ISCSI_MAX_STR_LEN];
	char			discovery_auth[ISCSI_MAX_STR_LEN];
	char			discovery_logout[ISCSI_MAX_STR_LEN];
	char			port_state[ISCSI_MAX_STR_LEN];
	char			port_speed[ISCSI_MAX_STR_LEN];
	/*
	 * TODO: we may have to make this bigger and interconnect
	 * specific for infiniband
	 */
	char			hwaddress[ISCSI_HWADDRESS_BUF_SIZE];
	char			transport_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	/*
	 * This is only used for boot now, but the iser guys
	 * can use this for their virtualization idea.
	 */
	char			alias[TARGET_NAME_MAXLEN + 1];
	char			iname[TARGET_NAME_MAXLEN + 1];
};

const struct iscsi_iface _DEFAULT_IFACES[] = {
	{
		.name = "default",
		.transport_name	= "tcp",
	},
	{
		.name		= "iser",
		.transport_name	= "iser",
	},
};

static int _load_kernel_module(struct iscsi_context *ctx, const char *drv_name);
static int _iface_conf_write(struct iscsi_context *ctx,
			     struct iscsi_iface *iface);
static int _fill_hw_iface_from_sys(struct iscsi_context *ctx,
				   struct iscsi_iface *iface,
				   const char *iface_kern_id);
static bool _is_default_iface(struct iscsi_iface *iface);

_iscsi_getter_func_gen(iscsi_iface, hwaddress, const char *);
_iscsi_getter_func_gen(iscsi_iface, transport_name, const char *);
_iscsi_getter_func_gen(iscsi_iface, ipaddress, const char *);
_iscsi_getter_func_gen(iscsi_iface, netdev, const char *);
_iscsi_getter_func_gen(iscsi_iface, iname, const char *);
_iscsi_getter_func_gen(iscsi_iface, port_state, const char *);
_iscsi_getter_func_gen(iscsi_iface, port_speed, const char *);
_iscsi_getter_func_gen(iscsi_iface, name, const char *);

int _iscsi_iface_get(struct iscsi_context *ctx, uint32_t host_id, uint32_t sid,
		     struct iscsi_iface **iface)
{
	int rc = LIBISCSI_OK;
	char *sysfs_se_dir_path = NULL;
	char *sysfs_sh_dir_path = NULL;
	char *sysfs_scsi_host_dir_path = NULL;
	char *sysfs_iface_dir_path = NULL;
	char *iface_kern_id = NULL;
	char proc_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	bool is_default_iface = false;

	assert(ctx != NULL);
	assert(host_id != 0);
	assert(iface != NULL);

	*iface = NULL;

	if (sid != 0) {
		sysfs_se_dir_path = malloc(PATH_MAX);
		_alloc_null_check(ctx, sysfs_se_dir_path, rc, out);
		snprintf(sysfs_se_dir_path, PATH_MAX, "%s/session%" PRIu32,
			 _ISCSI_SYS_SESSION_DIR, sid);
	}

	sysfs_sh_dir_path = malloc(PATH_MAX);
	_alloc_null_check(ctx, sysfs_sh_dir_path, rc, out);
	snprintf(sysfs_sh_dir_path, PATH_MAX, "%s/host%" PRIu32,
		 _ISCSI_SYS_HOST_DIR, host_id);

	sysfs_scsi_host_dir_path = malloc(PATH_MAX);
	_alloc_null_check(ctx, sysfs_scsi_host_dir_path, rc, out);
	snprintf(sysfs_scsi_host_dir_path, PATH_MAX, "%s/host%" PRIu32,
		 _SCSI_SYS_HOST_DIR, host_id);

	*iface = (struct iscsi_iface *) calloc(1, sizeof(struct iscsi_iface));
	_alloc_null_check(ctx, *iface, rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_scsi_host_dir_path, "proc_name",
				  proc_name, sizeof(proc_name) / sizeof(char),
				  NULL /* raise error if failed */),
	      rc, out);

	if (strncmp(proc_name, "iscsi_", strlen("iscsi_")) == 0)
		strncpy((*iface)->transport_name, proc_name + strlen("iscsi_"),
			sizeof((*iface)->transport_name) / sizeof(char));
	else
		strncpy((*iface)->transport_name, proc_name,
			sizeof((*iface)->transport_name) / sizeof(char));

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "hwaddress",
				  (*iface)->hwaddress,
				  sizeof((*iface)->hwaddress) / sizeof(char),
				  DEFAULT_HWADDRESS),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "netdev",
				  (*iface)->netdev,
				  sizeof((*iface)->netdev) / sizeof(char),
				  DEFAULT_NETDEV),
	      rc, out);

	if (sysfs_se_dir_path)
		_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "initiatorname",
				    (*iface)->iname,
				    sizeof((*iface)->iname) / sizeof(char), "");
	if (strcmp((*iface)->iname, "") == 0)
		_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path,
					  "initiatorname", (*iface)->iname,
					  sizeof((*iface)->iname) /
					  sizeof(char), ""),
		      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "port_state",
				  (*iface)->port_state,
				  sizeof((*iface)->port_state) / sizeof(char),
				  "unknown"),
	      rc, out);

	if (strcmp((*iface)->port_state, "Unknown!") == 0)
		strncpy((*iface)->port_state, "unknown",
			sizeof((*iface)->port_state) / sizeof(char));

	_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "port_speed",
				  (*iface)->port_speed,
				  sizeof((*iface)->port_speed) / sizeof(char),
				  "unknown"),
	      rc, out);

	if (strncmp((*iface)->port_speed, "Unknown", strlen("Unknown")) == 0)
		strncpy((*iface)->port_speed, "unknown",
			sizeof((*iface)->port_speed) / sizeof(char));

	if (sysfs_se_dir_path != NULL)
	    _sysfs_prop_get_str(ctx, sysfs_se_dir_path, "ifacename",
				(*iface)->name,
				sizeof((*iface)->name)/sizeof(char), "");

	if (strcmp((*iface)->name, "") == 0) {
		/*
		 * if the ifacename file is not there then we are
		 * using a older kernel and can try to find the
		 * binding by the net info which was used on these
		 * older kernels.
		 */

		/*TODO(Gris Ge): need to parse /etc/iscsi/ifaces/<iface_name>
		 * files to find a match. I will add the code later when
		 * we expose more defiled information on iscsi_iface.
		 */
		strncpy((*iface)->name, DEFAULT_IFACENAME,
			sizeof((*iface)->name) / sizeof(char));
	}
	is_default_iface = _is_default_iface(*iface);

	if (! is_default_iface) {
		_good(_iscsi_iface_kern_id_of_host_id(ctx, host_id,
						      iface_kern_id),
		      rc, out);
		_good(_fill_hw_iface_from_sys(ctx, *iface, iface_kern_id),
		      rc, out);
	} else {
		_good(_sysfs_prop_get_str(ctx, sysfs_sh_dir_path, "ipaddress",
					(*iface)->ipaddress,
					sizeof((*iface)->ipaddress) /
					sizeof(char), DEFAULT_IPADDRESS),
		      rc, out);
	}

out:
	if (rc != LIBISCSI_OK) {
		_iscsi_iface_free(*iface);
		*iface = NULL;
	}
	free(sysfs_se_dir_path);
	free(sysfs_sh_dir_path);
	free(sysfs_scsi_host_dir_path);
	free(sysfs_iface_dir_path);
	free(iface_kern_id);
	return rc;
}

void _iscsi_iface_free(struct iscsi_iface *iface)
{
	free(iface);
}

int iscsi_ifaces_get(struct iscsi_context *ctx, struct iscsi_iface ***ifaces,
		     uint32_t *iface_count)
{
	int rc = LIBISCSI_OK;

	assert(ctx != NULL);
	assert(ifaces != NULL);
	assert(iface_count != NULL);

	*ifaces = NULL;
	*iface_count = 0;

	return rc;
}

void iscsi_ifaces_free(struct iscsi_iface **ifaces, uint32_t iface_count)
{
	uint32_t i = 0;

	if ((ifaces == NULL) || (iface_count == 0))
		return;

	for (i = 0; i < iface_count; ++i)
		_iscsi_iface_free(ifaces[i]);
	free (ifaces);
}

int iscsi_default_iface_setup(struct iscsi_context *ctx)
{
	int rc = LIBISCSI_OK;
	char strerr_buff[_STRERR_BUFF_LEN];
	int errno_save = 0;
	struct _eth_if **eifs = NULL;
	uint32_t eif_count = 0;
	uint32_t i = 0;
	size_t j = 0;
	struct _iscsi_net_drv *ind = NULL;
	uint32_t *hids = NULL;
	uint32_t hid_count = 0;
	struct iscsi_iface *iface = NULL;
	char path[PATH_MAX];

	assert(ctx != NULL);

	_good(_idbm_lock(ctx), rc, out);

	if ((access(IFACE_CONFIG_DIR, F_OK) != 0) &&
	    (mkdir(IFACE_CONFIG_DIR, 0660) != 0)) {
		errno_save = errno;
		_idbm_unlock(ctx);
		_error(ctx, "Could not make %s folder(%d %s). "
		       "HW/OFFLOAD iscsi may not be supported.",
		       IFACE_CONFIG_DIR, errno_save,
		       _strerror(errno_save, strerr_buff));
		if (errno_save == EACCES)
			return LIBISCSI_ERR_ACCESS;
		return LIBISCSI_ERR_BUG;
	}
	_idbm_unlock(ctx);

	/* Load kernel driver for iSCSI offload cards, like cxgb3i */
	_good(_eth_ifs_get(ctx, &eifs, &eif_count), rc, out);

	for (i = 0; i < eif_count; ++i) {
		for (j = 0;
		     j < sizeof(_ISCSI_NET_DRVS)/sizeof(struct _iscsi_net_drv);
		     ++j) {
			ind = &(_ISCSI_NET_DRVS[j]);
			if ((eifs[i]->driver_name == NULL) ||
			    (ind->net_driver_name == NULL) ||
			    (strcmp(eifs[i]->driver_name,
				   ind->net_driver_name) != 0))
				continue;
			/*
			* iSCSI hardware offload for bnx2{,x} is only supported
			* if the iscsiuio executable is available.
			*/
			if ((strcmp(eifs[i]->driver_name, "bnx2x") == 0) ||
			    (strcmp(eifs[i]->driver_name, "bnx2") == 0)) {
				if (access(ISCSIUIO_PATH, F_OK) != 0) {
					_debug(ctx, "iSCSI offload on %s(%s) "
					       "via %s is not supported due to "
					       "missing %s", eifs[i]->if_name,
					       eifs[i]->driver_name,
					       ind->iscsi_driver_name,
					       ISCSIUIO_PATH);
					continue;
				}
			}

			if (_iscsi_transport_is_loaded(ind->transport_name))
				continue;

			_debug(ctx, "Loading kernel module %s for iSCSI "
			       "offload on %s(%s)", ind->iscsi_driver_name,
			       eifs[i]->if_name, eifs[i]->driver_name);
			_good(_load_kernel_module(ctx, ind->iscsi_driver_name),
			      rc, out);
		}
	}

	_good(_iscsi_hids_get(ctx, &hids, &hid_count), rc, out);
	for (i = 0; i < hid_count; ++i) {
		/* Skip host binding setting for _DEFAULT_IFACES */
		/* Create /etc/iscsi/ifaces/<iface_name> file if not found
		 * TODO(Gris Ge): Need to find out why we need this file.
		 */
		_good(_iscsi_iface_get(ctx, hids[i], 0, &iface), rc, out);
		snprintf(path, PATH_MAX, "%s/%s", IFACE_CONFIG_DIR,
			 iface->iscsi_ifacename);
		if (access(path, F_OK) != 0)
			_good(_iface_conf_write(ctx, iface), rc, out);
	}

out:
	_eth_ifs_free(eifs, eif_count);
	free(hids);
	free(iface);
	return rc;
}

static int _load_kernel_module(struct iscsi_context *ctx, const char *drv_name)
{
#ifdef USE_KMOD
	struct kmod_ctx *kctx = NULL;
	struct kmod_module *mod = NULL;
	int rc = LIBISCSI_OK;

	kctx = kmod_new(NULL, NULL);
	_alloc_null_check(ctx, kctx, rc, out);

	kmod_load_resources(kctx);

	if (kmod_module_new_from_name(kctx, drv_name, &mod)) {
		_error(ctx, "Failed to load module %s.", drv_name);
		rc = LIBISCSI_ERR_TRANS_NOT_FOUND;
		goto out;
	}

	if (kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST,
					    NULL, NULL, NULL, NULL)) {
		log_error("Could not insert module %s. Kmod error %d",
			  drv_name, rc);
		rc = LIBISCSI_ERR_TRANS_NOT_FOUND;
	}
	kmod_module_unref(mod);

out:
	if (kctx != NULL)
		kmod_unref(kctx);
	return rc;

#else
	char *cmdline[4];
	pid_t pid = 0;
	char strerr_buff[_STRERR_BUFF_LEN];
	int errno_save = 0;

	cmdline[0] = "/sbin/modprobe";
	cmdline[1] = "-qb";
	cmdline[2] = (char *) drv_name;
	cmdline[3] = NULL;

	pid = fork();
	if (pid == 0) {
		if (execv("/sbin/modprobe", cmdline) < 0) {
			errno_save = errno;
			_error(ctx, "Failed to load module %s, error %d: %s",
			       drv_name, errno_save,
			       _strerror(errno_save, strerr_buff));
			exit(-errno_save);
		}
		exit(0);
	} else if (pid < 0) {
		_error(ctx, "Failed to fork process to load module %s: %s",
		       drv_name, _strerror(errno_save, strerr_buff));
		return LIBISCSI_ERR_TRANS_NOT_FOUND;
	}

	if (waitpid(pid, NULL, 0) < 0) {
		_error(ctx, "Failed to load module %s", drv_name);
		return LIBISCSI_ERR_TRANS_NOT_FOUND;
	}

	return LIBISCSI_OK;
#endif
}

static int _iface_conf_write(struct iscsi_context *ctx,
			     struct iscsi_iface *iface)
{
	char conf_path[PATH_MAX];
	char strerr_buff[_STRERR_BUFF_LEN];
	int errno_save = 0;
	FILE *f = NULL;
	int rc = 0;

	if (_is_default_iface(iface)) {
		_error(ctx, "iface %s is not a special interface and "
		       "is not stored in %s", iface->iscsi_ifacename,
		       IFACE_CONFIG_DIR);
		return LIBISCSI_ERR_INVAL;
	}

	snprintf(conf_path, PATH_MAX, "%s/%s", IFACE_CONFIG_DIR,
		 iface->iscsi_ifacename);
	f = fopen(conf_path, "w");
	errno_save = errno;
	if (!f) {
		_error(ctx, "Failed to open %s using write mode: %d %s",
		       conf_path, errno_save,
		       _strerror(errno_save, strerr_buff));
		rc = LIBISCSI_ERR_IDBM;
		goto out;
	}

	_good(_idbm_lock(ctx), rc, out);

	rc = _idbm_print_iface(ctx, iface, f);

	if (rc != LIBISCSI_OK) {
		fclose(f);
		f = NULL;
		remove(conf_path);
	}
	_idbm_unlock(ctx);

out:
	if (f != NULL)
		fclose(f);
	return rc;
}

// mimic of iscsi_sysfs_read_iface() in iscsi_sysfs.c.
static int _fill_hw_iface_from_sys(struct iscsi_context *ctx,
				   struct iscsi_iface *iface,
				   const char *iface_kern_id)
{
	int rc = LIBISCSI_OK;
	char *sysfs_iface_dir_path = NULL;
	uint32_t tmp_host_no = 0;
	uint32_t iface_num = 0;
	int iface_type = 0;


	assert(ctx != NULL);
	assert(iface != NULL);
	assert(iface_kern_id != NULL);

	sysfs_iface_dir_path = malloc(PATH_MAX);
	_alloc_null_check(ctx, sysfs_iface_dir_path, rc, out);
	snprintf(sysfs_iface_dir_path, PATH_MAX, "%s/%s",
		 _ISCSI_SYS_IFACE_DIR, iface_kern_id);

	strncpy(iface->iscsi_ifacename, iface_kern_id,
		sizeof(iface->iscsi_ifacename) / sizeof(char));
	_good(_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				  "ipaddress",
				  iface->ipaddress,
				  sizeof(iface->ipaddress) /
				  sizeof(char), DEFAULT_IPADDRESS),
		      rc, out);

	if (!strncmp(iface_kern_id, "ipv4", strlen("ipv4"))) {
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "bootproto", iface->bootproto,
				    sizeof(iface->bootproto) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "gateway",
				    iface->gateway,
				    sizeof(iface->gateway) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "subnet",
				    iface->subnet_mask,
				    sizeof(iface->subnet_mask) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_alt_client_id_en",
				    iface->dhcp_alt_client_id,
				    sizeof(iface->dhcp_alt_client_id) /
				    sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_alt_client_id",
				    iface->dhcp_alt_client_id,
				    sizeof(iface->dhcp_alt_client_id) /
				    sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_dns_address_en", iface->dhcp_dns,
				    sizeof(iface->dhcp_dns) / sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_learn_iqn_en", iface->dhcp_learn_iqn,
				    sizeof(iface->dhcp_learn_iqn) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_req_vendor_id_en",
				    iface->dhcp_req_vendor_id_state,
				    sizeof(iface->dhcp_req_vendor_id_state) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_use_vendor_id_en",
				    iface->dhcp_vendor_id_state,
				    sizeof(iface->dhcp_vendor_id_state) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_vendor_id", iface->dhcp_vendor_id,
				    sizeof(iface->dhcp_vendor_id) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "dhcp_slp_da_info_en", iface->dhcp_slp_da,
				    sizeof(iface->dhcp_slp_da) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "fragment_disable", iface->fragmentation,
				    sizeof(iface->fragmentation) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "grat_arp_en", iface->gratuitous_arp,
				    sizeof(iface->gratuitous_arp) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "incoming_forwarding_en",
				    iface->incoming_forwarding,
				    sizeof(iface->incoming_forwarding) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tos_en",
				    iface->tos_state, sizeof(iface->tos_state) /
				    sizeof(char), "");
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "tos",
				   &iface->tos, 0, true);
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "ttl",
				   &iface->ttl, 0, true);
	} else {
		// ipv6
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "ipaddr_autocfg",
				    iface->ipv6_autocfg,
				    sizeof(iface->ipv6_autocfg) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "link_local_addr", iface->ipv6_linklocal,
				    sizeof(iface->ipv6_linklocal) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "link_local_autocfg",
				    iface->linklocal_autocfg,
				    sizeof(iface->linklocal_autocfg) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "router_addr", iface->ipv6_router,
				    sizeof(iface->ipv6_router) / sizeof(char),
				    "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "router_state", iface->router_autocfg,
				    sizeof(iface->router_autocfg) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
				    "grat_neighbor_adv_en",
				    iface->gratuitous_neighbor_adv,
				    sizeof(iface->gratuitous_neighbor_adv) /
				    sizeof(char), "");
		_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "mld_en",
				    iface->mld, sizeof(iface->mld) /
				    sizeof(char), "");
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path,
				   "dup_addr_detect_cnt",
				   &iface->dup_addr_detect_cnt, 0, true);
		_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "hop_limit",
				   &iface->hop_limit, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path,
				    "flow_label", &iface->flow_label, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path,
				    "nd_reachable_tmo",
				    &iface->nd_reachable_tmo, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "nd_rexmit_time",
				    &iface->nd_rexmit_time, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "nd_stale_tmo",
				    &iface->nd_stale_tmo, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path,
				    "router_adv_link_mtu",
				    &iface->router_adv_link_mtu, 0, true);
		_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "traffic_class",
				    &iface->traffic_class, 0, true);
	}

	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "port", &iface->port, 0,
			    true);
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "mtu", &iface->mtu, 0,
			    true);
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "vlan_id",
			    &iface->vlan_id, UINT16_MAX, true);
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "vlan_priority",
			    &iface->vlan_priority, UINT8_MAX, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "vlan_enabled",
			    iface->vlan_state, sizeof(iface->vlan_state) /
			    sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "enabled", iface->state,
			    sizeof(iface->state) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "delayed_ack_en",
			    iface->delayed_ack,
			    sizeof(iface->delayed_ack) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tcp_nagle_disable",
			    iface->nagle, sizeof(iface->nagle) / sizeof(char),
			    "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tcp_wsf_disable",
			    iface->tcp_wsf_state,
			    sizeof(iface->tcp_wsf_state) / sizeof(char), "");
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "tcp_wsf",
			   &iface->tcp_wsf, 0, true);
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "tcp_timer_scale",
			   &iface->tcp_timer_scale, 0, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "tcp_timestamp_en",
			    iface->tcp_timestamp,
			    sizeof(iface->tcp_timestamp) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "redirect_en",
			    iface->redirect,
			    sizeof(iface->redirect) / sizeof(char), "");
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "def_taskmgmt_tmo",
			    &iface->def_task_mgmt_tmo, 0, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "header_digest",
			    iface->header_digest,
			    sizeof(iface->header_digest) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "data_digest",
			    iface->data_digest,
			    sizeof(iface->data_digest) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "immediate_data",
			    iface->immediate_data,
			    sizeof(iface->immediate_data) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "initial_r2t",
			    iface->initial_r2t,
			    sizeof(iface->initial_r2t) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "data_seq_in_order",
			    iface->data_seq_inorder,
			    sizeof(iface->data_seq_inorder) / sizeof(char),
			    "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "data_pdu_in_order",
			    iface->data_pdu_inorder,
			    sizeof(iface->data_pdu_inorder) / sizeof(char), "");
	_sysfs_prop_get_u8(ctx, sysfs_iface_dir_path, "erl", &iface->erl, 0,
			    true);
	_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "max_recv_dlength",
			    &iface->max_recv_dlength, 0, true);
	_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "first_burst_len",
			    &iface->first_burst_len, 0, true);
	_sysfs_prop_get_u16(ctx, sysfs_iface_dir_path, "max_outstanding_r2t",
			    &iface->max_out_r2t, 0, true);
	_sysfs_prop_get_u32(ctx, sysfs_iface_dir_path, "max_burst_len",
			    &iface->max_burst_len, 0, true);
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "chap_auth",
			    iface->chap_auth,
			    sizeof(iface->chap_auth) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "bidi_chap",
			    iface->bidi_chap,
			    sizeof(iface->bidi_chap) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path, "strict_login_comp_en",
			    iface->strict_login_comp,
			    sizeof(iface->strict_login_comp) / sizeof(char),
			    "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
			    "discovery_auth_optional",
			    iface->discovery_auth,
			    sizeof(iface->discovery_auth) / sizeof(char), "");
	_sysfs_prop_get_str(ctx, sysfs_iface_dir_path,
			    "discovery_logout",
			    iface->discovery_logout,
			    sizeof(iface->discovery_logout) / sizeof(char), "");

	if (sscanf(iface_kern_id, "ipv%d-iface-%" SCNu32 "-%" SCNu32,
		   &iface_type, &tmp_host_no, &iface_num) == 3)
		iface->iface_num = iface_num;

out:
	free(sysfs_iface_dir_path);
	return rc;
}

static bool _is_default_iface(struct iscsi_iface *iface)
{
	size_t i = 0;
	for (; i < sizeof(_DEFAULT_IFACES)/sizeof(struct iscsi_iface); ++i) {
		if (strcmp(iface->iscsi_ifacename, _DEFAULT_IFACES[i].name)
		    == 0)
			return true;
	}
	return false;
}
