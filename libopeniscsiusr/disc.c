/*
 * Copyright (C) 2018 Red Hat, Inc.
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
#define _GNU_SOURCE   /* For NI_MAXHOST and strerror_r() */
#endif

#include <netdb.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "disc.h"
#include "rfc.h"
#include "idbm.h"
#include "iscsid.h"
#include "misc.h"
#include "sysfs.h"

struct _disc_cfg_key {
	const char *pro_name;
	const char *cfg_key;
}

static void _disc_init_cfg(struct iscsi_discovery_cfg *cfg,
			   struct iscsid_cfg *d_cfg);

int iscsi_discovery_cfg_new(struct iscsi_context *ctx,
			    enum iscsi_discovery_type type, const char *target,
			    int port, struct iscsi_discovery_cfg **cfg,
			    bool brand_new)
{
	int rc = LIBISCSI_OK;
	struct iscsid_cfg *d_cfg = NULL;
	const char *conf_path = NULL;

	assert(ctx != NULL);
	assert(target != NULL);
	assert(strlen(target) != 0);
	assert(cfg != NULL);

	if (port <= 0) {
		port = ISCSI_DEFAULT_PORT;
	}

	*cfg = NULL;
	*cfg = calloc(1, sizeof(struct iscsi_discovery_cfg));
	_alloc_null_check(ctx, *cfg, rc, out);
	snprintf((*cfg)->address, sizeof((*cfg)->address)/sizeof(char),
		 "%s", target);
	(*cfg)->port = port;
	(*cfg)->type = type;

	if (brand_new) {
		_debug(ctx, "Creating new discovery setting from iscsid.conf");
		_good(_iscsid_cfg_load(ctx, &d_cfg), rc, out);
		_disc_init_cfg(cfg, d_cfg);
	} else {
		_good(_idbm_disc_cfg_conf_path_gen(ctx, cfg, &conf_path, NULL),
		      rc, out);
		if (_file_exists(conf_path)) {
			_good(_idbm_disc_cfg_get(ctx, cfg), rc, out);
			goto out;
		} else {
			_good(_iscsid_cfg_load(ctx, &d_cfg), rc, out);
			_disc_init_cfg(cfg, d_cfg);
		}
	}

	_good(_idbm_disc_cfg_write(ctx, cfg), rc, out);

out:
	free((void *) conf_path);
	iscsid_cfg_free(d_cfg);
	if (rc != LIBISCSI_OK) {
		iscsi_discovery_cfg_free(*cfg);
	}

	return rc;
}

void iscsi_discovery_cfg_free(struct iscsi_discovery_cfg *cfg)
{
	free(cfg);
}

int iscsi_discovery_cfg_edit(struct iscsi_context *ctx,
			     struct iscsi_discovery_cfg *cfg,
			     const char *name, const char *value)
{
	assert(ctx != NULL);
	assert(cfg != NULL);
	assert(name != NULL);
	assert(strlen(name) != 0);
	assert(value != NULL);
	assert(strlen(value) != 0);

	_good(_idbm_lock(ctx), rc, out);
	_good(_idbm_disc_cfg_edit(ctx, cfg, name, value), rc, out);

out:
	_idbm_unlock(ctx);
	return rc;
}

static int _do_sw_discovery(struct iscsi_context *ctx,
			    struct iscsi_iface *iface,
			    struct iscsi_discovery_cfg *cfg,
			    struct iscsi_node ***nodes, uint32_t *node_count)
{
	// Need to use realloc() for nodes
}

static int _do_hw_discovery(struct iscsi_context *ctx,
			    struct iscsi_iface *iface,
			    struct iscsi_discovery_cfg *cfg,
			    struct iscsi_node ***nodes, uint32_t *node_count)
{
	int rc = LIBISCSI_OK;
	uint32_t host_id = 0;

	assert(ctx != NULL);
	assert(iface != NULL);
	assert(nodes != NULL);
	assert(node_count != NULL);

	if (! _iface_is_valid(iface)) {
		rc = LIBISCSI_ERR_INVAL;
		_error(ctx, "Invalid iSCSI interface %s", iface->name);
		goto out;
	}

	_good(_iscsid_send_target(ctx, cfg, host_id), rc, out);

	// Find out the nodes of added hardware

out:
	return rc;
}

static bool _is_sw_iface(struct iscsi_iface *iface)
{
	if ((strcmp(iface->transport_name, "tcp") == 0) ||
	    (strcmp(iface->transport_name, "iser") == 0)) {
		return true;
	}
	return false;
}

int iscsi_do_discovery(struct iscsi_context *ctx, const char **iface_names,
		       uint32_t iface_count, struct iscsi_discovery_cfg *cfg,
		       struct iscsi_node ***nodes, uint32_t *node_count)
{
	uint32_t i = 0;
	struct iscsi_iface *iface = NULL;
	assert(ctx != NULL);
	assert(cfg != NULL);
	assert(discs != NULL);
	assert(disc_count != NULL);
	const char *trans_name = NULL;

	*nodes = NULL;
	*node_count = 0;

	_good(_idbm_lock(ctx), rc, out);

	switch (cfg->type) {
	case ISCSI_DISCOVERY_TYPE_SEND_TARGET:
		if (iface_count == 0) {
			_good(_do_sw_discovery(ctx, NULL, cfg, nodes, node_count),
			      rc, out);
			break;
		} else {
			// We allows user to mix software iface and hardware
			// iface
			for (i = 0; i < iface_count; ++i) {
				if (iface_names[i] == NULL) {
					rc = LIBISCSI_ERR_INVAL;
					_error(ctx, "Invalid argument "
					       "'iface_names': array index "
					       "%" PRIu32 " is NULL", i);
					goto out;
				}
				// Validate user defined iface.
				_good(_idbm_iface_get(ctx, iface_names[i],
						      &iface),
				      rc, out);
				if (_is_sw_iface(iface)) {
					_good(_do_sw_discovery(ctx, NULL, cfg,
							       nodes,
							       node_count),
					      rc, out);
					continue;
				}
				trans_name = iface->transport_name;
				// Load kernel module if needed.
				if (! _iscsi_transport_is_loaded(trans_name)) {
					// iSCSI transport name are the same
					// with driver name for now.
					_good(_load_kernel_module(ctx,
								  trans_name),
					      rc, out);
				}
				_good(_do_hw_discovery(ctx, iface, cfg, nodes,
						       node_count),
				      rc, out);
			}
		}
		break;
	case ISCSI_DISC_PARENT_ISNS:
		// TODO
		break;
	case ISCSI_DISC_PARENT_FW:
		// TODO
		break;
	default:
		rc = LIBISCSI_ERR_INVAL;
		_error(ctx, "Invalid iSCSI discovery type %d", type);
		goto out;
	}

	/* iscsi_discovery_cfg_new() already checked the portal*/

	if (cfg->portal == NULL) {
		rc = LIBISCSI_ERR_INVAL;
		_error(ctx, "NULL iSCSI discovery portal");
		goto out;
	}

	if (strlen(cfg->portal) == 0) {
		rc = LIBISCSI_ERR_INVAL;
		_error(ctx, "Empty iSCSI discovery portal");
		goto out;
	}

out:
	_idbm_unlock(ctx);
	if (rc != LIBISCSI_OK) {
		iscsi_node_free(*nodes, *node_count);
	}
	iscsi_iface_free(iface);
	return rc;
}

int iscsi_discovery_cfg_del(struct iscsi_context *ctx,
			    struct iscsi_discovery_cfg *cfg)
{
	int unlink_rc = 0;
	const char *conf_path = NULL;
	char strerr_buff[_STRERR_BUFF_LEN];

	assert(ctx != NULL);
	assert(cfg != NULL);

	_good(_idbm_lock(ctx), rc, out);
	_good(_idbm_disc_cfg_conf_path_gen(ctx, cfg, &conf_path, NULL),
	      rc, out);
	if (_file_exists(conf_path)) {
		unlink_rc = unlink(conf_path);
		if (unlink_rc != 0) {
			rc = LIBISCSI_ERR_IDBM;
			_error(ctx, "Failed to delete discovery configuration ",
			       "file '%s': error %d, %s", conf_path, errno,
			       _strerror(errno, strerr_buff));
			goto out;
		}
	}

out:
	_idbm_unlock(ctx);
	free(conf_path);
	return rc;
}

static void _disc_init_cfg(struct iscsi_discovery_cfg *cfg,
			   struct iscsid_cfg *d_cfg)
{
	assert(cfg != NULL);
	assert(d_cfg != NULL);

	switch (cfg->type) {
	case ISCSI_DISCOVERY_TYPE_SEND_TARGET:
		memcpy(&cfg->u.sendtargets, d_cfg->st,
		       sizeof(cfg->u.sendtargets));
		break;
	case ISCSI_DISC_PARENT_ISNS:
		memcpy(&cfg->u.isns, d_cfg->isns,
		       sizeof(cfg->u.sendtargets));
		break;
	default:
		return
	}
}
