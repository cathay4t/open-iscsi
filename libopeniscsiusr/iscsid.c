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
#define _GNU_SOURCE   /* For strerror_r() */
#endif


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stddef.h>
#include <unistd.h>
#include <inttypes.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include "iscsid.h"
#include "idbm.h"
#include "misc.h"

#define MAXSLEEP			128
#define ISCSID_REQ_TIMEOUT		1000
#define ISCSID_IPC_NAMESPACE "ISCSIADM_ABSTRACT_NAMESPACE"
#define ISCSI_STATS_CUSTOM_MAX		32

#define MGMT_IPC_GETSTATS_BUF_MAX	\
		(sizeof(struct iscsi_uevent) + \
		 sizeof(struct iscsi_stats) + \
		 sizeof(struct iscsi_stats_custom) * \
		 ISCSI_STATS_CUSTOM_MAX)

enum iscsid_cmd {
	MGMT_IPC_SESSION_LOGIN		= 1,
	MGMT_IPC_SESSION_LOGOUT		= 2,
	MGMT_IPC_SESSION_ACTIVESTAT	= 4,
	MGMT_IPC_CONN_ADD		= 5,
	MGMT_IPC_CONN_REMOVE		= 6,
	MGMT_IPC_SESSION_STATS		= 7,
	MGMT_IPC_CONFIG_INAME		= 8,
	MGMT_IPC_CONFIG_IALIAS		= 9,
	MGMT_IPC_CONFIG_FILE		= 10,
	MGMT_IPC_IMMEDIATE_STOP		= 11,
	MGMT_IPC_SESSION_SYNC		= 12,
	MGMT_IPC_SESSION_INFO		= 13,
	MGMT_IPC_ISNS_DEV_ATTR_QUERY	= 14,
	MGMT_IPC_SEND_TARGETS		= 15,
	MGMT_IPC_NOTIFY_ADD_NODE	= 16,
	MGMT_IPC_NOTIFY_DEL_NODE	= 17,
	MGMT_IPC_NOTIFY_ADD_PORTAL	= 18,
	MGMT_IPC_NOTIFY_DEL_PORTAL	= 19,

	__MGMT_IPC_MAX_COMMAND
};

/* IPC Request */
struct iscsid_req {
	enum iscsid_cmd command;
	uint32_t payload_len;

	union {
		/* messages */
		struct ipc_msg_session {
			int sid;
			node_rec_t rec;
		} session;
		struct ipc_msg_conn {
			int sid;
			int cid;
		} conn;
		struct ipc_msg_send_targets {
			int host_no;
			int do_login;
			struct sockaddr_storage ss;
		} st;
		struct ipc_msg_set_host_param {
			int host_no;
			int param;
			/* TODO: make this variable len to support */
			char value[IFNAMSIZ + 1];

		} set_host_param;
	} u;
};

/* IPC Response */
struct iscsid_rsp {
	enum iscsid_cmd command;
	int err;	/* ISCSI_ERR value */

	union {
		struct ipc_msg_getstats {
			struct iscsi_uevent ev;
			struct iscsi_stats stats;
			char custom[sizeof(struct iscsi_stats_custom) *
				    ISCSI_STATS_CUSTOM_MAX];
		} getstats;
		struct ipc_msg_config {
			char var[VALUE_MAXLEN];
		} config;
		struct ipc_msg_session_state {
			int session_state;
			int conn_state;
		} session_state;
	} u;
};

static int _iscsid_ipc(struct iscsi_context *ctx, struct iscsid_req *req,
		       struct iscsid_rsp *rsp, bool start_iscsid, int tmo);
static void _iscsid_startup(struct iscsi_context *ctx);
static int _resolve_address(struct iscsi_context *ctx, const char *host,
			    int32_t port, struct sockaddr_storage *ss);

int _iscsid_cfg_load(struct iscsi_context *ctx, struct iscsid_cfg **d_cfg)
{
	int rc = LIBISCSI_OK;
	struct iscsid_req req;
	struct iscsid_rsp rsp;
	char *iscsid_conf_file = NULL;

	assert(d_cfg != NULL);
	*d_cfg = calloc(1, sizeof(struct iscsid_cfg));
	_alloc_null_check(ctx, *d_cfg, rc, out);

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_FILE;

	_good(_iscsid_ipc(ctx, &req, &rsp, true, ISCSID_REQ_TIMEOUT), rc, out);

	if (rsp.u.config.var[0] != '\0') {
		snprintf((*d_cfg)->config_file,
			 sizeof((*d_cfg)->config_file)/sizeof(char),
			 "%s", rsp.u.config.var);
		if (!_file_exists((*d_cfg)->config_file)) {
			rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
			_error(ctx, "The iscsid config file '%s' does not "
			       "exists", (*d_cfg)->config_file);
			goto out;
		}
	} else {
		_error(ctx, "Failed to get iscsid config file");
		rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
		goto out;
	}

	if (strlen((*d_cfg)->config_file) == 0) {
		_error(ctx, "The iscsid config file path should not be empty");
		rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
		goto out;
	}

	_good(_idbm_iscsid_cfg_get(ctx, *d_cfg, (*d_cfg)->config_file),
	      rc, out);

out:
	free(iscsid_conf_file);
	if (rc != LIBISCSI_OK) {
		_iscsid_cfg_free(*d_cfg);
	}
	return rc;
}

void _iscsid_cfg_free(struct iscsid_cfg *d_cfg)
{
	free(d_cfg);
}

static int _iscsid_ipc(struct iscsi_context *ctx, struct iscsid_req *req,
		       struct iscsid_rsp *rsp, bool start_iscsid, int tmo)
{
	int fd = -1;
	int rc = LIBISCSI_OK;
	int socket_rc = 0;
	char strerr_buff[_STRERR_BUFF_LEN];
	char iscsid_namespace[64] = ISCSID_IPC_NAMESPACE;
	struct sockaddr_un so_addr;
	size_t so_addr_len = 0;
	int nsec = 0;
	bool connected = false;
	size_t write_len = 0;
	size_t read_len = 0;
	int poll_wait = 0;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		_error(ctx, "can not create IPC socket (%d): %s!", errno,
		       _strerror(errno, strerr_buff));
		return LIBISCSI_ERR_ISCSID_NOTCONN;
	}
	memset(&so_addr, 0, sizeof(so_addr));
	so_addr.sun_family = AF_LOCAL;
	_strncpy(so_addr.sun_path + 1, iscsid_namespace,
		 sizeof(so_addr.sun_path) - 1);
	so_addr_len = offsetof(struct sockaddr_un, sun_path) +
		strlen(so_addr.sun_path + 1) + 1;
	for (nsec = 1; nsec < MAXSLEEP; nsec <<= 1) {
		if (connect(fd, (struct sockaddr *) &so_addr,
			    so_addr_len) == 0) {
			connected = true;
			_debug(ctx, "Connected to iscsid socket '%s'",
			       iscsid_namespace);
			break;
		}

		/* If iscsid isn't there, there's no sense in retrying. */
		if (errno == ECONNREFUSED) {
			if (start_iscsid && nsec == 1)
				_iscsid_startup(ctx);
			else {
				rc = LIBISCSI_ERR_ISCSID_NOTCONN;
				_error(ctx, "The iscsid is not started");
				goto out;
			}
		}

		/*
		 * Delay before trying again
		 */
		if (nsec <= MAXSLEEP/2)
			sleep(nsec);
	}
	if (!connected) {
		rc = LIBISCSI_ERR_ISCSID_NOTCONN;
		_error(ctx, "Timeout on connecting to iscsid, error %d: %s",
		       errno, _strerror(errno, strerr_buff));
		goto out;
	}

	write_len = write(fd, &req, sizeof(req));
	if (write_len != sizeof(req)) {
		rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
		_error(ctx, "Got write error (%d, errno %zu) on cmd: %s, "
		       "daemon died?", write_len, errno,
		       _strerror(errno, strerr_buff));
		goto out;
	}

	if (tmo == -1) {
		tmo = ISCSID_REQ_TIMEOUT;
		poll_wait = 1;
	}
	while (read_len >= sizeof(rsp)) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;
		socket_rc = poll(&pfd, 1, tmo);
		if (socket_rc == 0) {
			if (poll_wait)
				continue;
			rc = LIBISCSI_ERR_ISCSID_NOTCONN;
			_error(ctx, "Timeout on connecting to iscsid");
			goto out;
		} else if (socket_rc < 0) {
			if (socket_rc == EINTR)
				continue;
			rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
			_error(ctx, "Got poll error (%d, errno %d, %s), "
			       "daemon died?", socket_rc, errno,
			       _strerror(errno, strerr_buff));
			goto out;
		} else if (pfd.revents & POLLIN) {
			socket_rc = recv(fd, (void *) &rsp, sizeof(rsp),
					 MSG_WAITALL);
			if (socket_rc < 0) {
				rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
				_error(ctx, "Read error (%d, errno %d, %s), "
				       "daemon died?", socket_rc, errno,
				       _strerror(errno, strerr_buff));
				goto out;
			}
			read_len += socket_rc;
		}
	}

	if ((rsp->err == 0) && (req->command != rsp->command)) {
		_error(ctx, "The iSCSI daemon reply does not match requested "
		       "command");
		rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
		goto out;
	}
	if (rsp->err != 0) {
		rc = LIBISCSI_ERR_ISCSID_COMM_ERR;
		_error(ctx, "The iSCSI daemon failed to execute command %d, "
		       "error %d", rsp->command, rsp->err);
		goto out;
	}

out:
	if (fd >= 0) {
		close(fd);
	}
	return rc;
}

static void _iscsid_startup(struct iscsi_context *ctx)
{
	struct iscsid_cfg *d_cfg = NULL;
	assert(ctx != NULL);

	if (_iscsid_cfg_load(ctx, &d_cfg) != LIBISCSI_OK)
		return;
	if (strlen(d_cfg->startup) == 0) {
		_error(ctx, "iscsid is not running. Could not start it up "
			  "automatically using the startup command in the "
			  "/etc/iscsi/iscsid.conf iscsid.startup setting. "
			  "Please check that the file exists or that your "
			  "init scripts have started iscsid.");
		goto out;
	}
	_debug(ctx, "Starting iscsid daemon via command %s", d_cfg->startup);
	if (system(d_cfg->startup) < 0)
		_error(ctx, "Could not execute '%s' (err %d)", d_cfg->startup,
		       errno);

out:
	_iscsid_cfg_free(d_cfg);
	return;
}

int _iscsid_send_target(struct iscsi_context *ctx,
			struct iscsi_discovery_cfg *cfg, uint32_t host_no)
{
	int rc = LIBISCSI_OK;
	struct iscsid_req req;
	struct iscsid_rsp rsp;
	struct sockaddr_storage ss;

	assert(ctx != NULL);
	assert(cfg != NULL);

	_good(_resolve_address(ctx, cfg->address, cfg->port, &ss), rc, out);
	_debug(ctx, "Offload send target though host %d to %s port %" PRIi32,
	       host_no, cfg->address, cfg->port);
	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SEND_TARGETS;
	req.u.st.host_no = host_no;
	req.u.st.do_login = false; // We have separate interface for login.
	req.u.st.ss = ss;
	_good(_iscsid_ipc(ctx, &req, &rsp, true, cfg->iscsid_req_tmo),
	      rc, out);

out:
	return rc;

}

static int _resolve_address(struct iscsi_context *ctx, const char *host,
			    int32_t port, struct sockaddr_storage *ss)
{
	struct addrinfo hints, *res;
	char port_str_buff[11]; // Max int32 is 2147483647
	int rc = 0;

	assert(ctx != NULL);
	assert(host != NULL);
	assert(port != 0);
	assert(ss != NULL);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	snprintf(port_str_buff, sizeof(port_str_buff)/sizeof(char),
		 "%" PRIi32, port);

	if ((rc = getaddrinfo(host, port_str_buff, &hints, &res))) {
		_error(ctx,"Cannot resolve host %s. getaddrinfo error: %d "
		       "[%s]", host, rc, gai_strerror(rc));
		return LIBISCSI_ERR_HOST_NOT_FOUND;
	}

	memcpy(ss, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	return LIBISCSI_OK;
}
