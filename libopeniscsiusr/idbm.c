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

/* The code below is modified from usr/idbm.c which licensed like below:
 *
 * iSCSI Discovery Database Library
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
 * maintained by open-iscsi@@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE			/* For strerror_r() */
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"

#include "context.h"
#include "idbm.h"
#include "misc.h"

#ifndef LOCK_DIR
#define LOCK_DIR		"/var/lock/iscsi"
#endif
#define LOCK_FILE		LOCK_DIR"/lock"
#define LOCK_WRITE_FILE		LOCK_DIR"/lock.write"

struct idbm {
	void		*discdb;
	void		*nodedb;
	char		*configfile;
	int             refs;
	idbm_get_config_file_fn *get_config_file;
	node_rec_t	nrec;
	recinfo_t	ninfo[MAX_KEYS];
	discovery_rec_t	drec_st;
	recinfo_t	dinfo_st[MAX_KEYS];
	discovery_rec_t	drec_slp;
	recinfo_t	dinfo_slp[MAX_KEYS];
	discovery_rec_t	drec_isns;
	recinfo_t	dinfo_isns[MAX_KEYS];
} idbm_t;

int _idbm_lock(struct iscsi_context *ctx)
{
	int fd, i, ret;
	struct idbm *db = NULL;
	char strerr_buff[_STRERR_BUFF_LEN];

	assert(ctx != NULL);

	db = ctx->db;

	if (db->refs > 0) {
		db->refs++;
		return 0;
	}

	if (access(LOCK_DIR, F_OK) != 0) {
		if (mkdir(LOCK_DIR, 0660) != 0) {
			_error(ctx, "Could not open %s: %d %s", LOCK_DIR, errno,
				_strerror(errno, strerr_buff));
			return LIBISCSI_ERR_IDBM;
		}
	}

	fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0666);
	if (fd >= 0)
		close(fd);

	for (i = 0; i < 3000; i++) {
		ret = link(LOCK_FILE, LOCK_WRITE_FILE);
		if (ret == 0)
			break;

		if (errno != EEXIST) {
			_error(ctx, "Maybe you are not root? "
			       "Could not lock discovery DB: %s: %d %s",
			       LOCK_WRITE_FILE, errno,
			       _strerror(errno, strerr_buff));
			return LIBISCSI_ERR_IDBM;
		} else if (i == 0)
			_debug(ctx, "Waiting for discovery DB lock");

		usleep(10000);
	}

	db->refs = 1;
	return 0;
}

void _idbm_unlock(struct iscsi_context *ctx)
{
	struct idbm *db = NULL;

	assert(ctx != NULL);

	db = ctx->db;

	if (db->refs > 1) {
		db->refs--;
		return;
	}

	db->refs = 0;
	unlink(LOCK_WRITE_FILE);
}

int _idbm_print_iface(struct iscsi_context *ctx, struct iscsi_iface *iface,
		      FILE *f)
{
}
