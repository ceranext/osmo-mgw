/* Message connection list handling */

/*
 * (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <osmocom/mgcp/mgcp_conn.h>
#include <osmocom/mgcp/mgcp_network.h>
#include <osmocom/mgcp/mgcp_protocol.h>
#include <osmocom/mgcp/mgcp_common.h>
#include <osmocom/mgcp/mgcp_endp.h>
#include <osmocom/mgcp/mgcp_trunk.h>
#include <osmocom/mgcp/mgcp_sdp.h>
#include <osmocom/mgcp/mgcp_codec.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/timer.h>
#include <ctype.h>

const static struct rate_ctr_group_desc rate_ctr_group_desc = {
	.group_name_prefix = "conn_rtp",
	.group_description = "rtp connection statistics",
	.class_id = 1,
	.num_ctr = ARRAY_SIZE(mgcp_conn_rate_ctr_desc),
	.ctr_desc = mgcp_conn_rate_ctr_desc
};


/* Allocate a new connection identifier. According to RFC3435, they must
 * be unique only within the scope of the endpoint. (Caller must provide
 * memory for id) */
static int mgcp_alloc_id(struct mgcp_endpoint *endp, char *id)
{
#define MGCP_CONN_ID_GEN_LEN 8
	int i;
	int k;
	int rc;
	uint8_t id_bin[MGCP_CONN_ID_GEN_LEN / 2];
	char *id_hex;

	/* Generate a connection id that is unique for the current endpoint.
	 * Technically a counter would be sufficient, but in order to
	 * be able to find a specific connection in large logfiles and to
	 * prevent unintentional connections we assign the connection
	 * identifiers randomly from a reasonable large number space */
	for (i = 0; i < 32; i++) {
		LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_alloc_id: loop %d\n", i);
		rc = osmo_get_rand_id(id_bin, sizeof(id_bin));
		if (rc < 0) {
			LOGP(DLMGCP, LOGL_ERROR, "pespin: [%d] osmo_get_rand_id failed: %d\n", i, rc);
			return rc;
		}
		LOGP(DLMGCP, LOGL_ERROR, "pespin: [%d] after osmo_get_rand_id\n", i);

		id_hex = osmo_hexdump_nospc(id_bin, sizeof(id_bin));
		LOGP(DLMGCP, LOGL_ERROR, "pespin: [%d] after osmo_hexdump_nospc\n", i);
		for (k = 0; k < strlen(id_hex); k++)
			id_hex[k] = toupper(id_hex[k]);
		LOGP(DLMGCP, LOGL_ERROR, "pespin: [%d] after toupper: '%s'\n", i, id_hex);

		/* ensure that the generated conn_id is unique
		 * for this endpoint */
		if (!mgcp_conn_get_rtp(endp, id_hex)) {
			LOGP(DLMGCP, LOGL_ERROR, "pespin: [%d] mgcp_conn_get_rtp finish\n", i);
			osmo_strlcpy(id, id_hex, MGCP_CONN_ID_MAXLEN);
			return 0;
		}
		LOGP(DLMGCP, LOGL_ERROR, "pespin: [%d] after mgcp_conn_get_rtp\n", i);
	}

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "unable to generate a unique connectionIdentifier\n");

	return -1;
}

/* Initialize rtp connection struct with default values */
static int mgcp_rtp_conn_init(struct mgcp_conn_rtp *conn_rtp, struct mgcp_conn *conn)
{
	LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_rtp_conn_init: init\n");
	struct mgcp_rtp_end *end = &conn_rtp->end;
	/* FIXME: Each new rate counter group requires an unique index. At the
	 * moment we generate this index using this counter, but perhaps there
	 * is a more concious way to assign the indexes. */
	static unsigned int rate_ctr_index = 0;

	conn_rtp->type = MGCP_RTP_DEFAULT;
	conn_rtp->osmux.cid_allocated = false;
	conn_rtp->osmux.cid = 0;

	/* backpointer to the generic part of the connection */
	conn->u.rtp.conn = conn;

	end->rtp.fd = -1;
	end->rtcp.fd = -1;
	end->rtp_port = end->rtcp_port = 0;
	talloc_free(end->fmtp_extra);
	end->fmtp_extra = NULL;

	/* Set default values */
	end->frames_per_packet = 0;	/* unknown */
	end->packet_duration_ms = DEFAULT_RTP_AUDIO_PACKET_DURATION_MS;
	end->output_enabled = 0;
	end->maximum_packet_time = -1;

	conn_rtp->rate_ctr_group = rate_ctr_group_alloc(conn, &rate_ctr_group_desc, rate_ctr_index);
	if (!conn_rtp->rate_ctr_group)
		return -1;

	conn_rtp->state.in_stream.err_ts_ctr = &conn_rtp->rate_ctr_group->ctr[IN_STREAM_ERR_TSTMP_CTR];
	conn_rtp->state.out_stream.err_ts_ctr = &conn_rtp->rate_ctr_group->ctr[OUT_STREAM_ERR_TSTMP_CTR];
	rate_ctr_index++;

	/* Make sure codec table is reset */
	mgcp_codec_reset_all(conn_rtp);
	LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_rtp_conn_init: after mgcp_codec_reset_all\n");

	return 0;
}

/* Cleanup rtp connection struct */
static void mgcp_rtp_conn_cleanup(struct mgcp_conn_rtp *conn_rtp)
{
	if (mgcp_conn_rtp_is_osmux(conn_rtp))
		conn_osmux_disable(conn_rtp);
	mgcp_free_rtp_port(&conn_rtp->end);
	rate_ctr_group_free(conn_rtp->rate_ctr_group);
	mgcp_codec_reset_all(conn_rtp);
}

void mgcp_conn_watchdog_cb(void *data)
{
	struct mgcp_conn *conn = data;
	LOGPCONN(conn, DLMGCP, LOGL_ERROR, "connection timed out!\n");
	mgcp_conn_free(conn->endp, conn->id);
}

void mgcp_conn_watchdog_kick(struct mgcp_conn *conn)
{
	int timeout = conn->endp->cfg->conn_timeout;
	if (!timeout)
		return;

	LOGPCONN(conn, DLMGCP, LOGL_DEBUG, "watchdog kicked\n");
	osmo_timer_schedule(&conn->watchdog, timeout, 0);
}

/*! allocate a new connection list entry.
 *  \param[in] ctx talloc context
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \param[in] type connection type (e.g. MGCP_CONN_TYPE_RTP)
 *  \returns pointer to allocated connection, NULL on error */
struct mgcp_conn *mgcp_conn_alloc(void *ctx, struct mgcp_endpoint *endp,
				  enum mgcp_conn_type type, char *name)
{
	struct mgcp_conn *conn;
	int rc;

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: start\n");
	/* Do not allow more then two connections */
	if (llist_count(&endp->conns) >= endp->type->max_conns)
		return NULL;

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after llist_count\n");

	/* Create new connection and add it to the list */
	conn = talloc_zero(ctx, struct mgcp_conn);
	if (!conn)
		return NULL;
	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after talloc_zero\n");
	conn->endp = endp;
	conn->type = type;
	conn->mode = MGCP_CONN_NONE;
	conn->mode_orig = MGCP_CONN_NONE;
	osmo_strlcpy(conn->name, name, sizeof(conn->name));
	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after osmo_strlcpy: '%s'\n", conn->name);
	rc = mgcp_alloc_id(endp, conn->id);
	if (rc < 0) {
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc:mgcp_alloc_id failed: %d\n", rc);
		talloc_free(conn);
		return NULL;
	}
	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after mgcp_alloc_id\n");

	switch (type) {
	case MGCP_CONN_TYPE_RTP:
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: type MGCP_CONN_TYPE_RTP\n");
		if (mgcp_rtp_conn_init(&conn->u.rtp, conn) < 0) {
			talloc_free(conn);
			return NULL;
		}
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after MGCP_CONN_TYPE_RTP\n");
		break;
	default:
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: default type\n");
		/* NOTE: This should never be called with an
		 * invalid type, its up to the programmer
		 * to ensure propery types */
		OSMO_ASSERT(false);
	}

	/* Initialize watchdog */
	osmo_timer_setup(&conn->watchdog, mgcp_conn_watchdog_cb, conn);
	mgcp_conn_watchdog_kick(conn);
	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after mgcp_conn_watchdog_kick\n");
	mgcp_endp_add_conn(endp, conn);
	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_alloc: after mgcp_endp_add_conn\n");

	return conn;
}

/*! find a connection by its ID.
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \returns pointer to allocated connection, NULL if not found */
struct mgcp_conn *mgcp_conn_get(struct mgcp_endpoint *endp, const char *id)
{
	struct mgcp_conn *conn;
	const char *id_upper;
	const char *conn_id;

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: start '%s'\n", id);


	if (!id || !*id)
		return NULL;

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: after first check\n");

	/* Ignore leading zeros in needle */
	while (*id == '0')
		id++;

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: after loop: %s\n", id);

	/* Use uppercase to compare identifiers, to avoid mismatches: RFC3435 2.1.3.2 "Names of
	 * Connections" defines the id as a hex string, so clients may return lower case hex even though
	 * we sent upper case hex in the CRCX response. */
	id_upper = osmo_str_toupper(id);
	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: after osmo_str_toupper: %s\n", id_upper);


	llist_for_each_entry(conn, &endp->conns, entry) {
		/* Ignore leading zeros in haystack */
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: checking against: '%s'\n", conn->id);

		for (conn_id=conn->id; *conn_id == '0'; conn_id++);
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: checking forward against: '%s'\n", conn_id);

		if (strcmp(conn_id, id_upper) == 0) {
			LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: strcmp matches\n");
			return conn;
		}
		LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: after strcmp\n");
	}

	LOGPENDP(endp, DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get: return NULL\n");

	return NULL;
}

/*! find an RTP connection by its ID.
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection
 *  \returns pointer to allocated connection, NULL if not found */
struct mgcp_conn_rtp *mgcp_conn_get_rtp(struct mgcp_endpoint *endp,
					const char *id)
{
	struct mgcp_conn *conn;

	LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get_rtp: start '%s'\n", id);

	conn = mgcp_conn_get(endp, id);
	if (!conn)
		return NULL;

	LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get_rtp: after mgcp_conn_get %p\n", conn);

	if (conn->type == MGCP_CONN_TYPE_RTP) {
		LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get_rtp: type is MGCP_CONN_TYPE_RTP\n");
		return &conn->u.rtp;
	}

		LOGP(DLMGCP, LOGL_ERROR, "pespin: mgcp_conn_get_rtp: return NULL\n");
	return NULL;
}

static void aggregate_rtp_conn_stats(struct mgcp_endpoint *endp, struct mgcp_conn_rtp *conn_rtp)
{
	struct rate_ctr_group *all_stats = endp->trunk->ratectr.all_rtp_conn_stats;
	struct rate_ctr_group *conn_stats = conn_rtp->rate_ctr_group;

	if (all_stats == NULL || conn_stats == NULL)
		return;

	/* Compared to per-connection RTP statistics, aggregated RTP statistics
	 * contain one additional rate couter item (RTP_NUM_CONNECTIONS).
	 * All other counters in both counter groups correspond to each other. */
	OSMO_ASSERT(conn_stats->desc->num_ctr + 1 == all_stats->desc->num_ctr);

	/* all other counters are [now] updated in real-time */
	rate_ctr_add(&all_stats->ctr[IN_STREAM_ERR_TSTMP_CTR],
		     conn_stats->ctr[IN_STREAM_ERR_TSTMP_CTR].current);
	rate_ctr_add(&all_stats->ctr[OUT_STREAM_ERR_TSTMP_CTR],
		     conn_stats->ctr[OUT_STREAM_ERR_TSTMP_CTR].current);

	rate_ctr_inc(&all_stats->ctr[RTP_NUM_CONNECTIONS]);
}

/*! free a connection by its ID.
 *  \param[in] endp associated endpoint
 *  \param[in] id identification number of the connection */
void mgcp_conn_free(struct mgcp_endpoint *endp, const char *id)
{
	struct mgcp_conn *conn;

	conn = mgcp_conn_get(endp, id);
	if (!conn)
		return;

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		aggregate_rtp_conn_stats(endp, &conn->u.rtp);
		mgcp_rtp_conn_cleanup(&conn->u.rtp);
		break;
	default:
		/* NOTE: This should never be called with an
		 * invalid type, its up to the programmer
		 * to ensure propery types */
		OSMO_ASSERT(false);
	}

	osmo_timer_del(&conn->watchdog);
	mgcp_endp_remove_conn(endp, conn);
	/* WARN: endp may have be freed after call to mgcp_endp_remove_conn */
	talloc_free(conn);
}

/*! free oldest connection in the list.
 *  \param[in] endp associated endpoint */
void mgcp_conn_free_oldest(struct mgcp_endpoint *endp)
{
	struct mgcp_conn *conn;

	if (llist_empty(&endp->conns))
		return;

	conn = llist_last_entry(&endp->conns, struct mgcp_conn, entry);
	if (!conn)
		return;

	mgcp_conn_free(endp, conn->id);
}

/*! free all connections at once.
 *  \param[in] endp associated endpoint */
void mgcp_conn_free_all(struct mgcp_endpoint *endp)
{
	struct mgcp_conn *conn;
	struct mgcp_conn *conn_tmp;

	/* Drop all items in the list */
	llist_for_each_entry_safe(conn, conn_tmp, &endp->conns, entry) {
		mgcp_conn_free(endp, conn->id);
	}

	return;
}

/*! dump basic connection information to human readable string.
 *  \param[in] conn to dump
 *  \returns human readable string */
char *mgcp_conn_dump(struct mgcp_conn *conn)
{
	static char str[sizeof(conn->name)+sizeof(conn->id)+256];
	char ipbuf[INET6_ADDRSTRLEN];

	if (!conn) {
		snprintf(str, sizeof(str), "(null connection)");
		return str;
	}

	switch (conn->type) {
	case MGCP_CONN_TYPE_RTP:
		/* Dump RTP connection */
		snprintf(str, sizeof(str), "(%s/rtp, id:0x%s, ip:%s, "
			 "rtp:%u rtcp:%u)",
			 conn->name,
			 conn->id,
			 osmo_sockaddr_ntop(&conn->u.rtp.end.addr.u.sa, ipbuf),
			 ntohs(conn->u.rtp.end.rtp_port),
			 ntohs(conn->u.rtp.end.rtcp_port));
		break;

	default:
		/* Should not happen, we should be able to dump
		 * every possible connection type. */
		snprintf(str, sizeof(str), "(unknown connection type)");
		break;
	}

	return str;
}

/*! find destination connection on a specific endpoint.
 *  \param[in] conn to search a destination for
 *  \returns destination connection, NULL on failure */
struct mgcp_conn *mgcp_find_dst_conn(struct mgcp_conn *conn)
{
	struct mgcp_endpoint *endp;
	struct mgcp_conn *partner_conn;
	endp = conn->endp;

	/*! NOTE: This simply works by grabbing the first connection that is
	 *  not the supplied connection, which is suitable for endpoints that
	 *  do not serve more than two connections. */

	llist_for_each_entry(partner_conn, &endp->conns, entry) {
		if (conn != partner_conn) {
			return partner_conn;
		}
	}

	return NULL;
}

/*! get oldest connection in the list.
 *  \param[in] endp associated endpoint */
struct mgcp_conn *mgcp_conn_get_oldest(struct mgcp_endpoint *endp)
{
	if (llist_empty(&endp->conns))
		return NULL;

	return llist_last_entry(&endp->conns, struct mgcp_conn, entry);
}
