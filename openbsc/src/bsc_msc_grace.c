/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/bsc_msc_grace.h>
#include <openbsc/bsc_msc_rf.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/signal.h>

int bsc_grace_allow_new_connection(struct gsm_network *network)
{
	return network->rf->policy == S_RF_ON;
}

static int handle_sub(struct gsm_lchan *lchan, const char *text)
{
	/* only send it to TCH */
	if (lchan->type != GSM_LCHAN_TCH_H && lchan->type != GSM_LCHAN_TCH_F)
		return -1;

	/* only when active */
	if (lchan->state != LCHAN_S_ACTIVE)
		return -1;

	gsm0480_send_ussdNotify(lchan, 0, text);
	gsm0480_send_releaseComplete(lchan);

	return 0;
}

/*
 * The place to handle the grace mode. Right now we will send
 * USSD messages to the subscriber, in the future we might start
 * a timer to have different modes for the grace period.
 */
static int handle_grace(struct gsm_network *network)
{
	int ts_nr, lchan_nr;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;

	if (!network->ussd_grace_txt)
		return 0;

	llist_for_each_entry(bts, &network->bts_list, list) {
		llist_for_each_entry(trx, &bts->trx_list, list) {
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ++ts_nr) {
				struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
				for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN; ++lchan_nr) {
					handle_sub(&ts->lchan[lchan_nr],
						   network->ussd_grace_txt);
				}
			}
		}
	}
	return 0;
}

static int handle_rf_signal(unsigned int subsys, unsigned int signal,
			    void *handler_data, void *signal_data)
{
	struct rf_signal_data *sig;

	if (subsys != SS_RF)
		return -1;

	sig = signal_data;

	if (signal == S_RF_GRACE)
		handle_grace(sig->net);

	return 0;
}

static __attribute__((constructor)) void on_dso_load_grace(void)
{
	register_signal_handler(SS_RF, handle_rf_signal, NULL);
}
