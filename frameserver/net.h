/* Arcan-fe, scriptable front-end engine
 *
 * Arcan-fe is the legal property of its developers, please refer
 * to the COPYRIGHT file distributed with this source distribution.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#ifndef HAVE_ARCAN_FRAMESERVER_NET
#define HAVE_ARCAN_FRAMESERVER_NET

#ifndef DEFAULT_DISCOVER_REQ_PORT
#define DEFAULT_DISCOVER_REQ_PORT 6681
#endif

#ifndef DEFAULT_DISCOVER_RESP_PORT
#define DEFAULT_DISCOVER_RESP_PORT 6682
#endif

#ifndef DEFAULT_RLEDEC_SZ 
#define DEFAULT_RLEDEC_SZ 65536
#endif

/* this is just used as a hint (when using discovery mode) */
#ifndef DEFAULT_CONNECTION_PORT
#define DEFAULT_CONNECTION_PORT 6680
#endif

/* should be >= 64k */
#ifndef DEFAULT_INBUF_SZ
#define DEFAULT_INBUF_SZ 65536
#endif

/* should be >= 64k */
#ifndef DEFAULT_OUTBUF_SZ
#define DEFAULT_OUTBUF_SZ 65536
#endif

#ifndef DEFAULT_CONNECTION_CAP
#define DEFAULT_CONNECTION_CAP 64 
#endif

/* only effective for state transfer over the TCP channel,
 * additional state data won't be pushed until buffer 
 * status is below SATCAP * OUTBUF_SZ */
#ifndef DEFAULT_OUTBUF_SATCAP
#define DEFAULT_OUTBUF_SATCAP 0.5
#endif

void arcan_frameserver_net_run(const char* resource, const char* shmkey);

#endif
