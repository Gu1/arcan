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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,MA 02110-1301,USA.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <assert.h>

#include "net_graph.h"
#include <arcan_math.h>
#include <arcan_general.h>
/*
 * allocate context -> depending on type, different buckets are set up.
 * Each bucket maintain separate data-tracking,
 * can have different rendering modes etc. Buckets are populated indirectly
 * through calling the exported higher-abstraction
 * functions ("connected", "sending tlv", ...) and the rendering mode
 * of the context define how the buckets are setup,
 * scaling, refreshes etc.
 */

/* can be created by taking a TTF font,
 * convert -resize 8x8\! -font Name-Family-Style -pointsize num 
 * label:CodePoint outp.xbm sweep through the desired codepoints and 
 * build the outer array, dump to header and replace */
#include "font_8x8.h"

static const int pxfont_width = PXFONT_WIDTH;
static const int pxfont_height = PXFONT_HEIGHT;

#define GRAPH_SERVER(X) ( (X) >= GRAPH_NET_SERVER && (X) < GRAPH_NET_CLIENT )

enum plot_mode {
	PLOT_XY_POINT,
	PLOT_XY_LERP,
	PLOT_XY_ROW
};

struct datapoint {
	long long int timestamp;
	char* label; /* optional */
/* part of the regular dataflow or should be treated as an alarm */
	bool continuous; 

	char type_id;
	union {
		int ival;
		float fval;
	} value;
};

struct event_bucket {
	bool labels;   /* render possibly attached labels */

	/* should basev/maxv/minv be relative to window or accumulate */
	bool absolute; 

	enum plot_mode mode;

/* data model -- ring-buffer of datapoints, these and scales are
 * modified dynamically based on the domain- specific events further below */
	int ringbuf_sz, buf_front, buf_back;
	struct datapoint* ringbuf;

/* x scale */
	const char* suffix_x;
	long long int last_updated;
	long long int window_beg;

/* y scale */
	const char* suffix_y;
	int maxv, minv, basev;
};

struct graph_context {
/* graphing storage */
	int width, height;
	uint32_t* vidp;

	struct {
		uint32_t bg;
		uint32_t border;
		uint32_t grid;
		uint32_t gridalign;
		uint32_t data;
		uint32_t alert;
		uint32_t notice;
	} colors;

/* data storage */
	int n_buckets;
	struct event_bucket* buckets;

/* mode is determined on context creation, and determines how logged entries
 * will be stored and presented */
	enum graphing_mode mode;
};

void blend_hline(struct graph_context* ctx, int x, int y, 
	int width, uint32_t col, float fact)
{
}

void blend_vline(struct graph_context* ctx, int x, int y, 
	int width, uint32_t col, float fact)
{
}

void draw_hline(struct graph_context* ctx, int x, int y, 
	int width, uint32_t col)
{
	width = abs(width);

/* clip */
	if (y < 0 || y >= ctx->height)
		return;

	if (x + width > ctx->width)
		width = ctx->width - x;

	uint32_t* buf = &ctx->vidp[y * ctx->width + x];

	while (--width > 0)
		*(buf++) = col;
}

void draw_vline(struct graph_context* ctx, int x, int y, 
	int height, uint32_t col)
{
	int dir;
	int length = abs(height);

	if (x < 0 || x >= ctx->width || height == 0)
		return;

/* direction and clip */
	if (height < 0){
		dir = -1;
		if (y - height < 0)
			length = y;
	} else {
		dir = 1;
		if (y + height >= ctx->height)
			length = ctx->height - y - 1;
	}

	uint32_t* buf = &ctx->vidp[y * ctx->width + x];
	int step = dir * ctx->width;

	while (--length > 0){
		*buf = col;
		buf += step;
	}
}

void clear_tocol(struct graph_context* ctx, uint32_t col)
{
	int ntc = ctx->width * ctx->height;
	for (int i = 0; i < ntc; i++)
		ctx->vidp[i] = col;
}

bool draw_box(struct graph_context* ctx, int x, int y, 
	int width, int height, uint32_t col)
{
	if (x >= ctx->width || y >= ctx->height || x < 0 || y < 0)
		return false;

	width  = abs(width);
	height = abs(height);

	int ux = x + width  >= ctx->width  ?  ctx->width : x + width;
	int uy = y + height >= ctx->height ? ctx->height : y + height;

	for (int cy = y; cy != uy; cy++)
		for (int cx = x; cx != ux; cx++)
			ctx->vidp[ cy * ctx->width + cx ] = col;

	return true;
}

void draw_square(struct graph_context* ctx, int x, int y, 
	int side, uint32_t col)
{
	side = abs(side);

	int lx = x - side >= 0 ? x - side : 0;
	int ly = y - side >= 0 ? y - side : 0;
	int ux = x + side >= ctx->width  ? ctx->width  - 1 : x + side;
	int uy = y + side >= ctx->height ? ctx->height - 1 : y + side;

	for (int cy = ly; cy != uy; cy++)
		for (int cx = lx; cx != ux; cx++)
			ctx->vidp[ cy * ctx->width + cx ] = col;
}

void text_dimensions(struct graph_context* ctx, const char* msg,
	int* dw, int* dh){

	int nvc = 0;
	while (*msg){
		if (*msg <= 127)
			nvc++;
	
		msg++;
	}

	*dw = nvc * pxfont_width;
	*dh = pxfont_height;
}

/* use the included 8x8 bitmap font to draw simple 7-bit ASCII messages */
bool draw_text(struct graph_context* ctx, const char* msg, 
	int x, int y, uint32_t txcol)
{
	if (y + pxfont_height >= ctx->height)
		return false;

	while (*msg && x+pxfont_width < ctx->width){
/* font only has that many entry points */
		if (*msg <= 127)
			for (int row = 0; row < pxfont_height; row++)
				for (int col = 0; col < pxfont_width; col++)
/* no AA, no blending, no filtering */
					if (PXFONT[(unsigned char) *msg][row] & 1 << col)
						ctx->vidp[ctx->width * (row + y) + col + x] = txcol;

			x += pxfont_width;
			msg++;
	}

	return true;
}

static void draw_bucket(struct graph_context* ctx, struct event_bucket* src, 
	int x, int y, int w, int h)
{
/* with labels toggled, the issue is if labels should be 
 * placed closed to the datapoint, or if separate space should be 
 * allocated beneath the grid and use colors to map */
	draw_vline(ctx, x, y, h, ctx->colors.border);
	draw_hline(ctx, x, y, w, ctx->colors.border);

/*	int step_sz = (src->maxv - src->minv) / y; */
	int i = src->buf_back;

/* we use the bucket midpoint as 0 for y axis, it should be <= minv */
/* independent of draw-mode, process non-continous datapoints separately,
 * and distribute evenly across y. */ 
	switch (src->mode){
	case PLOT_XY_POINT:
		while (i != src->buf_front){
			int xv = 0, yv = 0;
			uint32_t col = 0;
			draw_square(ctx, xv, yv, 4, col);
			i = (i + 1) % src->ringbuf_sz;
		}
	break;
	case PLOT_XY_LERP:
/* check the xv and yv for the datapoint vs. the next datapoint and 
 * linearly fill in the rest */	
	break;
	case PLOT_XY_ROW:   
/* for every datapoint, fill from y- base to projected y-point, and 
 * for collisions vs x. scale and horizontal time resolution, additively 
 * blend to illustrate the intensity between datapoints */
	break;
	default:
		abort();
	}
}

/* These two functions traverses the history buffer, 
 * drops the elements that are outside the current time-window,
 * and converts the others to draw-calls, layout is different 
 * for server (1:n) and client (1:1). */
static bool graph_refresh_server(struct graph_context* ctx)
{
	if (ctx->mode == GRAPH_MANUAL)
		return false;

/* these are responsible for allocating buckets based on mode, 
 * only relevant for GRAPH_NET class */
	switch (ctx->mode){

/* divide the space evenly, one for each client */
	case GRAPH_NET_SERVER_SPLIT:
	break;

/* server mode, main server ins and outs */
	case GRAPH_NET_SERVER_SINGLE:
	break;

/* we just want to see server traffic abstracted */
	case GRAPH_NET_SERVER:
		clear_tocol(ctx, ctx->colors.bg);
		draw_bucket(ctx, &ctx->buckets[0], 0, 0, ctx->width, ctx->height);
	break;

/* silence compilers .. */
	case GRAPH_MANUAL:
		case GRAPH_NET_CLIENT:
	break;
	}

	return true;
}

static bool graph_refresh_client(struct graph_context* ctx)
{
	if (ctx->n_buckets == 0)
		return false;

/*	int bucketh = (ctx->height - 10) / 3; */

	clear_tocol(ctx, ctx->colors.bg);
	draw_bucket(ctx, &ctx->buckets[0], 0, 0, ctx->width, ctx->height);

	return true;
}

bool graph_refresh(struct graph_context* ctx)
{
	if (ctx->mode != GRAPH_NET_CLIENT)
		return graph_refresh_server(ctx);
	else
		return graph_refresh_client(ctx);
}

/* setup basic context (history buffer etc.)
 * along with colours etc. to some defaults. */
struct graph_context* graphing_new(int width, int height, uint32_t* vidp)
{
	if (width * height == 0)
		return NULL;

	struct graph_context* rctx = malloc( sizeof(struct graph_context) );

	if (rctx){
		struct graph_context rv = { 
			.mode = GRAPH_MANUAL, 
			.width = width, 
			.height = height, 
			.vidp = vidp,
			.colors.bg = 0xffffffff, 
			.colors.border = 0xff000000,
		 	.colors.grid = 0xffaaaaaa,
		 	.colors.gridalign = 0xffff4444,
			.colors.data = 0xff00ff00,
		 	.colors.alert = 0xffff0000,
		 	.colors.notice = 0xff0000ff };
			*rctx = rv;
	}

	return rctx;
}

static void drop_buckets(struct graph_context* ctx)
{
	if (ctx->n_buckets > 0){
		for (int i = 0; i < ctx->n_buckets; i++){
			for (int j = 0; j < ctx->buckets[i].ringbuf_sz; j++)
				free(ctx->buckets[i].ringbuf[j].label);
	
			free(ctx->buckets[i].ringbuf);
		}

		ctx->n_buckets = 0;
		free(ctx->buckets);
		ctx->buckets = NULL;
	}
}

void graphing_switch_mode(struct graph_context* ctx, enum graphing_mode mode)
{
	assert(ctx);
	drop_buckets(ctx);

	switch(mode){
/* create <connection limit> buckets */
	case GRAPH_NET_SERVER_SPLIT:
		mode = GRAPH_MANUAL;			
	break;

/* server mode, focus on a single targetid */
	case GRAPH_NET_SERVER_SINGLE:
		ctx->n_buckets = 1;
		ctx->buckets = malloc(sizeof(struct event_bucket) * ctx->n_buckets);
		memset(ctx->buckets, '\0', sizeof(struct event_bucket));
		ctx->buckets[0].labels = false;
		ctx->buckets[0].absolute = false;
		ctx->buckets[0].mode = PLOT_XY_LERP;
	break;

/* plot out traffic belonging to a single client */
	case GRAPH_NET_CLIENT:
		ctx->n_buckets = 1;
		ctx->buckets = malloc(sizeof(struct event_bucket) * ctx->n_buckets);
		ctx->buckets[0].labels = false;
		ctx->buckets[0].absolute = false;
		ctx->buckets[0].mode = PLOT_XY_LERP;
	break;

/* we just want to see server traffic abstracted */
	case GRAPH_NET_SERVER:
		ctx->n_buckets = 1;
		ctx->buckets = malloc(sizeof(struct event_bucket) * ctx->n_buckets);
		ctx->buckets[0].labels = true;
		ctx->buckets[0].absolute = false;
		ctx->buckets[0].mode = PLOT_XY_ROW;
	break;

/* already set / don't care (re-use of graphing code) */
	case GRAPH_MANUAL:
	break;
	}

	ctx->mode = mode;
}

void graphing_destroy(struct graph_context* ctx)
{
		if (ctx){
			drop_buckets(ctx);

			memset(ctx, 0, sizeof(struct graph_context));
			free(ctx);
		}
}

/* all these events are simply translated to a data-point and 
 * inserted into the related bucket */
void graph_log_connected(struct graph_context* ctx, char* label)
{
	assert(ctx);
	if (ctx->n_buckets == 0)
		return;	

	if (GRAPH_SERVER(ctx->mode)){
			
	} else {
	}

}

void graph_log_connecting(struct graph_context* ctx, char* label)
{
	assert(ctx);
	if (ctx->n_buckets == 0)
		return;	

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}

}

void graph_log_connection(struct graph_context* ctx, 
	unsigned id, const char* label)
{
	if (ctx->n_buckets == 0)
		return;	

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}
}

void graph_log_disconnect(struct graph_context* ctx, 
	unsigned id, const char* label)
{
	assert(ctx);

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}
}

void graph_log_discover_req(struct graph_context* ctx, 
	unsigned id, const char* label)
{
	assert(ctx);
	assert(label);

//	attach_datapoint(ctx, &newp);
}

void graph_log_discover_rep(struct graph_context* ctx, 
	unsigned id, const char* label)
{
}

void graph_log_tlv_in(struct graph_context* ctx, unsigned id, 
	const char* label, unsigned tag, unsigned len)
{
	assert(ctx);

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}
}

void graph_log_tlv_out(struct graph_context* ctx, unsigned id, 
	const char* label, unsigned tag, unsigned len)
{
	assert(ctx);

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}
}

void graph_log_conn_error(struct graph_context* ctx, 
	unsigned id, const char* label)
{
	assert(ctx);

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}
}

void graph_log_message(struct graph_context* ctx, unsigned long timestamp, 
	size_t pkg_sz, int stateid, bool oob)
{
	assert(ctx);

	if (GRAPH_SERVER(ctx->mode)){
	}
	else {
	}
}
