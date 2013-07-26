--
-- AWB List View
-- Specialized window subclass to handle longer multi-column lists
-- With clickable headers, sorting etc.
-- 
local function awblist_scrollbar(self)
	if (self.capacity > self.total) then
		if (self.scroll) then
			self.scroll = false;
			hide_image(self.dir[self.icon_bardir].fill.vid);
			self.dir[self.icon_bardir].oldsz = self.dir[self.icon_bardir].bsize;
			self.dir[self.icon_bardir].bsize = 0;
			self:list_resize(self.w, self.h);
		end

		return;

	elseif (self.capacity < self.total and self.scroll == false) then
		self.scroll = true;
		show_image(self.dir[self.icon_bardir].fill.vid);
		self.dir[self.icon_bardir].bsize = self.dir[self.icon_bardir].oldsz;
		self:list_resize(self.w, self.h);
	end

	local prop = image_surface_properties(self.dir[self.icon_bardir].fill.vid);
	local stepsz = prop.height / self.total;
	
	resize_image(self.scrollcaret, self.dir[self.icon_bardir].size - 2,
		stepsz * self.capacity);
	move_image(self.scrollcaret, 1, stepsz * (self.ofs - 1)); 
end

function awblist_resize(self, neww, newh)
	self:list_resize(neww, newh);
	local props = image_surface_properties(self.canvas.vid);
	self.capacity = math.ceil(props.height / (self.lineh + self.linespace)) + 1;

-- only redraw if we've grown (keep image when shrinking), some parts of
-- this function is really expensive and high-resolution mice etc. do
-- emitt lots of resize events when drag-resizing
	if (props.height - self.lasth > (self.lineh + self.linespace)) then
		self.lasth  = props.height;
		self.restbl, self.total = self:datasel(self.ofs, self.capacity);	
		
		for i, v in ipairs(self.listtemp) do
			delete_image(v);
		end
		self.listtemp = {};

-- Render each column separately, using a clipping anchor 
		local xofs = 0;
		for ind, col in ipairs(self.cols) do
			local clip = null_surface(math.floor(props.width * col), props.height);
	
			link_image(clip, self.canvas.vid);
			show_image(clip);
			image_mask_set(clip, MASK_UNPICKABLE);
			image_inherit_order(clip, true);
			image_tracetag(clip, "listview.col(" .. tostring(ind) .. ").clip");
			xofs = xofs + math.floor(props.width * col);

-- concat the subselected column lines, force-add headers to the top
			local rendtbl = {};
			for i, v in ipairs(self.restbl) do
				table.insert(rendtbl, v.cols[ind]);
			end
			local colv, lines = self.renderfn(table.concat(rendtbl, [[\n\r]]));
	
			self.line_heights = lines;

			link_image(colv, clip);
			show_image(colv);
			move_image(colv, 0, self.linespace * 0.5);
			image_tracetag(colv, "listview.col(" .. tostring(ind) ..").column");
			image_inherit_order(colv, true);
			order_image(colv, 2);
			image_mask_set(colv, MASK_UNPICKABLE);
			image_clip_on(colv, CLIP_SHALLOW);
			table.insert(self.listtemp, clip);  
		end

-- hilighted striped bars to make it easier to distinguish between items
		if (self.bglines) then
			for i,v in ipairs(self.bglines) do
				delete_image(v);
			end
			
			self.bglines = {};

			local yofs = 0;
			for i=2,#self.line_heights do
				if (i % 2 == 0) then
					a = color_surface(props.width, 
						self.line_heights[i] - self.line_heights[i - 1], 
						self.rowhicol[1], self.rowhicol[2], self.rowhicol[3]);
					move_image(a, 0, self.line_heights[i]);
					link_image(a, self.canvas.vid);
					show_image(a);
					image_inherit_order(a, true);
					image_clip_on(a);
					image_tracetag(a, "listview.stripbg");
					image_mask_set(a, MASK_UNPICKABLE);
					table.insert(self.bglines, a);
				end
			end
		end

	end

-- always update clipping anchors
	local xofs = 0;
	for i, col in ipairs(self.cols) do
		local clipw = math.floor(props.width * col);
		resize_image(self.listtemp[i], clipw, props.height);
		move_image(self.listtemp[i], xofs, 0);
		xofs = xofs + clipw;
	end

	if (self.bglines) then
		for i,v in ipairs(self.bglines) do
			resize_image(v, props.width, image_surface_properties(v).height);
		end
	end

	resize_image(self.cursor, props.width, self.lineh + self.linespace);
	awblist_scrollbar(self);
end

function awbicon_liney(self, yv)
	if (self.line_heights) then

-- find the matching pair and pick the closest one
		for i=1,#self.line_heights-1 do
			local dy1 = self.line_heights[i];
			local dy2 = self.line_heights[i+1];

			if (dy1 <= yv and dy2 >= yv) then
				return dy1, i;
			end
		end

		return self.line_heights[#self.line_heights], #self.line_heights;
	end

	return 0, nil;
end

local function clampofs(self)
	if (self.ofs < 1) then
		self.ofs = 1;
	elseif (self.ofs + self.capacity >= self.total) then
		self.ofs = self.total - self.capacity;
	end
end

local function scrollup(self, n)
	self.ofs = self.ofs - math.abs(n);
	clampofs(self);
	self.lasth = 0;
	self:resize(self.w, self.h);
end

local function scrolldown(self, n)
	self.ofs = self.ofs + math.abs(n);
	clampofs(self);
	self.lasth = 0;
	self:resize(self.w, self.h);
end

local function caretdrop(self)
	self.caret_dy = 0;
end

local function caretdrag(self, vid, dx, dy)
	local prop = image_surface_properties(
		self.wnd.dir[self.wnd.icon_bardir].fill.vid);

	local stepsz = prop.height / self.wnd.total;
	self.caret_dy = self.caret_dy + dy;

	if(self.caret_dy < -5) then
		local steps = math.floor(-1 * self.caret_dy / 5);
		self.caret_dy = self.caret_dy + steps * 5;
		scrollup(self.wnd, steps); 

	elseif (self.caret_dy > 5) then
		local steps = math.floor(self.caret_dy / 5);
		self.caret_dy = self.caret_dy - steps * 5;
		scrolldown(self.wnd, steps);
	end
end

local function scrollclick(self, vid, x, y)
	local props = image_surface_resolve_properties(self.caret);

	self.wnd.ofs = (y < props.y) and (self.wnd.ofs - self.wnd.capacity) or
		(self.wnd.ofs + self.wnd.capacity);

	clampofs(self.wnd);

	self.wnd.lasth = 0;
	self.wnd:resize(self.wnd.w, self.wnd.h);
end

function awbwnd_listview(pwin, lineh, linespace, colcfg, datasel_fun, 
	render_fun,scrollbar_icn, scrollcaret_icn, cursor_icn, bardir,
	options)

	if (bardir == nil) then
		bardir = "r";
	end

-- overridable options
	pwin.cell_w   = cell_w;
	pwin.cell_h   = cell_h;
	pwin.rowhicol = {0, 0, 0};
	pwin.bglines  = {};

-- apply user options
	if (options) then
		for k,v in pairs(options) do
			pwin[k] = v;
		end
	end

-- protect against namespace collisions
	pwin.lasth      = 0;
	pwin.lineh      = lineh;
	pwin.linespace  = linespace;
	pwin.ofs        = 1;
	pwin.listtemp   = {};
	pwin.datasel    = datasel_fun;
	pwin.renderfn   = render_fun;
	pwin.cols       = colcfg;
	pwin.scrollup   = stepup;
	pwin.scrolldown = stepdown;

	pwin.icon_bardir = bardir;
	pwin.scrollcaret = scrollcaret_icn;
	pwin.scroll      = true;
	pwin.line_y      = awbicon_liney;

	image_tracetag(scrollbar_icn,   "awbwnd_listview.scrollbar");
	image_tracetag(scrollcaret_icn, "awbwnd_listview.scrollcaret_icn");

--
-- build scrollbar 
--
	local bartbl = pwin.dir[bardir];
	local newicn = bartbl:add_icon("fill", scrollbar_icn);

	link_image(scrollcaret_icn, newicn.vid);
	image_inherit_order(scrollcaret_icn, true);
	order_image(newicn.vid, 3);
	order_image(scrollcaret_icn, 3);
	show_image(scrollcaret_icn);
	resize_image(scrollcaret_icn,
		pwin.dir["t"].size - 2, pwin.dir["t"].size - 2); 
	image_clip_on(scrollcaret_icn, CLIP_SHALLOW);

	pwin.list_resize = pwin.resize;
	pwin.resize = awblist_resize;

	link_image(cursor_icn, pwin.canvas.vid);
	image_inherit_order(cursor_icn, true);
	order_image(cursor_icn, 1);
	blend_image(cursor_icn, 0.8);
	pwin.cursor = cursor_icn;
	image_clip_on(cursor_icn, CLIP_SHALLOW);
	image_mask_set(cursor_icn, MASK_UNPICKABLE);

	local carretmh = {
		wnd  = pwin,
		caret_dy = 0,
		drag = caretdrag,
		drop = caretdrop,
		own  = function(self,vid) return scrollcaret_icn == vid; end
	};

	local scrollmh = {
		caret = pwin.scrollcaret,
		wnd   = pwin, 
		own   = function(self, vid) return newicn.vid == vid; end,
		click = scrollclick; 
	};

	mouse_addlistener(scrollmh, {"click"});
	mouse_addlistener(carretmh, {"drag", "drop"});

-- find cursor ..
	local mhand = {};
	mhand.dblclick = function(self, vid, x, y)
		local props = image_surface_resolve_properties(pwin.canvas.vid);
		local yofs, linen = pwin:line_y(y - props.y);

		if (linen and pwin.restbl[linen]) then
			pwin.restbl[linen]:trigger();
		end
	end

	mhand.motion = function(self, vid, x, y)
		local props = image_surface_resolve_properties(pwin.canvas.vid);
		local yofs, linen = pwin:line_y(y - props.y);
		move_image(pwin.cursor, 0, yofs); 
	end

	mhand.own = function(self, vid)
		return pwin.canvas.vid == vid;
	end

	mouse_addlistener(mhand, {"dblclick", "motion"});

	pwin.on_destroy = function()
		mouse_droplistener(scrollmh);
		mouse_droplistener(carretmh);
		mouse_droplistener(mhand);
	end
--
-- selected cursor management linked to canvas
-- 
	pwin:resize(pwin.w, pwin.h);
	return pwin;
end