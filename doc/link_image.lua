-- link_image
-- @short: Bind the state-space of one video object to that of another. 
-- @inargs: src, newparent
-- @longdescr: Full video objects (not instances and other restricted types)
-- can have their properties be dependent of the state of another. This function
-- associates *src* with *newparent*, which by default means that opacity, position
-- orientation becomes relative. The exact properties can be tuned with the _mask class
-- of functions.
-- @group: image 
-- @cfunction: arcan_lua_linkimage
function main()
#ifdef MAIN
	a = fill_surface(64, 64, 255, 0, 0);
	b = fill_surface(32, 32, 0, 255, 0);
	link_image(b, a);
	show_image(b);
	blend_image(a, 1.0, 50);
	move_image(a, VRESW, VRESH, 100);
	rotate_image(a, 100, 100);
	expire_image(a, 100);
#endif
end
