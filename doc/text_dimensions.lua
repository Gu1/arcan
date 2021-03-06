-- text_dimensions
-- @short: Calculate the output volume of a format string.
-- @inargs: message, *vspacing*, *tspacing*
-- @outargs: width, height
-- @note: The main difference between this function and render_text is
-- that, although intermediate allocations are still needed, no output
-- video object will be setup.
-- @group: image 
-- @cfunction: arcan_lua_strsize
-- @exampletheme: fonttest
-- @related: render_text

