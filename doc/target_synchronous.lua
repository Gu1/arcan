-- target_synchronous
-- @short: Enforce synchronous transfers 
-- @inargs: dstvid
-- @outargs: 
-- @longdescr: This function is potentially dangerous;
-- there is a tradeoff between responsiveness and reliable readbacks
-- for recordtargets in that if the frameserver isn't ready to receive
-- when a readback from the GPU has been completed, the frame will be discarded.
-- This asynchronous-discard behavior can be altered on a single frameserver
-- by calling target_synchronous. This changes synchronization behavior in that
-- processing will not continue until the frameserver is ready to receive.
-- This means that an untrusted frameserver implementation can potentially 
-- livelock the main engine and will introduce additional jitter between
-- rendered frames.  If this is performed on a frameserver in decode mode however,
-- the "discard if PTS is too old" behavior will be disabled and the 
-- last presented timestamp will be set to the frame that would've otherwise
-- been discared.
-- @group: targetcontrol 
-- @cfunction: targetsynchronous
-- @flags: expert
-- @related:

