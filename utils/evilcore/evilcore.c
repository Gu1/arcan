#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#include "libretro.h"

/* basic core skeleton just patched from the test- core 
 * used for fuzzing / setup up different levels 
 * of terrible test-cases for manipulating the arcan
 * frameserver behavior */

/*
 * button1 => toggle resize/harassment on/off
 * button2 => toggle _run timing jitter
 * button3 => toggle crazy input
 * button4 => toggle audio_overflow
*/

static uint32_t* outbuf;

/* every new frame is a new resize,
 * cycle color each resize, increment / wraparound dimensions */
static bool mass_resize;

/* add random sleeps in each _run */
static bool timing_jitter;

/* input polls with values way out of bounds */
static bool crazy_input;

/* emitt larger audio buffers than expected */
static bool audio_overflow;

void retro_init(void)
{
	outbuf = malloc(1920 * 1080 * 4);	
}

void retro_deinit(void)
{
}

unsigned retro_api_version(void)
{
   return RETRO_API_VERSION;
}

void retro_set_controller_port_device(unsigned port, unsigned device)
{
   (void)port;
   (void)device;
}

void retro_get_system_info(struct retro_system_info *info)
{
   memset(info, 0, sizeof(*info));
   info->library_name     = "EvilCore";
   info->library_version  = "v1";
   info->need_fullpath    = false;
   info->valid_extensions = NULL; // Anything is fine, we don't care.
}

void retro_get_system_av_info(struct retro_system_av_info *info)
{
   info->timing = (struct retro_system_timing) {
      .fps = 60.0,
      .sample_rate = 30000.0,
   };

   info->geometry = (struct retro_game_geometry) {
      .base_width   = 320,
      .base_height  = 240,
      .max_width    = 1920,
      .max_height   = 1080,
      .aspect_ratio = 1920.0 / 1080.0
   };
}

static retro_video_refresh_t video_cb;
static retro_audio_sample_t audio_cb;
static retro_audio_sample_batch_t audio_batch_cb;
static retro_environment_t environ_cb;
static retro_input_poll_t input_poll_cb;
static retro_input_state_t input_state_cb;

void retro_set_environment(retro_environment_t cb)
{
   environ_cb = cb;

   static const struct retro_variable vars[] = {
      { "test_opt0", "Test option #0; false|true" },
      { "test_opt1", "Test option #1; 0" },
      { "test_opt2", "Test option #2; 0|1|foo|3" },
      { NULL, NULL },
   };

   cb(RETRO_ENVIRONMENT_SET_VARIABLES, (void*)vars);

   bool no_rom = true;
   cb(RETRO_ENVIRONMENT_SET_SUPPORT_NO_GAME, &no_rom);

   if (!cb(RETRO_ENVIRONMENT_GET_LOG_INTERFACE, &logging))
      logging.log = fallback_log;
}

void retro_set_audio_sample(retro_audio_sample_t cb)
{
   audio_cb = cb;
}

void retro_set_audio_sample_batch(retro_audio_sample_batch_t cb)
{
   audio_batch_cb = cb;
}

void retro_set_input_poll(retro_input_poll_t cb)
{
   input_poll_cb = cb;
}

void retro_set_input_state(retro_input_state_t cb)
{
   input_state_cb = cb;
}

void retro_set_video_refresh(retro_video_refresh_t cb)
{
   video_cb = cb;
}

static unsigned x_coord;
static unsigned y_coord;
static unsigned phase;
static int mouse_rel_x;
static int mouse_rel_y;

void retro_reset(void)
{
   x_coord = 0;
   y_coord = 0;
}

static void update_input(void)
{
   int dir_x = 0;
   int dir_y = 0;

   input_poll_cb();
   if (input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_UP))
      dir_y--;
   if (input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_DOWN))
      dir_y++;
   if (input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_LEFT))
      dir_x--;
   if (input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_RIGHT))
      dir_x++;

   if (input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RETURN))
      logging.log(RETRO_LOG_INFO, "Return key is pressed!\n");

   if (input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_x))
      logging.log(RETRO_LOG_INFO, "x key is pressed!\n");

   int16_t mouse_x = input_state_cb(0, RETRO_DEVICE_MOUSE, 0, RETRO_DEVICE_ID_MOUSE_X);
   int16_t mouse_y = input_state_cb(0, RETRO_DEVICE_MOUSE, 0, RETRO_DEVICE_ID_MOUSE_Y);
   bool mouse_l    = input_state_cb(0, RETRO_DEVICE_MOUSE, 0, RETRO_DEVICE_ID_MOUSE_LEFT);
   bool mouse_r    = input_state_cb(0, RETRO_DEVICE_MOUSE, 0, RETRO_DEVICE_ID_MOUSE_RIGHT);
   if (mouse_x)
      logging.log(RETRO_LOG_INFO, "Mouse X: %d\n", mouse_x);
   if (mouse_y)
      logging.log(RETRO_LOG_INFO, "Mouse Y: %d\n", mouse_y);
   if (mouse_l)
      logging.log(RETRO_LOG_INFO, "Mouse L pressed.\n");
   if (mouse_r)
      logging.log(RETRO_LOG_INFO, "Mouse R pressed.\n");

   mouse_rel_x += mouse_x;
   mouse_rel_y += mouse_y;
   if (mouse_rel_x >= 310)
      mouse_rel_x = 309;
   else if (mouse_rel_x < 10)
      mouse_rel_x = 10;
   if (mouse_rel_y >= 230)
      mouse_rel_y = 229;
   else if (mouse_rel_y < 10)
      mouse_rel_y = 10;

   bool pointer_pressed = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_PRESSED);
   int16_t pointer_x = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_X);
   int16_t pointer_y = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_Y);
   if (pointer_pressed)
      logging.log(RETRO_LOG_INFO, "Pointer: (%6d, %6d).\n", pointer_x, pointer_y);

   dir_x += input_state_cb(0, RETRO_DEVICE_ANALOG, RETRO_DEVICE_INDEX_ANALOG_LEFT, RETRO_DEVICE_ID_ANALOG_X) / 5000;
   dir_y += input_state_cb(0, RETRO_DEVICE_ANALOG, RETRO_DEVICE_INDEX_ANALOG_LEFT, RETRO_DEVICE_ID_ANALOG_Y) / 5000;
   dir_x += input_state_cb(0, RETRO_DEVICE_ANALOG, RETRO_DEVICE_INDEX_ANALOG_RIGHT, RETRO_DEVICE_ID_ANALOG_X) / 5000;
   dir_y += input_state_cb(0, RETRO_DEVICE_ANALOG, RETRO_DEVICE_INDEX_ANALOG_RIGHT, RETRO_DEVICE_ID_ANALOG_Y) / 5000;

   x_coord = (x_coord + dir_x) & 31;
   y_coord = (y_coord + dir_y) & 31;

   if (rumble.set_rumble_state)
   {
      static bool old_start;
      static bool old_select;
      uint16_t strength_strong = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_R2) ? 0x4000 : 0xffff;
      uint16_t strength_weak = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_L2) ? 0x4000 : 0xffff;
      bool start = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_START);
      bool select = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_SELECT);
      if (old_start != start)
         logging.log(RETRO_LOG_INFO, "Strong rumble: %s.\n", start ? "ON": "OFF");
      rumble.set_rumble_state(0, RETRO_RUMBLE_STRONG, start * strength_strong);

      if (old_select != select)
         logging.log(RETRO_LOG_INFO, "Weak rumble: %s.\n", select ? "ON": "OFF");
      rumble.set_rumble_state(0, RETRO_RUMBLE_WEAK, select * strength_weak);

      old_start = start;
      old_select = select;
   }
}

static void render_checkered(void)
{
   uint16_t color_r = 31 << 11;
   uint16_t color_g = 63 <<  5;

   uint16_t *line = frame_buf;
   for (unsigned y = 0; y < 240; y++, line += 320)
   {
      unsigned index_y = ((y - y_coord) >> 4) & 1;
      for (unsigned x = 0; x < 320; x++)
      {
         unsigned index_x = ((x - x_coord) >> 4) & 1;
         line[x] = (index_y ^ index_x) ? color_r : color_g; 
      }
   }

   for (unsigned y = mouse_rel_y - 5; y <= mouse_rel_y + 5; y++)
      for (unsigned x = mouse_rel_x - 5; x <= mouse_rel_x + 5; x++)
         frame_buf[y * 320 + x] = 0x1f;

   video_cb(frame_buf, 320, 240, 320 << 1);
}

static void render_audio(void)
{
   for (unsigned i = 0; i < 30000 / 60; i++, phase++)
   {
      int16_t val = 0x800 * sinf(2.0f * M_PI * phase * 300.0f / 30000.0f);
      audio_cb(val, val);
   }

   phase %= 100;
}

static void check_variables(void)
{
   struct retro_variable var = {0};
   var.key = "test_opt0";
   if (environ_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var) && var.value)
      logging.log(RETRO_LOG_INFO, "Key -> Val: %s -> %s.\n", var.key, var.value);
   var.key = "test_opt1";
   if (environ_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var) && var.value)
      logging.log(RETRO_LOG_INFO, "Key -> Val: %s -> %s.\n", var.key, var.value);
   var.key = "test_opt2";
   if (environ_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var) && var.value)
      logging.log(RETRO_LOG_INFO, "Key -> Val: %s -> %s.\n", var.key, var.value);
}

void retro_run(void)
{
   update_input();
   render_checkered();
   render_audio();

   bool updated = false;
   if (environ_cb(RETRO_ENVIRONMENT_GET_VARIABLE_UPDATE, &updated) && updated)
      check_variables();
}

static void keyboard_cb(bool down, unsigned keycode,
      uint32_t character, uint16_t mod)
{
   logging.log(RETRO_LOG_INFO, "Down: %s, Code: %d, Char: %u, Mod: %u.\n",
         down ? "yes" : "no", keycode, character, mod);
}

bool retro_load_game(const struct retro_game_info *info)
{
   struct retro_input_descriptor desc[] = {
      { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_LEFT,  "Left" },
      { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_UP,    "Up" },
      { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_DOWN,  "Down" },
      { 0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_RIGHT, "Right" },
      { 0 },
   };

   environ_cb(RETRO_ENVIRONMENT_SET_INPUT_DESCRIPTORS, desc);

   enum retro_pixel_format fmt = RETRO_PIXEL_FORMAT_RGB565;
   if (!environ_cb(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &fmt))
   {
      logging.log(RETRO_LOG_INFO, "RGB565 is not supported.\n");
      return false;
   }

   struct retro_keyboard_callback cb = { keyboard_cb };
   environ_cb(RETRO_ENVIRONMENT_SET_KEYBOARD_CALLBACK, &cb);
   if (environ_cb(RETRO_ENVIRONMENT_GET_RUMBLE_INTERFACE, &rumble))
      logging.log(RETRO_LOG_INFO, "Rumble environment supported.\n");
   else
      logging.log(RETRO_LOG_INFO, "Rumble environment not supported.\n");

   check_variables();

   (void)info;
   return true;
}

void retro_unload_game(void)
{}

unsigned retro_get_region(void)
{
   return RETRO_REGION_NTSC;
}

bool retro_load_game_special(unsigned type, const struct retro_game_info *info, size_t num)
{
   (void)type;
   (void)info;
   (void)num;
   return false;
}

size_t retro_serialize_size(void)
{
   return 2;
}

bool retro_serialize(void *data_, size_t size)
{
   if (size < 2)
      return false;

   uint8_t *data = data_;
   data[0] = x_coord;
   data[1] = y_coord;
   return true;
}

bool retro_unserialize(const void *data_, size_t size)
{
   if (size < 2)
      return false;

   const uint8_t *data = data_;
   x_coord = data[0] & 31;
   y_coord = data[1] & 31;
   return true;
}

void *retro_get_memory_data(unsigned id)
{
   (void)id;
   return NULL;
}

size_t retro_get_memory_size(unsigned id)
{
   (void)id;
   return 0;
}

void retro_cheat_reset(void)
{}

void retro_cheat_set(unsigned index, bool enabled, const char *code)
{
   (void)index;
   (void)enabled;
   (void)code;
}

