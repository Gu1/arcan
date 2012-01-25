#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <openctm.h>
#include <SDL/SDL_opengl.h>
#include <SDL/SDL.h>

#include "arcan_math.h"
#include "arcan_general.h"
#include "arcan_event.h"
#include "arcan_video.h"
#include "arcan_videoint.h"

//#include "arcan_3dbase_synth.h"

// #define M_PI 3.14159265358979323846

extern struct arcan_video_display arcan_video_display;

/* since the 3d is planned as a secondary feature, rather than the primary one,
 * things work slightly different as each 3d object is essentially coupled to 1..n of 2D video objects */

enum virttype{
	virttype_camera = 0,
	virttype_pointlight,
	virttype_dirlight,
	virttype_reflection,
	virttype_shadow
};

struct virtobj {
/* for RTT - type scenarios */
	GLuint rendertarget;
	vector position;
    unsigned int updateticks;
	bool dynamic;
	
/* ignored by pointlight */
    quat rotation;
	orientation direction;
    float projmatr[16];
	
	enum virttype type;
/* linked list arranged, sorted high-to-low
 * based on virttype */
	struct virtobj* next;
};

typedef struct virtobj virtobj;

typedef struct {
    unsigned ntxcos;
    float* txcos;
    arcan_vobj_id vid;
} texture_set;

typedef struct {
	virtobj* perspectives;
} arcan_3dscene;

typedef struct {
	orientation direction;
    point position;
    scalefactor scale;
    
/* Geometry */
    struct{
        unsigned nverts;
        float* verts;
        unsigned nindices;
        unsigned* indices;
        /* nnormals == nverts */
        float* normals;
    } geometry;

    unsigned char nsets;
    texture_set* textures;
    
/* Frustum planes */
	float frustum[6][4];
	
/* AA-BB */
    vector bbmin;
    vector bbmax;
    
/* position, opacity etc. are inherited from parent */	
	struct {
        bool debug_vis;
		bool recv_shdw;
		bool cast_shdw;
		bool cast_refl;
/* used for skyboxes etc. should be rendered before anything else
 * without depth buffer writes enabled */
        bool infinite;
	} flags;

	arcan_vobject* parent;
} arcan_3dmodel;

static arcan_3dscene current_scene = {0};

/*
 * CAMERA Control, generation and manipulation
 */

static virtobj* find_camera(unsigned camtag)
{
	virtobj* vobj = current_scene.perspectives;
	unsigned ofs = 0;
	
	while (vobj){
		if (vobj->type == virttype_camera && camtag == ofs){
			return vobj;			
		} else ofs++;
		vobj = vobj->next;
	}
	return NULL;
}

void arcan_3d_movecamera(unsigned camtag, float px, float py, float pz, unsigned tv)
{
	virtobj* vobj = find_camera(camtag);
	if (vobj){
		vobj->position.x = px;
		vobj->position.y = py;
		vobj->position.z = pz;
	}
}

static vector camera_forward(vector position, quat orientation)
{
	vector res;
	/* get quaternion inverse */
	/* forward = quat * vec3(0,0,-1) */
    return res;
}

void arcan_3d_orientcamera(unsigned camtag, float roll, float pitch, float yaw, unsigned tv)
{
	unsigned ofs = 0;
	virtobj* vobj = find_camera(camtag);
	if (vobj){
		vobj->rotation = build_quat_euler(roll, pitch, yaw);
	}
}

void arcan_3d_camera_sidestep(unsigned camtag, float factor)
{
	virtobj* vobj = find_camera(camtag);
	if (vobj){
		vector viewv = camera_forward(vobj->position, vobj->rotation);
		vector cpv = crossp_vector(viewv, build_vect(0.0, 1.0, 0.0));
		vobj->position.x += cpv.x * factor;
		vobj->position.y += cpv.y * factor; 
	}
}

void arcan_3d_camera_forward(unsigned camtag, float fact)
{
	virtobj* vobj = find_camera(camtag);
	if (vobj){
		vector viewv = camera_forward(vobj->position, vobj->rotation);
		vobj->position.x += viewv.x;
		vobj->position.y += viewv.y;
		vobj->position.z += viewv.z;
	}
}

/*
 * MODEL Control, generawtion and manipulation
 */

/* take advantage of the "vid as frame" feature to allow multiple video sources to be
 * associated with the texture- coordinaet sets definedin the model source */
arcan_errc arcan_3d_modelmaterial(arcan_vobj_id model, unsigned frameno, unsigned txslot)
{
	arcan_vobject* vobj = arcan_video_getobject(model);
	arcan_errc rv = ARCAN_ERRC_NO_SUCH_OBJECT;
	
	if (vobj){
	}
	
	return rv;
}

static void freemodel(arcan_3dmodel* src)
{
	if (src){
		
	}
}

/*
 * Render-loops, Pass control, Initialization
 */


static void rendermodel(arcan_3dmodel* src, surface_properties props)
{
	glPushMatrix();
	glDisableClientState(GL_TEXTURE_COORD_ARRAY);
    /* if there's texture coordsets and an associated vobj,
     * enable texture coord array, normal array etc. */
	if (src->flags.infinite){
        glLoadIdentity();
		glDepthMask(GL_FALSE);
		glEnable(GL_DEPTH_TEST);
	}

	if (1 || src->flags.debug_vis){
//        wireframe_box(src->bbmin.x, src->bbmin.y, src->bbmin.z, src->bbmax.x, src->bbmax.y, src->bbmax.z);
    }

    glColor4f(1.0, 1.0, 1.0, props.opa);
	glTranslatef(props.position.x, props.position.y, props.position.z);
    glMultMatrixf(src->direction.matr);
    glVertexPointer(3, GL_FLOAT, 0, src->geometry.verts);
    glDrawArrays(GL_POINTS, 0, src->geometry.nverts);

	if (src->flags.infinite){
		glDepthMask(GL_TRUE);
		glEnable(GL_DEPTH_TEST);
	}
	
    glPopMatrix();
}

/* the current model uses the associated scaling / blending
 * of the associated vid and applies it uniformly */ 
static const int8_t ffunc_3d(enum arcan_ffunc_cmd cmd, uint8_t* buf, uint32_t s_buf, uint16_t width, uint16_t height, uint8_t bpp, unsigned mode, vfunc_state state)
{
	if (state.tag == ARCAN_TAG_3DOBJ && state.ptr){
		switch (cmd){
			case ffunc_tick:
			break;
			
			case ffunc_render_direct:
/*				rendermodel( (arcan_3dmodel*) state.ptr, *(surface_properties*)buf ); */
			break;
				
			case ffunc_destroy:
				freemodel( (arcan_3dmodel*) state.ptr );
			break;
			
			default:
			break;
		}
	}
	
	return 0;
}

/* Simple one- off rendering pass, no exotic sorting, culling structures, projections or other */
static void process_scene_normal(arcan_vobject_litem* cell, float lerp)
{
	glEnableClientState(GL_VERTEX_ARRAY);
    
	arcan_vobject_litem* current = cell;
	while (current){
		if (current->elem->order >= 0) break;
		surface_properties dprops;
 		arcan_resolve_vidprop(cell->elem, lerp, &dprops);
		
		rendermodel((arcan_3dmodel*) current->elem->state.ptr, dprops);

		current = current->next;
	}

	glDisableClientState(GL_VERTEX_ARRAY);
}

/* Chained to the video-pass in arcan_video, stop at the first non-negative order value */
arcan_vobject_litem* arcan_refresh_3d(arcan_vobject_litem* cell, float frag)
{
	virtobj* base = current_scene.perspectives;

	while(base){
		float matr[16];
		
		switch(base->type){
			case virttype_camera :
            glMatrixMode(GL_PROJECTION);
                glLoadMatrixf(base->projmatr);

                glMatrixMode(GL_MODELVIEW);
					glLoadIdentity();
                    glMultMatrixf(base->direction.matr);
                    glTranslatef(base->position.x, base->position.y, base->position.z);
                
                    process_scene_normal(cell, frag);

/* curious about deferred shading and forward shadow mapping, thus likely the first "hightech" renderpath */
			case virttype_dirlight   : break;
			case virttype_pointlight : break;
/* camera with inverted Y, add a stencil at clipping plane and (optionally) render to texture (for water) */
			case virttype_reflection : break;
/* depends on caster source, treat pointlights separately, for infinite dirlights use ortographic projection, else
 * have a caster-specific perspective projection */
			case virttype_shadow : break;
		}

		base = base->next;
	}
	
	return cell;
}


static void minmax_verts(vector* minp, vector* maxp, const float* verts, unsigned nverts)
{
    vector empty = {0};
    *minp = *maxp = empty;
    
    for (unsigned i = 0; i < nverts * 3; i += 3){
        vector a = {.x = verts[i], .y = verts[i+1], .z = verts[i+2]};
        if (a.x < minp->x) minp->x = a.x;        
        if (a.y < minp->y) minp->y = a.y;
        if (a.z < minp->z) minp->z = a.z;
        if (a.x > maxp->x) maxp->x = a.x;        
        if (a.y > maxp->y) maxp->y = a.y;
        if (a.z > maxp->z) maxp->z = a.z;            
    }
}


arcan_vobj_id arcan_3d_buildplane(float minx, float minz, float maxx, float maxz, float y){
    return ARCAN_OK;
}

arcan_vobj_id arcan_3d_loadmodel(const char* resource)
{
	arcan_vobj_id rv = ARCAN_EID;
	arcan_3dmodel* newmodel = NULL;
	arcan_vobject* vobj = NULL;
	
	CTMcontext ctx = ctmNewContext(CTM_IMPORT);
	ctmLoad(ctx, resource);

	if (ctmGetError(ctx) == CTM_NONE){
		CTMuint n_verts, n_tris, n_uvs;
		const CTMfloat* verts;
/* create container object and proxy vid */
		newmodel = (arcan_3dmodel*) calloc(sizeof(arcan_3dmodel), 1);
		vfunc_state state = {.tag = ARCAN_TAG_3DOBJ, .ptr = newmodel};

		img_cons empty = {0};
		rv = arcan_video_addfobject(ffunc_3d, state, empty, 1);

		if (rv == ARCAN_EID)
			goto error;

		arcan_vobject* obj = arcan_video_getobject(rv);
		newmodel->parent = obj;
        update_view(&newmodel->direction, 0, 0, 0);

        newmodel->geometry.nverts = ctmGetInteger(ctx, CTM_VERTEX_COUNT);
        newmodel->geometry.nindices = ctmGetInteger(ctx, CTM_TRIANGLE_COUNT) * 3;
//        unsigned uvmaps = ctmGetInteger(ctx, CTM_
		n_verts = ctmGetInteger(ctx, CTM_VERTEX_COUNT);
		verts   = ctmGetFloatArray(ctx, CTM_VERTICES);

/* normalize model to a -1..1 scale and copy */
        minmax_verts(&newmodel->bbmin, &newmodel->bbmax, verts, n_verts);
        unsigned indsize = newmodel->geometry.nindices * sizeof(unsigned);
        unsigned vrtsize = n_verts * 3 * sizeof(float);

        float dx = newmodel->bbmax.x - newmodel->bbmin.x;
        float dy = newmodel->bbmax.y - newmodel->bbmin.y;
        float dz = newmodel->bbmax.z - newmodel->bbmin.z;
        float sfx = 2.0 / dx, sfy = 2.0 / dy, sfz = 2.0 / dz;
        
        for (unsigned i = 0; i < n_verts * 3; i += 3){
            newmodel->geometry.verts[i]   = verts[i]   * sfx;
            newmodel->geometry.verts[i+1] = verts[i+1] * sfy;
            newmodel->geometry.verts[i+2] = verts[i+2] * sfz;
        }

/* verbatimely copy indices and normals */
        newmodel->geometry.verts = (float*) malloc(vrtsize);
        newmodel->geometry.indices = (unsigned*) malloc(indsize);
        
        memcpy(newmodel->geometry.indices, ctmGetIntegerArray(ctx, CTM_INDICES), indsize);
        memcpy(newmodel->geometry.normals, ctmGetFloatArray(ctx, CTM_NORMALS), vrtsize);

/* generate a container for each texture set (or cap to limit) */
        
        ctmFreeContext(ctx);
        		
		return rv;
	}

error:
	ctmFreeContext(ctx);
	if (vobj) /* if a feed object was set up, this will still call that part */
		arcan_video_deleteobject(rv);
	else if (newmodel)
		free(newmodel);
	
	arcan_warning("arcan_3d_loadmodel(), couldn't load 3dmodel (%s)\n", resource);
	return ARCAN_EID;
}

void arcan_3d_setdefaults()
{
	current_scene.perspectives = calloc( sizeof(virtobj), 1);
	virtobj* cam = current_scene.perspectives;
	cam->dynamic = true;

    build_projection_matrix(0.1, 100.0, (float)arcan_video_display.width / (float) arcan_video_display.height, 45.0, cam->projmatr);
    
    cam->rendertarget = 0;
    cam->type = virttype_camera;
	cam->position = build_vect(0, 0, 0); /* ret -x, y, +z */
	update_view(&cam->direction, 0, 0, 0);
}

