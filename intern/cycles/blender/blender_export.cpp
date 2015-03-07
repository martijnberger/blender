
#include "blender_export.h"

#include "MEM_guardedalloc.h" // both needed for  RNA_blender_cpp
#include "malloc.h"           // both needed for  RNA_blender_cpp
#include "RNA_blender_cpp.h"

#include "blender_util.h"



CCL_NAMESPACE_BEGIN

CyclesSceneExporter::CyclesSceneExporter(PointerRNA &dataptr, PointerRNA &sceneptr,const char *path):
	data(dataptr), scene(sceneptr), path(path) {}



void CyclesSceneExporter::export_integrator()
{
PointerRNA cscene = RNA_pointer_get(&scene, "cycles");



fprintf(cxml, "<scene experimental=\"%d\">\n", (RNA_enum_get(&cscene, "feature_set") != 0));
fprintf(cxml, "  <min_bounces val=\"%d\" />\n", get_int(cscene, "min_bounces"));
fprintf(cxml, "  <max_bounces val=\"%d\" />\n", get_int(cscene, "max_bounces"));
fprintf(cxml, "</scene>\n");

/*
integrator->max_diffuse_bounce = get_int(cscene, "diffuse_bounces");
integrator->max_glossy_bounce = get_int(cscene, "glossy_bounces");
integrator->max_transmission_bounce = get_int(cscene, "transmission_bounces");
integrator->max_volume_bounce = get_int(cscene, "volume_bounces");

integrator->transparent_max_bounce = get_int(cscene, "transparent_max_bounces");
integrator->transparent_min_bounce = get_int(cscene, "transparent_min_bounces");
integrator->transparent_shadows = get_boolean(cscene, "use_transparent_shadows");

integrator->volume_max_steps = get_int(cscene, "volume_max_steps");
integrator->volume_step_size = get_float(cscene, "volume_step_size");

integrator->caustics_reflective = get_boolean(cscene, "caustics_reflective");
integrator->caustics_refractive = get_boolean(cscene, "caustics_refractive");
integrator->filter_glossy = get_float(cscene, "blur_glossy");

integrator->seed = get_int(cscene, "seed");
*/
}


void CyclesSceneExporter::export_camera(){


//  bcam->type = CAMERA_PERSPECTIVE;
//	bcam->zoom = 1.0f;
//	bcam->pixelaspect = make_float2(1.0f, 1.0f);
//	bcam->sensor_width = 32.0f;
//	bcam->sensor_height = 18.0f;
//	bcam->sensor_fit = BlenderCamera::AUTO;
//	bcam->shuttertime = 1.0f;
//	bcam->border.right = 1.0f;
//	bcam->border.top = 1.0f;
//	bcam->pano_viewplane.right = 1.0f;
//	bcam->pano_viewplane.top = 1.0f;
//	bcam->viewport_camera_border.right = 1.0f;
//	bcam->viewport_camera_border.top = 1.0f;

//	/* render resolution */
//	bcam->full_width = render_resolution_x(b_render);
//	bcam->full_height = render_resolution_y(b_render);


}

CCL_NAMESPACE_END
