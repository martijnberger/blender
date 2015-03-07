
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

fprintf(cxml, "  <max_diffuse_bounce val=\"%d\" />\n", get_int(cscene, "diffuse_bounces"));
fprintf(cxml, "  <max_glossy_bounce val=\"%d\" />\n", get_int(cscene, "glossy_bounces"));
fprintf(cxml, "  <max_transmission_bounce val=\"%d\" />\n", get_int(cscene, "transmission_bounces"));
fprintf(cxml, "  <max_volume_bounce val=\"%d\" />\n", get_int(cscene, "volume_bounces"));

fprintf(cxml, "  <transparent_max_bounce val=\"%d\" />\n", get_int(cscene, "transparent_max_bounces"));
fprintf(cxml, "  <transparent_min_bounce val=\"%d\" />\n", get_int(cscene, "transparent_min_bounces"));
fprintf(cxml, "  <transparent_shadows val=\"%d\" />\n", get_boolean(cscene, "use_transparent_shadows"));

fprintf(cxml, "  <volume_max_steps val=\"%d\" />\n", get_int(cscene, "volume_max_steps"));
fprintf(cxml, "  <volume_step_size val=\"%f\" />\n", (double)get_float(cscene, "volume_step_size"));

fprintf(cxml, "  <caustics_reflective val=\"%d\" />\n", get_boolean(cscene, "caustics_reflective"));
fprintf(cxml, "  <caustics_refractive val=\"%d\" />\n", get_boolean(cscene, "caustics_refractive"));

fprintf(cxml, "  <filter_glossy val=\"%f\" />\n", (double)get_float(cscene, "blur_glossy"));
fprintf(cxml, "  <seed val=\"%d\" />\n", get_int(cscene, "seed"));


fprintf(cxml, "  <min_bounces val=\"%d\" />\n", get_int(cscene, "min_bounces"));
fprintf(cxml, "  <method val=\"%d\" />\n", get_enum(cscene, "progressive"));

fprintf(cxml, "  <sample_all_lights_direct val=\"%d\" />\n", get_boolean(cscene, "sample_all_lights_direct"));
fprintf(cxml, "  <sample_all_lights_indirect val=\"%d\" />\n", get_boolean(cscene, "sample_all_lights_indirect"));

fprintf(cxml, "  <diffuse_samples val=\"%d\" />\n", get_int(cscene, "diffuse_samples"));
fprintf(cxml, "  <glossy_samples val=\"%d\" />\n", get_int(cscene, "glossy_samples"));
fprintf(cxml, "  <transmission_samples val=\"%d\" />\n", get_int(cscene, "transmission_samples"));
fprintf(cxml, "  <ao_samples val=\"%d\" />\n", get_int(cscene, "ao_samples"));
fprintf(cxml, "  <mesh_light_samples val=\"%d\" />\n", get_int(cscene, "mesh_light_samples"));
fprintf(cxml, "  <subsurface_samples val=\"%d\" />\n", get_int(cscene, "subsurface_samples"));
fprintf(cxml, "  <volume_samples val=\"%d\" />\n", get_int(cscene, "volume_samples"));

fprintf(cxml, "</scene>\n");

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
