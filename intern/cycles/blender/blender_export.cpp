
#include "blender_export.h"

#include "MEM_guardedalloc.h" // both needed for  RNA_blender_cpp
#include "malloc.h"           // both needed for  RNA_blender_cpp
#include "RNA_blender_cpp.h"

#include "blender_util.h"

/* macros for importing */
#define RAD2DEGF(_rad) ((_rad) * (float)(180.0 / M_PI))
#define DEG2RADF(_deg) ((_deg) * (float)(M_PI / 180.0))

CCL_NAMESPACE_BEGIN

CyclesSceneExporter::CyclesSceneExporter(PointerRNA &dataptr, PointerRNA &sceneptr,const char *path):
	data(dataptr), scene(sceneptr), path(path) {
}



void CyclesSceneExporter::export_integrator()
{
PointerRNA cscene = RNA_pointer_get(&scene.ptr, "cycles");

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

BL::Object camera = scene.camera();

BL::RenderSettings render_settings = scene.render();

Transform bmat = get_transform(camera.matrix_world());
Transform mat = bmat * transform_scale(1.0f, 1.0f, -1.0f);

fprintf(cxml, "<!-- Camera -->\n");

fprintf(cxml, "<transform matrix=\"");
fprintf(cxml, "%f %f %f %f  ", (double)mat.x.x, (double)mat.y.x, (double)mat.z.x, (double)mat.w.x);
fprintf(cxml, "%f %f %f %f  ", (double)mat.x.y, (double)mat.y.y, (double)mat.z.y, (double)mat.w.y);
fprintf(cxml, "%f %f %f %f  ", (double)mat.x.z, (double)mat.y.z, (double)mat.z.z, (double)mat.w.z);
fprintf(cxml, "%f %f %f %f\"", (double)mat.x.w, (double)mat.y.w, (double)mat.z.w, (double)mat.w.w);
fprintf(cxml, " >\n");


fprintf(cxml, "<camera ");

int percentage;

percentage = render_settings.resolution_percentage();

fprintf(cxml, "width=\"%d\" ", (render_settings.resolution_x() * percentage) / 100 );
fprintf(cxml, "height=\"%d\" ", (render_settings.resolution_y() * percentage) / 100 );

BL::ID b_ob_data = camera.data();

if(b_ob_data.is_a(&RNA_Camera)) {
	BL::Camera b_camera(b_ob_data);
	PointerRNA ccamera = RNA_pointer_get(&b_camera.ptr, "cycles");

	fprintf(cxml, "fov=\"%f\" ", (double)RAD2DEGF(b_camera.angle()));
	fprintf(cxml, "nearclip=\"%f\" ", (double)b_camera.clip_start());
	fprintf(cxml, "farclip=\"%f\" ", (double)b_camera.clip_end());

	switch(b_camera.type())
	{
		case BL::Camera::type_ORTHO:
			fprintf(cxml, "type=\"orthographic\" ");
			break;
		case BL::Camera::type_PANO:\
			fprintf(cxml, "type=\"panorama\" ");
			switch(RNA_enum_get(&ccamera, "panorama_type"))
			{
				case 1:
					fprintf(cxml, "panorama_type=\"fisheye_equidistant\" ");
					break;
				case 2:
					fprintf(cxml, "panorama_type=\"fisheye_equisolid\" ");
					break;
				case 0:
				default:
					fprintf(cxml, "panorama_type=\"equirectangular\" ");
					break;
			}
			break;
		case BL::Camera::type_PERSP:
		default:
			fprintf(cxml, "type=\"perspective\" ");
			break;
	}

}


//xml_read_float(&cam->aperturesize, node, "aperturesize"); // 0.5*focallength/fstop
//xml_read_float(&cam->focaldistance, node, "focaldistance");
//xml_read_float(&cam->shuttertime, node, "shuttertime");
//xml_read_float(&cam->aperture_ratio, node, "aperture_ratio");

//xml_read_float(&cam->fisheye_fov, node, "fisheye_fov");
//xml_read_float(&cam->fisheye_lens, node, "fisheye_lens");

//xml_read_float(&cam->sensorwidth, node, "sensorwidth");
//xml_read_float(&cam->sensorheight, node, "sensorheight");

//cam->matrix = state.tfm;

fprintf(cxml, " />\n");

fprintf(cxml, "\n</transform>\n");



}

void CyclesSceneExporter::export_dummy(){
fprintf(cxml,
		"<!-- Background Shader -->\n"
		"<background>\n"
			"<background name=\"bg\" strength=\"2.0\" color=\"0.2, 0.2, 0.2\" />\n"
			"<connect from=\"bg background\" to=\"output surface\" />\n"
		"</background>\n"
		"\n"
		"<!-- Cube Shader -->"
		"<shader name=\"cube\">"
		"	<checker_texture name=\"tex\" scale=\"2.0\" color1=\"0.8, 0.8, 0.8\" color2=\"1.0, 0.2, 0.2\" />"
		"	<diffuse_bsdf name=\"cube_closure\" roughness=\"0.0\" />"
		"	<connect from=\"tex color\" to=\"cube_closure color\" />"
		"	<connect from=\"cube_closure bsdf\" to=\"output surface\" />"
		"</shader>"

		"<!-- Cube Object -->"
		"<state interpolation=\"smooth\" shader=\"cube\">"
		"    <mesh P=\"1.000000 1.000000 -1.000000"
		"             1.000000 -1.000000 -1.000000"
		"             -1.000000 -1.000000 -1.000000"
		"             -1.000000 1.000000 -1.000000"
		"             1.000000 0.999999 1.000000"
		"             0.999999 -1.000001 1.000000"
		"             -1.000000 -1.000000 1.000000"
		"             -1.000000 1.000000 1.000000\""
		"         nverts=\"4 4 4 4 4 4 \""
		"         verts=\"0 1 2 3"
		"                4 7 6 5"
		"                0 4 5 1"
		"                1 5 6 2"
		"                2 6 7 3"
		"                4 0 3 7\"/>"
		"</state>");


}

CCL_NAMESPACE_END
