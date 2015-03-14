/*
 * Copyright 2011-2013 Blender Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __BLENDER_EXPORT_H__
#define __BLENDER_EXPORT_H__

#include "stdio.h"
#include "RNA_types.h"
#include "MEM_guardedalloc.h" // both needed for  RNA_blender_cpp
#include "malloc.h"           // both needed for  RNA_blender_cpp
#include "RNA_blender_cpp.h"

CCL_NAMESPACE_BEGIN

class CyclesSceneExporter {
public:
	CyclesSceneExporter(PointerRNA &dataptr, PointerRNA &sceneptr,const char *path);
	~CyclesSceneExporter(){}

	void export_scene(){
		fprintf(stderr, "saving cycles file to %s\n", path);
		cxml = fopen(path, "w");
		//export_integrator();
		export_camera();

		export_dummy();
		fclose(cxml);
	}

	void export_integrator();
	void export_camera();

	void export_dummy();

private:
	PointerRNA data;
	BL::Scene scene;
	const char *path;
	FILE *cxml;
};


CCL_NAMESPACE_END

#endif /* __BLENDER_EXPORT_H__ */
