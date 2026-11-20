#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"

// this is the WORST fucking library i used

static
char* slurp (const char* path)
{
	FILE* f = fopen(path, "rb");

	if (f==NULL)
		return (NULL);
	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* buf = malloc((size_t)n+1);
	if (buf==NULL) {
		fclose(f);
		return (NULL);
	}
	if (fread(buf, 1, (size_t)n, f)!=(size_t)n) {
		free(buf);
		fclose(f);
		return (NULL);
	}
	buf[n] = '\0';
	fclose(f);
	return (buf);
}


static
struct json_value_s * lookup (struct json_object_s * obj, const char* name)
{
	for (struct json_object_element_s * e=obj->start; e!=NULL; e=e->next)
		if (strlen(name)==e->name->string_size&&
		    strncmp(name, e->name->string, e->name->string_size)==0)
			return (e->value);
	return (NULL);
}

// write to config.h line by line
static
void emit_str (struct json_object_s * obj, const char* name, const char* macro)
{
	struct json_value_s * v = lookup(obj, name);

	if (v==NULL)
		return;
	struct json_string_s * s = json_value_as_string(v);
	if (s!=NULL)
		printf("#define %s \"%.*s\"\n", macro, (int)s->string_size,
		    s->string);
}

static
void emit_all_bools (struct json_object_s* obj)
{
	struct json_object_element_s* el;

	for (el = obj->start; el!=NULL; el = el->next) {
		if (!json_value_is_true(el->value))
			continue;
		char macro[128];
		snprintf(macro, sizeof(macro), "CFG_");
		for (size_t i = 0; i<el->name->string_size; i++) {
			char p = el->name->string[i];
			char s[2] = { (p>='a' && p<='z') ? p-32 : p, '\0' };
			strncat(macro, s, 1);
		}
		printf("#define %s 1\n", macro);
	}
}

int main (int argc, char** argv)
{
	if (argc != 2) return (1);

	char* buf = slurp(argv[1]);

	if (!buf) return (1);

	struct json_value_s * root = json_parse(buf, strlen(buf));

	if (!root) {
		free(buf);
		return (1);
	}

	struct json_object_s * obj = json_value_as_object(root);
	if (!obj) {
		free(root);
		free(buf);
		return (1);
	}

	emit_all_bools(obj);
	emit_str(obj, "helper_path", "CFG_HELPER_PATH");

	struct json_value_s * v = lookup(obj, "paths");
	// if (!v)
	struct json_object_s * paths = v ? json_value_as_object(v) : NULL;
	if (paths!=NULL) {
		static const char* names[] = {
			"root_file", "rc_dir", "etc", "kdir", "boot", "slash"
		};
		static const char* macros[] = {
			"CFG_ROOT_FILE", "CFG_RC_DIR", "CFG_ETC",
			"CFG_kdir", "CFG_BOOT", "CFG_SLASH"
		};
		for (int i=0; i<7; i++)
			emit_str(paths, names[i], macros[i]);
	}


	free(root);
	free(buf);
	return (0);
}
