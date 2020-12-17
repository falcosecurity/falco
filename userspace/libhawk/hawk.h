#ifndef HAWK_H
#define HAWK_H

// TODO(fntlnz): decide what to do with versioning here
#define HAWK_VERSION_CODE 0x000001
#define HAWK_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | (z))
#define HAWK_AT_LEAST_VERSION(x, y, z) \
	(HAWK_VERSION_CODE >= HAWK_VERSION_BITS(x, y, z))

typedef void (*hawk_watch_rules_cb)(char* rules_content);

typedef struct
{
	void (*hawk_init)(void);
	void (*hawk_destroy)(void);
	void (*hawk_watch_rules)(hawk_watch_rules_cb);
} hawk_plugin_definition;

typedef void(register_plugin_cb)(const char*, hawk_plugin_definition);

typedef struct
{
	register_plugin_cb* register_plugin;
} hawk_plugin_registry;

extern hawk_plugin_registry plugin_registry;

#define HAWK_REGISTER_PLUGIN(name, definition)                           \
	void name##_hawk_plugin_init(void) __attribute__((constructor)); \
	void name##_hawk_plugin_init(void)                               \
	{                                                                \
		plugin_registry.register_plugin(#name, definition);      \
	}

#endif //HAWK_H
