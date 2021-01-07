#ifndef HAWK_H
#define HAWK_H

// TODO(fntlnz): decide what to do with versioning here
#define HAWK_VERSION_CODE 0x000001
#define HAWK_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | (z))
#define HAWK_AT_LEAST_VERSION(x, y, z) \
	(HAWK_VERSION_CODE >= HAWK_VERSION_BITS(x, y, z))

// Rules update follows a transactional pattern
// - begin the transaction with `hawk_rules_begin_cb`
// - add rules as many times you want with `hawk_rules_insert_cb`
// - commit the rules with `hawk_rules_commit_cb`
// - if anything went wrong, you can rollback with hawk_rules_rollback_cb
typedef void (*hawk_rules_begin_cb)();
typedef void (*hawk_rules_insert_cb)(char* rules_content);
typedef void (*hawk_rules_commit_cb)();
typedef void (*hawk_rules_rollback_cb)();

typedef struct
{
	void (*hawk_init)(void);
	void (*hawk_destroy)(void);
	void (*hawk_watch_rules)(hawk_rules_begin_cb, hawk_rules_insert_cb, hawk_rules_commit_cb, hawk_rules_rollback_cb);
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
