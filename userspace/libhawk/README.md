# Libhawk

Libhawk is a plugin system that can be used to enrich Falco
functionalities via external, user-defined libraries.

## Glossary:

- library: a bundle (e.g: an ELF shared library) containing one or more plugins
- plugin: an hawk plugin. Libraries can register one or more plugins using the `HAWK_REGISTER_PLUGIN` macro
- plugin function: a specific function inside the plugin definition of each plugin. `hawk_init`, `hawk_destroy`

## Plugin definitions and lifecycle

Plugins are all loaded when Falco starts.
Falco provides a default plugin for the main functionalities.

### hawk_init
On start, the `hawk_init` function of every plugin is called.
You can use that function to create any resource you might need
for your plugin's lifecycle.

### hawk_destroy

When Falco is stopped, the `hawk_destroy` p

### hawk_watch_rules

TODO: explain that only one at time can be done and how to configure. This can be
explained once we have the plugin configuration code done.

<a name="plugin-loading"></a>
## Plugin loading

TODO, describe how to dynamically load a plugin.
This can be explained once this feature is developed.

## Plugin configuration

TODO
This can be explained once this feature is developed.

## Plugin example

A plugin can define one or more definitions.

Here's an example of plugin that is registered and defines
`hawk_init`, `hawk_destroy` and `hawk_watch_rules`

```c
#include "hawk.h"

void hawk_init() { printf("hawk_example init!\n"); }

void hawk_destroy() {printf("hawk example destroy\n");}

void hawk_watch_rules(hawk_watch_rules_cb cb, hawk_engine *engine) {
  printf("loading rules\n");
  cb("", engine); // todo: pass the rules here, this is empty
}

hawk_plugin_definition plugin_definition = {
    .hawk_init = &hawk_init,
    .hawk_destroy = &hawk_destroy,
    .hawk_watch_rules = &hawk_watch_rules,
};

HAWK_REGISTER_PLUGIN(hawk_example_c, plugin_definition)
```

To compile the plugin, save it in a file `plugin.c` and then:

```bash
FALCO=/source/falco
gcc -o libhawk.so -fPIC -shared -I$FALCO/userspace/libhawk plugin.c
```

Remember to change the `FALCO` variable to point to where you have the Falco sources.

This should produce shared object called `libhawk.so`, you can use that to load the plugin in Falco.
See the [Plugin loading](#plugin-loading) section.
