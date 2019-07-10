std = "min"
cache = true
include_files = {
    "userspace/falco/lua/*.lua",
    "userspace/engine/lua/*.lua",
    "userspace/engine/lua/lyaml/*.lua",
    "*.luacheckrc"
}
exclude_files = {"build"}
