#ifndef HAWK_H
#define HAWK_H
extern void hawk_init();
extern void hawk_destroy();

typedef void* hawk_engine;
typedef void (*hawk_watch_rules_cb)(char* rules_content, hawk_engine* engine);
extern void hawk_watch_rules(hawk_watch_rules_cb cb, hawk_engine* engine);

#endif //HAWK_H
