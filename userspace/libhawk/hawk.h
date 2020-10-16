#ifndef HAWK_H
#define HAWK_H
extern void hawk_init();
extern void hawk_destroy();
typedef void (*hawk_watch_rules_cb)(char *rules_content);
extern void hawk_watch_rules(hawk_watch_rules_cb cb);
#endif //HAWK_H
