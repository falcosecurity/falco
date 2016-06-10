require(jsonlite)
library(ggplot2)
library(reshape)

res <- fromJSON("/home/mstemm/results.txt", flatten=TRUE)

plot <- ggplot(data=res, aes(x=config, y=elapsed.real)) +
    geom_bar(stat = "summary", fun.y = "mean") +
    coord_flip() +
    facet_grid(shortfile ~ .) +
    ylab("Wall Clock Time (sec)") +
    xlab("Trace File/Program")


ggsave(file="/mnt/sf_mstemm/res-real.png")

plot <- ggplot(data=res, aes(x=config, y=elapsed.user)) +
    geom_bar(stat = "summary", fun.y = "mean") +
    coord_flip() +
    facet_grid(shortfile ~ .) +
    ylab("User Time (sec)") +
    xlab("Trace File/Program")


ggsave(file="/mnt/sf_mstemm/res-user.png")

res2 <- melt(res, id.vars = c("config", "shortfile"), measure.vars = c("elapsed.sys", "elapsed.user"))
plot <- ggplot(data=res2, aes(x=config, y=value, fill=variable, order=variable)) +
     geom_bar(stat = "summary", fun.y = "mean") +
     coord_flip() +
     facet_grid(shortfile ~ .) +
     ylab("User/System Time (sec)") +
     xlab("Trace File/Program")

ggsave(file="/mnt/sf_mstemm/res-sys-user.png")
