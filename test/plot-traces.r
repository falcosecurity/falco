#
# Copyright (C) 2018 Draios Inc.
#
# This file is part of falco.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

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
