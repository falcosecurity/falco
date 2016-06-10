require(jsonlite)
library(ggplot2)
library(GetoptLong)

initial.options <- commandArgs(trailingOnly = FALSE)
file.arg.name <- "--file="
script.name <- sub(file.arg.name, "", initial.options[grep(file.arg.name, initial.options)])
script.basename <- dirname(script.name)

if (substr(script.basename, 1, 1) != '/') {
    script.basename = paste(getwd(), script.basename, sep='/')
}

results = paste(script.basename, "results.json", sep='/')
output = "./output.png"

GetoptLong(
    "results=s", "Path to results file",
    "benchmark=s", "Benchmark from results file to graph",
    "variant=s@", "Variant(s) to include in graph. Can be specified multiple times",
    "output=s", "Output graph file"
)

res <- fromJSON(results, flatten=TRUE)

res2 = res[res$benchmark == benchmark & res$variant %in% variant,]

plot <- ggplot(data=res2, aes(x=sample, y=cpu_usage, group=variant, colour=variant)) +
    geom_line() +
    ylab("CPU Usage (%)") +
    xlab("Time") +
    ggtitle(sprintf("Falco/Sysdig CPU Usage: %s", benchmark))
    theme(legend.position=c(.2, .88));

print(paste("Writing graph to", output, sep=" "))
ggsave(file=output)




