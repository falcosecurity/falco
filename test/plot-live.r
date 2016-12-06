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
metric = "cpu"

GetoptLong(
    "results=s", "Path to results file",
    "benchmark=s", "Benchmark from results file to graph",
    "variant=s@", "Variant(s) to include in graph. Can be specified multiple times",
    "output=s", "Output graph file",
    "metric=s", "Metric to graph. Can be one of (cpu|drops)"
)

if (metric == "cpu") {
    data_metric="cpu_usage"
    yaxis_label="CPU Usage (%)"
    title="Falco/Sysdig/Multimatch CPU Usage: %s"
} else if (metric == "drops") {
    data_metric="drop_pct"
    yaxis_label="Event Drops (%)"
    title="Falco/Sysdig/Multimatch Event Drops: %s"
}

res <- fromJSON(results, flatten=TRUE)

res2 = res[res$benchmark == benchmark & res$variant %in% variant,]

plot <- ggplot(data=res2, aes(x=sample, y=get(data_metric), group=variant, colour=variant)) +
    geom_line() +
    ylab(yaxis_label) +
    xlab("Time") +
    ggtitle(sprintf(title, benchmark))
    theme(legend.position=c(.2, .88));

print(paste("Writing graph to", output, sep=" "))
ggsave(file=output)




