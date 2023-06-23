# On Host Anomaly Detection Framework

## Motivation

**A Wind of Change for Threat Detection**

Feel that light breeze? That is the continued advancement of cloud native security blowing steady. But despite our progress, threat actors are outpacing our innovation constantly finding new ways to thwart and tornado past our achievements — rule-based detections focus on what we *think* attackers will do, not on what they *are* doing and generate enough alerts to bury security analysts in a sandstorm of poor signal-to-noise. Can this dynamic be blown back to shift the information asymmetry in favor of defenders?

This framework lays the foundation on how to create high-value, kernel signals that are difficult to bypass  - but not in the traditional way. Advanced data analytics is an emerging crosswind that enables us to soar past attackers by detecting deviations in current behavior from past behavior. 


## Benefits to the Ecosystem

Advanced data analytics enables us to combine the intricacies of the Linux kernel with on-host anomaly detection in cloud native and cloud environments to determine patterns of past behavior in running applications. By detecting deviations in current behavior from past behavior, we can shift the focus away from relying solely on signatures and rule matching to catch attackers.

Threat detection in open source and more importantly cloud native is constrained by the amount of rules we can write and the signatures we know to look for in our environments. But these have the same problem: they assume our attackers don't change what they're doing. The reality is attackers are not limited to the ways, means, and methods they employ to expose, manipulate, or even destroy our data, systems, and organizations. 

This framework leverages an attacker's mindset applied to detection engineering: observing and learning about our targets to create more rich and actionable alerts so we can catch them earlier and more often - regardless if it's behavior we know about, or something we haven't seen yet.

## Elevator Pitch

When Falco processes events in userspace, its rules engine filters the events while the parsers simultaneously update and maintain an internal state. This state includes a process tree cache that enhances Falco alerts by providing contextual information derived from previous events. The goal is to enhance the "state engine" even further and provide an option for monitoring the behavior of applications over time.

To achieve this, end users define a "behavior profile" in the configuration by combining existing event fields such as process name, file descriptor (fd), executable path, parent lineage, cmdline, and others. During event parsing on the hot path, Falco compresses and stores this information in a "filter" - an efficient probabilistic data structure that optimizes space, time, robustness and accuracy. As time progresses, Falco provides more accurate estimates of application behavior counts and identifies events as rare or heavy hitters. Instead of analyzing the original event stream, you can write Falco rules based on pre-filtered data. 

This approach enables a novel threat detection framework that incorporates the concept of abnormal application behavior derived and observed in a data-driven fashion. It complements the operator's expertise and extends capabilities similar to our current practices. The new capability draws inspiration from big data stream and database query optimizations, ensuring that Falco maintains a streamlined real-time one-pass stream with zero allocations.

Similar to Falco rules, the analysis of events may require multiple behavior profiles of different dimensions based on sets of events. These profiles can either vote in parallel or in a cascading fashion, a common practice in established algorithms. This is just the beginning and and paves the way for more sophisticated approaches, such as running Falco in a DAST-like capacity to build a pre-state pattern file on a workload with test data and soften the cold-start via distributing it to production.


## Initial Scope

The initial scope is focused on cloud-native environments rather than bare-metal infrastructure due to the inherent properties of modern cloud orchestration systems like Kubernetes. Containerized deployments offer a natural semantic distinction and attribution of processes belonging to individual applications. Consequently, it becomes possible to allocate separate behavior filters per container and perform clearing and purging of filters. This effectively addresses concerns regarding shared space and potential lossy compression.

Furthermore, The Falco Project will provide good initial thresholds for adopters, including callouts for known issues in thresholds based on environment and business case. One important consideration is the identification of SRE anti-patterns. Another consideration is to provide *very clear* guidance to adopters for setting and configuring parameters, including recommended minimums. Additionally, guidance should be provided on indicators to look for in order to determine if adjustments need to be made and in which direction, particularly when defining application behavior profiles.


## Challenges and Considerations

First, The Falco Project is committed to continuously ensuring access to the most accurate data possible for on-host threat detection. As an example, ongoing efforts involve expanding kernel signal logging, such as verifying if an execve call pertains to a file descriptor existing exclusively in memory or improving the efficient and reliable resolution of symlinks for file opens and executable paths. The proposed anomaly detection framework operates under the assumption of having the *correct* data, thereby complementing the ongoing efforts to expand logging coverage and improve its quality. In summary, the primary focus of the framework is to derive increased value from the existing *right* data that is currently available.

There is a common perception that attacks on running cloud applications, as well as their indicators of compromise, are typically rare when the appropriate data or combination of signals is considered. While this holds true, there are inherent challenges in applying this concept of rarity to robust data analytics approaches. This is not only due to the diverse range of attacks and attack vectors but also because of their nature. An attacker may introduce a new malicious binary (which is comparatively easier to detect using traditional rules and high-value kernel signals) after gaining initial access. Alternatively, they may exploit existing binaries, shell built-ins, and employ obfuscation techniques to "live off the land." The Turing completeness of the latter scenario, in particular, leads to an infinite number of attack possibilities.

However, what poses even more challenges in anomaly detection is not the rarity of attacks, but rather the difficulty of identifying the right signals and their appropriate combinations for robust analytics. This challenge becomes particularly evident when considering the natural fluctuations in application behavior over time and the occurrence of ad-hoc legitimate debugging activities. Such fluctuations can arise from various factors, including routine deployment updates. Moreover, certain applications may produce random file names or execute arbitrary executable paths as part of their regular operations, adding to the challenge of anomaly detection. This is compounded by the inherent "cold start" issue when initially observing an application. In such cases, the algorithms must demonstrate flexibility and robustness by recognizing and encoding consistent patterns, similar to how humans can identify the sameness by examining combinations of file names, command arguments, parent process lineage, and other attributes. Furthermore, factors like data inconsistency and the diverse forms of data representations (comprising a mix of numeric data and strings with varying meanings) further complicate the task.

We believe it is important to incorporate operator heuristics or domain knowledge into the algorithm's definition of rarity. For example, while current algorithms are capable of generating human faces, they used to frequently produce images with different eye colors. However, if we were to inform the machine that humans typically have matching eye colors, it could easily correct this discrepancy. This highlights the role of the security engineer as a guiding hand to the algorithms, both in terms of handling noise tolerance and choosing the appropriate data to be ingested into the algorithm. This is crucial as machines are currently limited in their ability to draw meaningful observations from limited data and constrained memory. In summary, this is where the fusion of data-driven anomaly detection and rules matching will come into play.

Lastly, the value proposition of conducting real-time anomaly analysis on the host lies in the unique options it offers, which cannot be achieved through alternative methods. On the host, we can observe anomalies based on all relevant and observed kernel events. In contrast, sending a large volume of kernel events to a centralized system would be impractical, resulting in significant costs for data pipeline management and data lake compute expenses.


## High-Level Technical Design


This document provides a high-level proposal with limited technical details. Upon acceptance, two additional proposals will be opened, one for the libs repository and another for the plugins repository, to ensure alignment on the precise code implementation changes.


*Probabilistic Data Structures (libs)*

One option for implementing the probabilistic filter is by utilizing a robust two-dimensional probabilistic data structure known as the Count-Min sketch. This data structure is widely employed in distributed stream processing frameworks such as Apache Spark, Apache Storm, Apache Flink, and others, as well as databases like Redis and PostgreSQL.

Technical details and implications are extensively covered in numerous research papers and textbooks. Therefore, here are some key points to consider in order to make informed choices:

- Each entity of interest, whether it be a container or the underlying host processes treated as a distinct entity, should ideally be allocated its own sketch. This allocation helps address concerns regarding shared space and potential implications of lossy compression. 
- The challenges posed by both hard and soft collisions can be mitigated by using multiple non-cryptographic hash functions, which has been mathematically proven to be effective.
- To ensure accuracy and minimize estimation errors, it is crucial to conduct due diligence by de-biasing the data (e.g., using Count-Min Sketch with Conservative Updates) and/or considering a logarithmic scale to handle data skew in kernel event data. The logarithmic scale could be well-suited for threat detection, targeting low-frequency or long-tail items relevant to various attacks.
- The sketchy data structure guarantees that counts are never underestimated, providing a one-sided error guarantee. However, there is a potential for overestimating counts, although this can be mitigated through mathematical adjustments. Nonetheless, adopters still need to define a tolerance level specific to their use case. This enables them to determine what qualifies as rare or noteworthy. This issue is closely interconnected with the challenges of data encoding and inconsistency that we *will* encounter.
- ... and numerous other aspects that will be discussed in subsequent detailed implementation proposals.



*Plumbing and Interface (falco, plugins)*

A significant amount of work will be dedicated to addressing the necessary plumbing required to support the new framework and integrate it with the existing rules filtering and plugin mechanisms. This integration aims to provide a user-friendly interface that allows users to easily configure and utilize the opt-in framework for different use cases. The interface will enable end users to access and adjust the dimensions (m and p) of the sketches, as well as other tuning parameters, bounds and settings, and define the behavior profile(s).


## What this Framework is Not

- This framework is not intended to function as an event aggregator or enhancer, such as netflow data. Its purpose is solely to act as an anomaly filter for individual events, leveraging the existing sinsp state and current rules engine.
- The development of this framework will not be swayed by overly specific use cases that limit its broader adoption and coverage.
- While it may not offer flawless attack threat detection from the beginning, it serves as an initial step towards comprehensive event logging and analysis, capturing all events that exhibit any form of new or changing behavior we observe. Therefore, initially, the greatest value lies in combining it with regular Falco rules based on the anomaly-filtered event stream.


## Why now?

Over the past several Falco releases, significant improvements have been made in terms of stability, configurability, and capabilities. Now is an opportune time to enhance the already proven capabilities of threat detection. In case you haven't noticed, advanced data analytics is quite the big deal these days, and we can leverage robust established algorithms used in real production settings across various industries. The novelty lies in addressing the specific data encoding challenges unique to the field of cybersecurity.


## Proposed Timelines

- Falco 0.36: Design details and scaffolding
- Falco 0.37: Experimental release
- Falco 0.38: First release


## Resources / References


- [Count-Min sketch](https://towardsdatascience.com/big-data-with-sketchy-structures-part-1-the-count-min-sketch-b73fb3a33e2a) blog post
- [Probabilistic Data Structures and Algorithms
for Big Data Applications](https://www.gakhov.com/books/pdsa.html) book
- [Count-Min-Log sketch](https://arxiv.org/pdf/1502.04885.pdf) paper
- [Count-Min Sketch with Conservative Updates](https://hal.science/hal-03613957/document#:~:text=Count%2DMin%20Sketch%20with%20Conservative%20Updates%20(CMS%2DCU),because%20of%20its%20inherent%20difficulty) paper




