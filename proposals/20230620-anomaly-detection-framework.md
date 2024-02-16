# On Host Anomaly Detection Framework - New `anomalydetection` Plugin

## Motivation

**A Wind of Change for Threat Detection**

Feel that light breeze? That is the continued advancement of cloud native security blowing steady. But despite our progress, threat actors are outpacing our innovation constantly finding new ways to thwart and tornado past our achievements — rule-based detections focus on what we *think* attackers will do, not on what they *are* doing and generate enough alerts to bury security analysts in a sandstorm of poor signal-to-noise. Can this dynamic be blown back to shift the information asymmetry in favor of defenders?

This framework lays the foundation on how to create high-value, kernel signals that are difficult to bypass - but not in the traditional way. Advanced data analytics is an emerging crosswind that enables us to soar past attackers by detecting deviations in current behavior from past behavior. 

## Benefits to the Ecosystem

Advanced data analytics enables us to combine the intricacies of the Linux kernel with on-host anomaly detection in cloud native and cloud environments to determine patterns of past behavior in running applications. By detecting deviations in current behavior from past behavior, we can shift the focus away from relying solely on signatures and rule matching to catch attackers.

Threat detection in open source and more importantly cloud native is constrained by the amount of rules we can write and the signatures we know to look for in our environments. But these have the same problem: they assume our attackers don't change what they're doing. The reality is attackers are not limited to the ways, means, and methods they employ to expose, manipulate, or even destroy our data, systems, and organizations. 

This framework leverages an attacker's mindset applied to detection engineering: observing and learning about our targets to create more rich and actionable alerts so we can catch them earlier and more often - regardless if it's behavior we know about, or something we haven't seen yet.

## Elevator Pitch

When Falco processes events in userspace, its rules engine filters the events while the parsers simultaneously update and maintain an internal state. This state includes a process tree cache that enhances Falco alerts by providing contextual information derived from previous events. The goal is to enhance the "state engine" even further and provide an option for monitoring the behavior of applications over time.

To achieve this, end users define a "behavior profile" in the configuration by combining existing event fields such as process name, file descriptor (fd), executable path, parent lineage, cmdline, and others. During event parsing on the hot path, Falco compresses and stores this information in a "filter" - an efficient probabilistic data structure that optimizes space, time, robustness and accuracy. As time progresses, Falco provides more accurate estimates of application behavior counts and identifies events as rare or heavy hitters. Instead of analyzing the original event stream, you can write Falco rules based on pre-filtered data. 

This approach introduces a novel threat detection framework that analyzes abnormal application behavior in real-time, derived and observed in a data-driven fashion, without requiring operator reconfiguration of Falco. It complements the operator's expertise and extends capabilities similar to our current practices. The new capability draws inspiration from big data stream and database query optimizations, ensuring that Falco maintains a streamlined real-time one-pass stream with zero allocations.

Similar to Falco rules, the analysis of events may require multiple behavior profiles of different dimensions based on sets of events. These profiles can either vote in parallel or in a cascading fashion, a common practice in established algorithms. This is just the beginning and and paves the way for more sophisticated approaches, such as running Falco in a DAST-like capacity to build a pre-state pattern file on a workload with test data and soften the cold-start via distributing it to production.

## Challenges and Considerations

First, The Falco Project is committed to continuously ensuring access to the most accurate data possible for on-host threat detection. As an example, recent efforts involved expanding kernel signal logging, such as verifying if an execve call is linked to a file descriptor existing exclusively in memory or improving the efficient and reliable resolution of symlinks for executable paths. Therefore, the proposed anomaly detection framework operates under the assumption of having the *correct* data, thereby complementing the ongoing efforts to expand logging coverage and improve its quality. In summary, the primary focus of the framework is to derive increased value from the existing *right* data that is currently available.

There is a common perception that attacks on running cloud applications, as well as their indicators of compromise, are typically rare when the appropriate data or combination of signals is considered. While this holds true, there are inherent challenges in applying this concept of rarity to robust data analytics approaches. 

On the one hand, this is due to the diverse range of attacks and attack vectors. An attacker may introduce a new malicious binary (which is comparatively easier to detect using traditional rules and high-value kernel signals) after gaining initial access. Alternatively, they may exploit existing binaries, shell built-ins, and employ obfuscation techniques to "live off the land". The Turing completeness of the latter scenario, in particular, leads to an infinite number of attack possibilities.

However, what poses even more challenges in anomaly detection lies not necessarily in the nature of attacks but rather in identifying the right signals and their appropriate combinations for robust analytics to distinguish between normal and anomalous behavior. This challenge becomes particularly evident when considering the natural fluctuations in application behavior over time and the occurrence of ad-hoc legitimate debugging activities. Such fluctuations can arise from various factors, including routine deployment updates. Moreover, certain applications may produce random file names or execute arbitrary executable paths as part of their regular operations, adding to the challenge of anomaly detection. This is compounded by the inherent "cold start" issue when initially observing an application. In such cases, the algorithms must demonstrate flexibility and robustness by recognizing and encoding consistent patterns, similar to how humans can identify the sameness by examining combinations of file names, command arguments, parent process lineage, and other attributes. Furthermore, factors like data inconsistency and the diverse forms of data representations (comprising a mix of numeric data and strings with varying meanings) further complicate the task.

We believe it is important to incorporate operator heuristics or domain knowledge into the algorithm's definition of rarity. For example, while current algorithms are capable of generating human faces, they used to frequently produce images with different eye colors. However, if we were to inform the machine that humans typically have matching eye colors, it could easily correct this discrepancy. This highlights the role of the security engineer as a guiding hand to the algorithms, both in terms of handling noise tolerance and choosing the appropriate data to be ingested into the algorithm. This is crucial as machines are currently limited in their ability to draw meaningful observations from limited data and constrained memory. In summary, this is where the fusion of data-driven anomaly detection and rules matching will come into play.

Lastly, the value proposition of conducting real-time anomaly analysis on the host lies in the unique options it offers, which cannot be achieved through alternative methods. On the host, we can observe anomalies based on all relevant and observed kernel events. In contrast, sending a large volume of kernel events to a centralized system would be impractical, resulting in significant costs for data pipeline management and data lake compute expenses.

## Initial Scope

The initial scope is to implement the Count Min Sketch algorithm using n shared sketches and expose its count estimates as new filterchecks for use in Falco rules. An MVP can be explored in this libs draft PR [wip: new(userspace/libsinsp): MVP CountMinSketch Powered Probabilistic Counting and Filtering](https://github.com/falcosecurity/libs/pull/1453). Moreover, the initial anomaly detection framework will include a transparent `plugin` user interface for defining application behavior profiles and utilizing sketch count estimates in Falco rules. The primary direct benefit lies in establishing a safety boundary for Falco rules in production environments, allowing for broader rule monitoring while preventing Falco rules from blowing up in production.

Furthermore, The Falco Project will provide adopters with valuable initial use cases, recommended thresholds, and callouts for known issues. One important consideration is the identification of SRE anti-patterns. Another consideration is to provide *very clear* guidance to adopters for setting and configuring parameters, including recommended minimums. Additionally, guidance should be provided on indicators to look for in order to determine if adjustments need to be made and in which direction, particularly when defining application behavior profiles.

## High-Level Technical Design of a New `anomalydetection` Plugin

This document provides a high-level proposal with limited technical details.

*Probabilistic Data Structures*

One option for implementing the probabilistic filter is by utilizing a robust two-dimensional probabilistic data structure known as the Count Min Sketch. This data structure is widely employed in distributed stream processing frameworks such as Apache Spark, Apache Storm, Apache Flink, and others, as well as databases like Redis and PostgreSQL.

Technical details and implications are extensively covered in numerous research papers and textbooks. Therefore, here are some key points to consider in order to make informed choices:

- The challenges posed by both hard and soft collisions can be mitigated by using multiple non-cryptographic hash functions, which has been mathematically proven to be effective.
- Despite providing one-sided error bounds and preventing undercounting, the sketchy data structure requires adopters to define a tolerance level for overcounting. This tolerance level determines what qualifies as rare or noteworthy.
- To enhance accuracy and reduce estimation errors, consider debiasing data (e.g. Count Min Sketch with Conservative Updates) or applying a logarithmic scale to address kernel event data skew. The logarithmic scale may suit threat detection, targeting low-frequency or long-tail attack-related items. However, only use if performance overhead is acceptable.
- Use larger shared sketches and incorporate container IDs as part of the behavior profiles to differentiate between workloads / applications. Conversely, use separate sketches for distinct behavior profiles, also known as the "what we are counting".
- ... and numerous other aspects that will be discussed in subsequent implementation PRs.

*Plumbing and Interface*

The ultimate goal is to introduce these new capabilities as plugin. A significant amount of work will be dedicated to addressing the necessary plumbing required to support the new framework and integrate it with the existing rules filtering, `libsinsp` and `plugin` mechanisms. This integration aims to provide a user-friendly interface that allows users to easily configure and utilize the opt-in framework for different use cases. 

For instance, the interface should empower end users to define error tolerances and, consequently, sketch dimensions, along with other tuning parameters, bounds, and settings. Ultimately, it should enable the definition of n behavior profiles to facilitate the use of count estimates in Falco rules.

## What this Framework is Not

- This framework is not intended to function as an event aggregator or enhancer, such as netflow data. Its sole purpose is to serve as an anomaly filter for individual events, utilizing the existing sinsp state, the newly built state through sketches, and the current rules engine.
- The development of this framework will not be swayed by overly specific use cases that limit its broader adoption and coverage.
- While it may not offer flawless attack threat detection from the beginning, it serves as an initial step towards comprehensive event logging and analysis, capturing all events that exhibit any form of new or changing behavior we observe. Therefore, initially, the greatest value lies in combining it with regular Falco rules based on the anomaly-filtered event stream.

## Why now?

In case you haven't noticed, advanced data analytics is quite the big deal these days, and we can leverage robust established algorithms used in real production settings across various industries. The novelty lies in addressing the specific data encoding challenges unique to the field of cybersecurity, not re-inventing already established algorithms.

Furthermore, over the past several Falco releases, we have significantly improved stability, configurability, and capabilities. Notably, the plugins system has been refined over the past year to efficiently access the complete `libsinsp` state, now also featuring an improved CPP SDK. Additionally, it now seamlessly collaborates with the existing primary syscalls event source, deviating from its original purpose of processing new data sources. This improvement allows for more intuitive functionality, as demonstrated by the new `k8smeta` plugin. Now is the opportune time to further enhance proven threat detection capabilities and expand the plugins system even more. 

*Initial community feedback concerning the KubeCon NA 2023 Full Talk*

- Overall, the feedback for [A Wind of Change for Threat Detection](https://kccncna2023.sched.com/event/1R2mX/a-wind-of-change-for-threat-detection-melissa-kilby-apple) was very positive and appreciative, particularly regarding the direct real-life benefits (a safety boundary for Falco rules enabling broader monitoring that won't blow up in production). Suggestions for future development included integrating the sketch directly into the kernel driver (which would be a remarkable achievement if feasible). Lastly, people have inquired about the timeline for the availability of this feature.
- Refer to the [KubeCon NA 2023 Slides](https://static.sched.com/hosted_files/kccncna2023/c5/A%20Wind%20of%20Change%20for%20Threat%20Detection%20-%20Melissa%20Kilby%20-%20KubeCon%20NA%202023.pdf) or [attached PDF](kubeconna23-anomaly-detection-slides.pdf) for more information. Here's the [Talk Recording](https://www.youtube.com/watch?v=1y1m9Vz93Yo) (please note that the first four minutes of the video are missing, but the slides and audio recordings are complete).

*Falco Community Call - January 17, 2024*

See dedicated [HackMD](https://hackmd.io/Ss0_1avySUuxArBQm-oaGQ?view):

- While not blocking the start of the plugin or an alpha dev version, there's feedback from @jasondellaluce that plugins cannot access the existing `libsinsp` filtercheck. It would be advantageous to enable this access to avoid reimplementing them and the constant risk of falling out of sync with `libs`. @leogr mentioned that supporting this over time should be possible.
- We have discussed the plugins config and are currently undecided on whether the definition of the behavior profile per sketch, meaning the fields that are string concatenated together and counted, should reside in the plugins config or in the rules files. The latter would potentially require a new rules component. Final decisions will be deferred to a later stage to ensure the config is intuitive, and we want to guarantee proper sketch definition when attempting to run Falco rules using the `anomalydetection` plugin.  
- One use case, namely determining if a rule has previously occurred in a container, could be addressed by this framework as well. However, we are currently unsure how to expose the rule names, as `libsinsp` is not aware of them. This may be an optimization we can address later and does not block the development of an initial version.
- Future use cases might involve counting distinct values, utilizing the hyper log log algorithm. However, there will be additional technical challenges to overcome.
- Finally, just to reiterate some feedback from the KubeCon talk, there's a suggestion that, perhaps in the future, we could pass intelligence back and forth between the drivers and userspace. This idea has been discussed independently, especially in the context of kernel-side filtering. However, such capabilities would be a long-term consideration.

## Proposed Timelines

- Falco 0.37.0: Design details and scaffolding
- Falco 0.38.0: Experimental release
- Falco 0.39.0: First release

## Resources / References

- [Probabilistic Data Structures and Algorithms
for Big Data Applications](https://www.gakhov.com/books/pdsa.html) book
- [Count Min Sketch blog 1](https://towardsdatascience.com/big-data-with-sketchy-structures-part-1-the-count-min-sketch-b73fb3a33e2a)
- [Count Min Sketch blog 2](https://www.synnada.ai/blog/probabilistic-data-structures-in-streaming-count-min-sketch)
- [Count Min Log Sketch](https://arxiv.org/pdf/1502.04885.pdf) paper
- [Count Min Sketch with Conservative Updates](https://hal.science/hal-03613957/document#:~:text=Count%2DMin%20Sketch%20with%20Conservative%20Updates%20(CMS%2DCU),because%20of%20its%20inherent%20difficulty) paper
- [xxHash](https://github.com/Cyan4973/xxHash) as new dependency for fast and reliable hashing (using xxh3)
