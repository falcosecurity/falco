# Adopters

Known end users with notable contributions to the project include:
* AWS
* IBM
* Red Hat

Falco is being used by numerous other companies, both large and small, to build higher layer products and services. The list includes but is not limited to: 
* Equinix Metal
* IEEE
* Lowes
* Reckrut
* Yellow Pepper
* CTx
* Utikal
* Discrete Events
* Agritech Infra

This is a list of production adopters of Falco (in alphabetical order):

* [ASAPP](https://www.asapp.com/) - ASAPP is a pushing the boundaries of fundamental artificial intelligence research. We apply our research into AI-Native® products that make organizations, in the customer experience industry, highly productive, efficient, and effective—by augmenting human activity and automating workflows. We constantly monitor our workloads against different hazards and FALCO helps us extend our threat monitoring boundaries.

* [Booz Allen Hamilton](https://www.boozallen.com/) - BAH leverages Falco as part of their Kubernetes environment to verify that work loads behave as they did in their CD DevSecOps pipelines. BAH offers a solution to internal developers to easily build DevSecOps pipelines for projects. This makes it easy for developers to incorporate Security principles early on in the development cycle. In production, Falco is used to verify that the code the developer ships does not violate any of the production security requirements. BAH [are speaking at Kubecon NA 2019](https://kccncna19.sched.com/event/UaWr/building-reusable-devsecops-pipelines-on-a-secure-kubernetes-platform-steven-terrana-booz-allen-hamilton-michael-ducy-sysdig) on their use of Falco.

* [Coveo](https://www.coveo.com/) - Coveo stitches together content and data, learning from every interaction, to tailor every experience using AI to drive growth, satisfy customers and develop employee proficiency. All Falco events are centralized in our SIEM for analysis. Understanding what is running on production servers, and the context around why things are running is even more tricky now that we have further abstractions with containers and orchestration systems. Falco is giving us a good visibility inside containers and complement other Host and Network Intrusion Detection Systems. In a near future, we expect to deploy serverless functions to take action when Falco identifies patterns worth taking action for.

* [Frame.io](https://frame.io/) - Frame.io is a cloud-based (SaaS) video review and collaboration platform that enables users to securely upload source media, work-in-progress edits, dailies, and more into private workspaces where they can invite their team and clients to collaborate on projects. Understanding what is running on production servers, and the context around why things are running is even more tricky now that we have further abstractions like Docker and Kubernetes. To get this needed visibility into our system, we rely on Falco. Falco's ability to collect raw system calls such as open, connect, exec, along with their arguments offer key insights on what is happening on the production system and became the foundation of our intrusion detection and alerting system.

* [GitLab](https://about.gitlab.com/direction/defend/container_host_security/) - GitLab is a complete DevOps platform, delivered as a single application, fundamentally changing the way Development, Security, and Ops teams collaborate. GitLab Ultimate provides the single tool teams need to find, triage, and fix vulnerabilities in applications, services, and cloud-native environments enabling them to manage their risk. This provides them with repeatable, defensible processes that automate security and compliance policies. GitLab includes a tight integration with Falco, allowing users to defend their containerized applications from attacks while running in production.

* [League](https://league.com/ca/) - League provides health benefits management services to help employees understand and get the most from their benefits, and employers to provide effective, efficient plans. Falco is used to monitor our deployed services on Kubernetes, protecting against malicious access to containers which could lead to leaks of PHI or other sensitive data. The Falco alerts are logged in Stackdriver for grouping and further analysis. In the future, we're hoping for integrations with Prometheus and AlertManager as well.

* [Logz.io](https://logz.io/) - Logz.io is a cloud observability platform for modern engineering teams. The Logz.io platform consists of three products — Log Management, Infrastructure Monitoring, and Cloud SIEM — that work together to unify the jobs of monitoring, troubleshooting, and security. We empower engineers to deliver better software by offering the world's most popular open source observability tools — the ELK Stack, Grafana, and Jaeger — in a single, easy to use, and powerful platform purpose-built for monitoring distributed cloud environments. Cloud SIEM supports data from multiple sources, including Falco's alerts, and offers useful rules and dashboards content to visualize and manage incidents across your systems in a unified UI.
  * https://logz.io/blog/k8s-security-with-falco-and-cloud-siem/

* [MathWorks](https://mathworks.com) - MathWorks develops mathematical computing software for engineers and scientists. MathWorks uses Falco for Kubernetes threat detection, unexpected application behavior, and maps Falco rules to their cloud infrastructure's security kill chain model. MathWorks presented their Falco use case at [KubeCon + CloudNativeCon North America 2020](https://www.youtube.com/watch?v=L-5RYBTV010).  

* [Pocteo](https://pocteo.co) - Pocteo helps with Kubernetes adoption in enterprises by providing a variety of services such as training, consulting, auditing and mentoring. We build CI/CD pipelines the GitOps way, as well as design and run k8s clusters. Pocteo uses Falco as a runtime monitoring system to secure clients' workloads against suspicious behavior and ensure k8s pods immutability. We also use Falco to collect, process and act on security events through a response engine and serverless functions.

* [Preferral](https://www.preferral.com) - Preferral is a HIPAA-compliant platform for Referral Management and Online Referral Forms. Preferral streamlines the referral process for patients, specialists and their referral partners. By automating the referral process, referring practices spend less time on the phone, manual efforts are eliminated, and patients get the right care from the right specialist. Preferral leverages Falco to provide a Host Intrusion Detection System to meet their HIPPA compliance requirements.
  * https://hipaa.preferral.com/01-preferral_hipaa_compliance/

* [Replicated](https://www.replicated.com/) - Replicated is the modern way to ship on-prem software. Replicated gives software vendors a container-based platform for easily deploying cloud native applications inside customers'​ environments to provide greater security and control. Replicated uses Falco as runtime security to detect threats in the Kubernetes clusters which host our critical SaaS services.

* [Secureworks](https://www.secureworks.com/) - Secureworks is a leading worldwide cybersecurity company with a cloud-native security product that combines the power of human intellect with security analytics to unify detection and response across cloud, network, and endpoint environments for improved security operations and outcomes. Our Taegis XDR platform and detection system processes petabytes of security relevant data to expose active threats amongst the billions of daily events from our customers. We are proud to protect our platform’s Kubernetes deployments, as well as help our customers protect their own Linux and container environments, using Falco. 

* [Shopify](https://www.shopify.com) - Shopify is the leading multi-channel commerce platform. Merchants use Shopify to design, set up, and manage their stores across multiple sales channels, including mobile, web, social media, marketplaces, brick-and-mortar locations, and pop-up shops. The platform also provides merchants with a powerful back-office and a single view of their business, from payments to shipping. The Shopify platform was engineered for reliability and scale, making enterprise-level technology available to businesses of all sizes. Shopify uses Falco to complement its Host and Network Intrusion Detection Systems.

* [Sight Machine](https://www.sightmachine.com) - Sight Machine is the category leader for manufacturing analytics and used by Global 500 companies to make better, faster decisions about their operations. Sight Machine uses Falco to help enforce SOC2 compliance as well as a tool for real time security monitoring and alerting in Kubernetes.

* [Skyscanner](https://www.skyscanner.net) - Skyscanner is the world's travel search engine for flights, hotels and car rentals. Most of our infrastructure is based on Kubernetes, and our Security team is using Falco to monitor anomalies at runtime, integrating Falco's findings with our internal ChatOps tooling to provide insight on the behavior of our machines in production. We also postprocess and store Falco's results to generate dashboards for auditing purposes.

* [Sumo Logic](https://www.sumologic.com/) - Sumo Logic provides a SaaS based log aggregation service that provides dashboards and applications to easily identify and analyze problems in your application and infrastructure. Sumo Logic provides native integrations for many CNCF projects, such as Falco, that allows end users to easily collect Falco events and analyze Falco events on DecSecOps focused dashboards.

* [Swissblock Technologies](https://swissblock.net/) At Swissblock we connect the dots by combining cutting-edge algorithmic trading strategies with in-depth market analysis. We route all Falco events to our control systems, both monitoring and logging. Being able to deeply analyse alerts, we can understand what is running on our Kubernetes clusters and check against security policies, specifically defined for each workload. A set of alarms notifies us in case of critical events, letting us react fast. In the near future we plan to build a little application to route Kubernetes internal events directly to Falco, fully leveraging Falco PodSecurityPolicies analyses.

* [Shapesecurity/F5] (https://www.shapesecurity.com/) Shapesecurity defends against application fraud attacks like Account Take Over, Credential Stuffing, Fake Accounts, etc. Required by FedRamp certification, we needed to find a FIM solution to help monitor and protect our Kubernetes clusters. Traditional FIM solutions were not scalable and not working for our environment, but with Falco we found the solution we needed. Falco's detection capabilities have helped us identify anomalous behaviour within our clusters. We leverage Sidekick (https://github.com/falcosecurity/charts/tree/master/falcosidekick) to send Falco alerts to a PubSub which in turn publishes those alerts to our SIEM (SumoLogic)

* [Yahoo! JAPAN](https://www.yahoo.co.jp/) Yahoo! JAPAN is a leading company of internet in Japan. We build an AI Platform in our private cloud and provide it to scientists in our company. AI Platform is a multi-tenant Kubernetes environment and more flexible, faster, more efficient Machine Learning environment. Falco is used to detect unauthorized commands and malicious access and our AI Platform is monitored and alerted by Falco.

* [Sysdig](https://www.sysdig.com/) Sysdig originally created Falco in 2016 to detect unexpected or suspicious activity using a rules engine on top of the data that comes from the sysdig kernel system call probe. Sysdig provides tooling to help with vulnerability management, compliance, detection, incident response and forensics in Cloud-native environments. Sysdig Secure has extended Falco to include: a rule library, the ability to update macros, lists & rules via the user interface and API, automated tuning of rules, and rule creation based on profiling known system behavior. On top of the basic Falco rules, Sysdig Secure implements the concept of a "Security policy" that can comprise several rules which are evaluated for a user-defined infrastructure scope like Kubernetes namespaces, OpenShift clusters, deployment workload, cloud regions etc.

## Adding a name

If you would like to add your name to this file, submit a pull request with your change. 
