# Adopters

This is a list of production adopters of Falco (in alphabetical order):

* [Booz Allen Hamilton](https://www.boozallen.com/) - BAH leverages Falco as part of their Kubernetes environment to verify that work loads behave as they did in their CD DevSecOps pipelines. BAH offers a solution to internal developers to easily build DevSecOps pipelines for projects. This makes it easy for developers to incorporate Security principles early on in the development cycle. In production, Falco is used to verify that the code the developer ships does not violate any of the production security requirements. BAH [are speaking at Kubecon NA 2019](https://kccncna19.sched.com/event/UaWr/building-reusable-devsecops-pipelines-on-a-secure-kubernetes-platform-steven-terrana-booz-allen-hamilton-michael-ducy-sysdig) on their use of Falco.

* [League](https://league.com/ca/) - League provides health benefits management services to help employees understand and get the most from their benefits, and employers to provide effective, efficient plans. Falco is used to monitor our deployed services on Kubernetes, protecting against malicious access to containerswhich could lead to leaks of PHI or other sensitive data. The Falco alerts are logged in Stackdriver for grouping and further analysis. In the future, we're hoping for integrations with Prometheus and AlertManaager as well.

* [Preferral](https://www.preferral.com) - Preferral is a HIPAA-compliant platform for Referral Management and Online Referral Forms. Preferral streamlines the referral process for patients, specialists and their referral partners. By automating the referral process, referring practices spend less time on the phone, manual efforts are eliminated, and patients get the right care from the right specialist. Preferral leverages Falco to provide a Host Intrusion Detection System to meet their HIPPA compliance requirements.
  * https://hipaa.preferral.com/01-preferral_hipaa_compliance/

* [Shopify](https://www.shopify.com) - Shopify is the leading multi-channel commerce platform. Merchants use Shopify to design, set up, and manage their stores across multiple sales channels, including mobile, web, social media, marketplaces, brick-and-mortar locations, and pop-up shops. The platform also provides merchants with a powerful back-office and a single view of their business, from payments to shipping. The Shopify platform was engineered for reliability and scale, making enterprise-level technology available to businesses of all sizes. Shopify uses Falco to complement its Host and Network Intrusion Detection Systems.

* [Sight Machine](https://www.sightmachine.com) - Sight Machine is the category leader for manufacturing analytics and used by Global 500 companies to make better, faster decisions about their operations. Sight Machine uses Falco to help enforce SOC2 compliance as well as a tool for real time security monitoring and alerting in kubernetes.

* [Sumo Logic](https://www.sumologic.com/) - Sumo Logic provides a SaaS based log aggregation service that provides dashboards and applications to easily identify and analyze problems in your application and infrastructure. Sumo Logic provides native integrations for many CNCF projects, such as Falco, that allows end users to easily collect Falco events and analyze Falco events on DecSecOps focused dashboards.

