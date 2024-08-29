# Warning

This environment is provided for demonstration purposes only and does not represent a production ready deployment of Falco.

# Components
The components that this docker-compose file spins up are [Falco](https://falco.org/), [falcosidekick](https://github.com/falcosecurity/falcosidekick), [falcosidekick-ui](https://github.com/falcosecurity/falcosidekick-ui) and a [redis](https://redis.io/) database.

# Running
To start this environment run `docker-compose up`.
Note: You may need to use sudo for Falco to start correctly.

# Cleaning up

To clean up run `docker-compose rm`.

# Generating events
If you'd like to generate events that will trigger rules and show up in the UI you can run `docker run -it --rm falcosecurity/event-generator run syscall --loop`