# A Warning
This environment is provided for demonstration purposes only and does not represent a production ready deployment of falco

# Components
The components that this docker-compose file spins up are falco, falcosidekick, falcosidekick-ui and a redis database

# Running
To start this environment run `docker-compose up`

# Cleaning up
To clean up run `docker-compose rm`

# Generating events
If you'd like to generate events that will trigger rules and show up in the UI you can run `docker run -it --rm falcosecurity/event-generator run syscall --loop`