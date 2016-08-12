#include <cstdio>
#include <utility>
#include <map>
#include <set>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pwd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

void usage(char *program)
{
	printf("Usage %s [options]\n\n", program);
	printf("Options:\n");
	printf("     -h/--help: show this help\n");
	printf("     -a/--action: actions to perform. Can be one of the following:\n");
	printf("          write_binary_dir                           Write to files below /bin\n");
	printf("          write_etc                                  Write to files below /etc\n");
	printf("          read_sensitive_file                        Read a sensitive file\n");
	printf("          read_sensitive_file_after_startup          As a trusted program, wait a while,\n");
	printf("                                                     then read a sensitive file\n");
	printf("          write_rpm_database                         Write to files below /var/lib/rpm\n");
	printf("          spawn_shell                                Run a shell (bash)\n");
	printf("          db_program_spawn_process                   As a database program, try to spawn\n");
	printf("                                                     another program\n");
	printf("          modify_binary_dirs                         Modify a file below /bin\n");
	printf("          mkdir_binary_dirs                          Create a directory below /bin\n");
	printf("          change_thread_namespace                    Change namespace\n");
	printf("          system_user_interactive                    Change to a system user and try to\n");
	printf("                                                     run an interactive command\n");
	printf("          network_activity                           Open network connections\n");
	printf("                                                     (used by system_procs_network_activity below)\n");
	printf("          system_procs_network_activity              Open network connections as a program\n");
	printf("                                                     that should not perform network actions\n");
	printf("          non_sudo_setuid                            Setuid as a non-root user\n");
	printf("          create_files_below_dev                     Create files below /dev\n");
	printf("          exec_ls                                    execve() the program ls\n");
	printf("                                                     (used by user_mgmt_binaries below)\n");
	printf("          user_mgmt_binaries                         Become the program \"vipw\", which triggers\n");
	printf("                                                     rules related to user management programs\n");
	printf("          all                                        All of the above\n");
	printf("     -i/--interval: Number of seconds between actions\n");
	printf("     -o/--once: Perform actions once and exit\n");
}

void open_file(const char *filename, const char *flags)
{
	FILE *f = fopen(filename, flags);
	if(f)
	{
		fclose(f);
	}
	else
	{
		fprintf(stderr, "Could not open %s for writing: %s\n", filename, strerror(errno));
	}

}

void touch(const char *filename)
{
	open_file(filename, "w");
}

void read(const char *filename)
{
	open_file(filename, "r");
}

uid_t become_user(const char *user)
{
	struct passwd *pw;
	pw = getpwnam(user);
	if(pw == NULL)
	{
		fprintf(stderr, "Could not find user information for \"%s\" user: %s\n", user, strerror(errno));
		exit(1);
	}

	int rc = setuid(pw->pw_uid);

	if(rc != 0)
	{
		fprintf(stderr, "Could not change user to \"%s\" (uid %u): %s\n", user, pw->pw_uid, strerror(errno));
		exit(1);
	}
}

void spawn(const char *cmd, char **argv, char **env)
{
	pid_t child;

	// Fork a process, that way proc.duration is reset
	if ((child = fork()) == 0)
	{
		execve(cmd, argv, env);
		fprintf(stderr, "Could not exec to spawn %s: %s\n", cmd, strerror(errno));
	}
	else
	{
		int status;
		waitpid(child, &status, 0);
	}
}

void respawn(const char *cmd, const char *action, const char *interval)
{
	char *argv[] = {(char *) cmd,
			(char *) "--action", (char *) action,
			(char *) "--interval", (char *) interval,
			(char *) "--once", NULL};

	char *env[] = {NULL};

	spawn(cmd, argv, env);
}

void write_binary_dir() {
	printf("Writing to /bin/created-by-event-generator-sh...\n");
	touch("/bin/created-by-event-generator-sh");
}

void write_etc() {
	printf("Writing to /etc/created-by-event-generator-sh...\n");
	touch("/etc/created-by-event-generator-sh");
}

void read_sensitive_file() {
	printf("Reading /etc/shadow...\n");
	read("/etc/shadow");
}

void read_sensitive_file_after_startup() {
	printf("Becoming the program \"httpd\", sleeping 6 seconds and reading /etc/shadow...\n");
	respawn("./httpd", "read_sensitive_file", "6");
}

void write_rpm_database() {
	printf("Writing to /var/lib/rpm/created-by-event-generator-sh...\n");
	touch("/var/lib/rpm/created-by-event-generator-sh");
}

void spawn_shell() {
	printf("Spawning a shell using system()...\n");
	int rc;

	if ((rc = system("ls > /dev/null")) != 0)
	{
		fprintf(stderr, "Could not run ls > /dev/null in a shell: %s\n", strerror(errno));
	}
}

void db_program_spawn_process() {
	printf("Becoming the program \"mysql\" and then spawning a shell\n");
	respawn("./mysqld", "spawn_shell", "0");
}

void modify_binary_dirs() {
	printf("Moving /bin/true to /bin/true.event-generator-sh and back...\n");

	if (rename("/bin/true", "/bin/true.event-generator-sh") != 0)
	{
		fprintf(stderr, "Could not rename \"/bin/true\" to \"/bin/true.event-generator-sh\": %s\n", strerror(errno));
	}
	else
	{
		if (rename("/bin/true.event-generator-sh", "/bin/true") != 0)
		{
			fprintf(stderr, "Could not rename \"/bin/true.event-generator-sh\" to \"/bin/true\": %s\n", strerror(errno));
		}
	}
}

void mkdir_binary_dirs() {
	printf("Creating directory /bin/directory-created-by-event-generator-sh...\n");
	if (mkdir("/bin/directory-created-by-event-generator-sh", 0644) != 0)
	{
		fprintf(stderr, "Could not create directory \"/bin/directory-created-by-event-generator-sh\": %s\n", strerror(errno));
	}
}

void change_thread_namespace() {
	printf("Calling setns() to change namespaces...\n");
	// It doesn't matter that the arguments to setns are
	// bogus. It's the attempt to call it that will trigger the
	// rule.
	setns(0, 0);
}

void system_user_interactive() {
	pid_t child;

	// Fork a child and do everything in the child.
	if ((child = fork()) == 0)
	{
		become_user("daemon");
		char *argv[] = {(char *)"/bin/login", NULL};
		char *env[] = {NULL};
		spawn("/bin/login", argv, env);
		exit(0);
	}
	else
	{
		int status;
		waitpid(child, &status, 0);
	}
}

void network_activity() {
	printf("Opening a listening socket on port 8192...\n");
	int rc;
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in localhost;

	localhost.sin_family = AF_INET;
	localhost.sin_port = htons(8192);
	inet_aton("127.0.0.1", &(localhost.sin_addr));

	if((rc = bind(sock, (struct sockaddr *) &localhost, sizeof(localhost))) != 0)
	{
		fprintf(stderr, "Could not bind listening socket to localhost: %s\n", strerror(errno));
		return;
	}

	listen(sock, 1);

	close(sock);
}

void system_procs_network_activity() {
	printf("Becoming the program \"sha1sum\" and then performing network activity\n");
	respawn("./sha1sum", "network_activity", "0");
}

void non_sudo_setuid() {
	pid_t child;

	// Fork a child and do everything in the child.
	if ((child = fork()) == 0)
	{
		// First setuid to something non-root. Then try to setuid back to root.
		become_user("daemon");
		become_user("root");
		exit(0);
	}
	else
	{
		int status;
		waitpid(child, &status, 0);
	}
}

void create_files_below_dev() {
	printf("Creating /dev/created-by-event-generator-sh...\n");
	touch("/dev/created-by-event-generator-sh");
}

void exec_ls()
{
	char *argv[] = {(char *)"/bin/ls", NULL};
	char *env[] = {NULL};
	spawn("/bin/ls", argv, env);
}

void user_mgmt_binaries() {
	printf("Becoming the program \"vipw\" and then running the program /bin/ls\n");
	printf("NOTE: does not result in a falco notification in containers\n");
	respawn("./vipw", "exec_ls", "0");
}

typedef void (*action_t)();

map<string, action_t> defined_actions = {{"write_binary_dir", write_binary_dir},
					 {"write_etc", write_etc},
					 {"read_sensitive_file", read_sensitive_file},
					 {"read_sensitive_file_after_startup", read_sensitive_file_after_startup},
					 {"write_rpm_database", write_rpm_database},
					 {"spawn_shell", spawn_shell},
					 {"db_program_spawn_process", db_program_spawn_process},
					 {"modify_binary_dirs", modify_binary_dirs},
					 {"mkdir_binary_dirs", mkdir_binary_dirs},
					 {"change_thread_namespace", change_thread_namespace},
					 {"system_user_interactive", system_user_interactive},
					 {"network_activity", network_activity},
					 {"system_procs_network_activity", system_procs_network_activity},
					 {"non_sudo_setuid", non_sudo_setuid},
					 {"create_files_below_dev", create_files_below_dev},
					 {"exec_ls", exec_ls},
					 {"user_mgmt_binaries", user_mgmt_binaries}};


void create_symlinks(const char *program)
{
	int rc;

	// Some actions depend on this program being re-run as
	// different program names like 'mysqld', 'httpd', etc. This
	// sets up all the required symlinks.
	const char *progs[] = {"./httpd", "./mysqld", "./sha1sum", "./vipw", NULL};

	for (unsigned int i=0; progs[i] != NULL; i++)
	{
		unlink(progs[i]);

		if ((rc = symlink(program, progs[i])) != 0)
		{
			fprintf(stderr, "Could not link \"./event_generator\" to \"%s\": %s\n", progs[i], strerror(errno));
		}
	}
}

void run_actions(map<string, action_t> &actions, int interval, bool once)
{
	while (true)
	{
		for (auto action : actions)
		{
			sleep(interval);
			printf("***Action %s\n", action.first.c_str());
			action.second();
		}
		if(once)
		{
			break;
		}
	}
}

int main(int argc, char **argv)
{
	map<string, action_t> actions;
	int op;
	int long_index = 0;
	int interval = 1;
	bool once = false;
	map<string, action_t>::iterator it;

	static struct option long_options[] =
	{
		{"help", no_argument, 0, 'h' },
		{"action", required_argument, 0, 'a' },
		{"interval", required_argument, 0, 'i' },
		{"once", no_argument, 0, 'o' },

		{0, 0}
	};

	//
	// Parse the args
	//
	while((op = getopt_long(argc, argv,
				"ha:i:l:",
				long_options, &long_index)) != -1)
	{
		switch(op)
		{
		case 'h':
			usage(argv[0]);
			exit(1);
		case 'a':
			if((it = defined_actions.find(optarg)) == defined_actions.end())
			{
				fprintf(stderr, "No action with name \"%s\" known, exiting.\n", optarg);
				exit(1);
			}
			actions.insert(*it);
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'o':
			once = true;
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if(actions.size() == 0)
	{
		actions = defined_actions;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	// Only create symlinks when running as the program event_generator
	if (strstr(argv[0], "generator"))
	{
		create_symlinks(argv[0]);
	}

	run_actions(actions, interval, once);
}
