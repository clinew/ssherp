#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

struct arguments {
	char* node;
	char* port;
};

/**
 * Print usage message and exit the program.
 */
void usage_print(char* message, char argv[]) {
	FILE* buffer;
	if (message) {
		buffer = stderr;
	} else {
		buffer = stdout;
	}

	// Print error message.
	if (message) {
		fprintf(buffer, "ERROR: %s.\n\n", message);
	}

	// Print usage message.
	fprintf(buffer, "USAGE: %s [OPT] HOST [PORT]\n", argv);
	fprintf(buffer, "OPT: -h|--help Print usage message and exit.\n");
	fprintf(buffer, "HOST: The remote host to connect to.\n");
	fprintf(buffer, "PORT: The remote port to connect to.\n");

	// Exit the program.
	if (message) {
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

void arguments_parse(int argc, char* argv[], struct arguments* arguments) {
	static struct option options[] = {
		{"help", no_argument,  NULL, 'h'},
		{0, 0, 0, 0}
	};

	memset(arguments, 0, sizeof(*arguments));

	// Parse optional arguments.
	int c;
	int index;
	while (1) {
		c = getopt_long(argc, argv, "h", options, &index);
		if (c == -1) {
			// No more arguments.
			break;
		}
		switch(c) {
		case 'h':
			usage_print(NULL, argv[0]);
			break;
		case '?':
			usage_print("Unknown option", argv[0]);
			break;
		}
	}

	// Parse arguments.
	if (optind >= argc) {
		usage_print("Must specify a host", argv[0]);
	} else if (optind + 2 < argc) {
		usage_print("Extranneous arguments", argv[0]);
	}
	arguments->node = argv[optind];
	if (++optind < argc) {
		arguments->port = argv[optind];
	} else {
		arguments->port = "22";
	}
}

int main(int argc, char* argv[]) {
	struct addrinfo addrinfo_hint;
	struct addrinfo* addrinfo_res;
	struct arguments arguments;
	int fd;
	int ret;

	// Parse arguments.
	arguments_parse(argc, argv, &arguments);

	// Connect to the server.
	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd == -1) {
		perror("Creating socket");
		exit(EXIT_FAILURE);
	}
	memset(&addrinfo_hint, 0, sizeof(addrinfo_hint));
	addrinfo_hint.ai_family = AF_INET;
	addrinfo_hint.ai_socktype = SOCK_STREAM;
	addrinfo_hint.ai_protocol = IPPROTO_TCP;
	fprintf(stderr, "Node: '%s', port: '%s'\n", arguments.node, arguments.port);
	if (ret = getaddrinfo(arguments.node, arguments.port,
		&addrinfo_hint, &addrinfo_res)) {
		fprintf(stderr, "'getaddrinfo': %s\n", gai_strerror(ret));
		if (ret == EAI_SYSTEM) {
			perror("'getaddrinfo'");
		}
		goto out1;
	}
	if (connect(fd, (struct sockaddr*)addrinfo_res->ai_addr,
		addrinfo_res->ai_addrlen) == -1) {
		perror("Connecting");
		goto out1;
	}
	freeaddrinfo(addrinfo_res);

	// Send/recieve protocol version exchange.
	// TODO.

	// Exit the program.
	exit(EXIT_SUCCESS);
out1:
	if (close(fd) == -1) {
		perror("Error closing socket");
	}
	exit(EXIT_FAILURE);
}
