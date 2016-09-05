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
	char* pve_protover;
	char* pve_softver;
	char* pve_comment;
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
		{"comment", required_argument, NULL, 'c'},
		{"help", no_argument,  NULL, 'h'},
		{"protover", required_argument, NULL, 'p'},
		{"softver", required_argument, NULL, 's'},
		{0, 0, 0, 0}
	};

	// Set argument defaults.
	memset(arguments, 0, sizeof(*arguments));
	arguments->pve_protover = "2.0";
	arguments->pve_softver = "ssherp";
	arguments->pve_comment = NULL;

	// Parse optional arguments.
	int c;
	int index;
	while (1) {
		c = getopt_long(argc, argv, "c:hp:s:", options, &index);
		if (c == -1) {
			// No more arguments.
			break;
		}
		switch(c) {
		case 'c':
			arguments->pve_comment = optarg;
			break;
		case 'h':
			usage_print(NULL, argv[0]);
			break;
		case 'p':
			arguments->pve_protover = optarg;
			break;
		case 's':
			arguments->pve_softver = optarg;
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
		freeaddrinfo(addrinfo_res);
		goto out1;
	}
	freeaddrinfo(addrinfo_res);

	// Send/recieve protocol version exchange.
	char buffer[256];
	snprintf(buffer, sizeof(buffer), "SSH-%s-%s%s%s\r\n",
		arguments.pve_protover, arguments.pve_softver,
		arguments.pve_comment ? " " : "",
		arguments.pve_comment ? arguments.pve_comment : "");
	if (write(fd, buffer, strlen(buffer)) < strlen(buffer)) {
		perror("Unable to write Protocol Version Exchange\n");
		goto out1;
	}
	char readbuf[256];
	memset(readbuf, 0, sizeof(readbuf));
	// TODO: Handle potential pre-messages, which is a giant PITA.
	if ((ret = read(fd, readbuf, sizeof(readbuf))) == -1) {
		perror("Unable to read PVE from server.\n");
		goto out1;
	}
	if (strncmp(readbuf, "SSH-", 4)) {
		fprintf(stderr, "Unexpected protocol ident");
		goto out1;
	}

	// Exit the program.
	exit(EXIT_SUCCESS);
out1:
	if (close(fd) == -1) {
		perror("Error closing socket");
	}
	exit(EXIT_FAILURE);
}
