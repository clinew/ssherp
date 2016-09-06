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
#include <unistd.h>

struct arguments {
	char* node;
	char* port;
	// Protocol Version Exchange.
	char* pve_protover;
	char* pve_softver;
	char* pve_comment;
	// Algorithm Negotiation.
	char* an_kex;
	char* an_host_key_algs;
	char* an_ciphers_ctos;
	char* an_ciphers_stoc;
	char* an_macs_ctos;
	char* an_macs_stoc;
	char* an_compression_ctos;
	char* an_compression_stoc;
	char* an_lang_ctos;
	char* an_lang_stoc;
};

char* arg_pve_protover_default = "2.0";
char* arg_pve_softver_default = "ssherp";
char* arg_pve_comment_default = NULL;
char* arg_an_kex_default = "curve25519-sha256@libssh.org,"
		"ecdh-sha2-nistp256,"
		"ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
		"diffie-hellman-group-exchange-sha256,"
		"diffie-hellman-group-exchange-sha1,"
		"diffie-hellman-group14-sha1,ext-info-c";
char* arg_an_host_key_algs_default = "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
		"ecdsa-sha2-nistp384-cert-v01@openssh.com,"
		"ecdsa-sha2-nistp521-cert-v01@openssh.com,"
		"ssh-ed25519-cert-v01@openssh.com,"
		"ssh-rsa-cert-v01@openssh.com,"
		"ecdsa-sha2-nistp256,"
		"ecdsa-sha2-nistp384,"
		"ecdsa-sha2-nistp521,"
		"ssh-ed25519,"
		"rsa-sha2-512,"
		"rsa-sha2-256,"
		"ssh-rsa";
char* arg_an_ciphers_ctos_default = "chacha20-poly1305@openssh.com,"
		"aes128-ctr,"
		"aes192-ctr,"
		"aes256-ctr,"
		"aes128-gcm@openssh.com,"
		"aes256-gcm@openssh.com,"
		"aes128-cbc,"
		"aes192-cbc,"
		"aes256-cbc,"
		"3des-cbc";
char* arg_an_ciphers_stoc_default = "chacha20-poly1305@openssh.com,"
		"aes128-ctr,"
		"aes192-ctr,"
		"aes256-ctr,"
		"aes128-gcm@openssh.com,"
		"aes256-gcm@openssh.com,"
		"aes128-cbc,"
		"aes192-cbc,"
		"aes256-cbc,3des-cbc";
char* arg_an_macs_ctos_default = "umac-64-etm@openssh.com,"
		"umac-128-etm@openssh.com,"
		"hmac-sha2-256-etm@openssh.com,"
		"hmac-sha2-512-etm@openssh.com,"
		"hmac-sha1-etm@openssh.com,"
		"umac-64@openssh.com,"
		"umac-128@openssh.com,"
		"hmac-sha2-256,"
		"hmac-sha2-512,"
		"hmac-sha1";
char* arg_an_macs_stoc_default = "umac-64-etm@openssh.com,"
		"umac-128-etm@openssh.com,"
		"hmac-sha2-256-etm@openssh.com,"
		"hmac-sha2-512-etm@openssh.com,"
		"hmac-sha1-etm@openssh.com,"
		"umac-64@openssh.com,"
		"umac-128@openssh.com,"
		"hmac-sha2-256,"
		"hmac-sha2-512,"
		"hmac-sha1";
char* arg_an_compression_ctos_default = "none,"
		"zlib@openssh.com,"
		"zlib";
char* arg_an_compression_stoc_default = "none,"
		"zlib@openssh.com,"
		"zlib";
char* arg_an_lang_ctos_default = "";
char* arg_an_lang_stoc_default = "";

/**
 * Print argument defaults and exit the program.
 */
void usage_defaults() {
	printf("Protocol Validation Exchange:\n");
	printf("\tProtocol Version: '%s'\n", arg_pve_protover_default);
	printf("\tSoftware Version: '%s'\n", arg_pve_softver_default);
	printf("\tComment: '%s'\n", arg_pve_comment_default);
	printf("Algorithm Negotiation:\n");
	printf("\tKex Exchange Algorithms: '%s'\n", arg_an_kex_default);
	printf("\tHost Key Algorithms: '%s'\n", arg_an_host_key_algs_default);
	printf("\tEncryption Ciphers (Client-to_Server): '%s'\n", arg_an_ciphers_ctos_default);
	printf("\tEncryption Ciphers (Server-to-Client): '%s'\n", arg_an_ciphers_stoc_default);
	printf("\tMACs (Client-to-Server): '%s'\n", arg_an_macs_ctos_default);
	printf("\tMACs (Server-to-Client): '%s'\n", arg_an_macs_stoc_default);
	printf("\tCompression (Client-to-Server): '%s'\n", arg_an_compression_ctos_default);
	printf("\tCompression (Server-to-Client): '%s'\n", arg_an_compression_stoc_default);
	printf("\tLanguages (Client-to-Server): '%s'\n", arg_an_lang_ctos_default);
	printf("\tLanguages (Server-to-Client): '%s'\n", arg_an_lang_stoc_default);
	exit(EXIT_SUCCESS);
}

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
	fprintf(buffer, "USAGE: %s [OPT] HOST [PORT]\n\n", argv);
	fprintf(buffer, "OPT:\n");
	fprintf(buffer, "    -a|--macs-stoc  MAC algorithms server-to-client.\n");
	fprintf(buffer, "    -c|--comment  Protocol Version Exchange comment field.\n");
	fprintf(buffer, "    -d|--defaults  Print argument defaults.\n");
	fprintf(buffer, "    -e|--ciphers-stoc  Encryption ciphers server-to-client.\n");
	fprintf(buffer, "    -f|--force  Do not validate spoofed input for correctness.\n");
	fprintf(buffer, "    -h|--help  Print usage message and exit.\n");
	fprintf(buffer, "    -i|--ciphers-ctos  Encryption ciphers client-to-server.\n");
	fprintf(buffer, "    -k|--host-keys  Host Key Algorithms.\n");
	fprintf(buffer, "    -l|--lang-stoc  Languages server-to-client.\n");
	fprintf(buffer, "    -m|--macs-ctos  MAC algorithms client-to-server.\n");
	fprintf(buffer, "    -n|--lang-ctos  Languages client-to-server.\n");
	fprintf(buffer, "    -p|--protover  Protocol version in the Protocol Version Exchange.\n");
	fprintf(buffer, "    -s|--softver  Software version in the Protocol Version Exchange.\n");
	fprintf(buffer, "    -x|--key-exchange  Key Exchange algorithm.\n");
	fprintf(buffer, "    -y|--compression-ctos  Compression client-to-server.\n");
	fprintf(buffer, "    -z|--compression-stoc  Compression server-to-client.\n");
	fprintf(buffer, "HOST: The remote host to connect to.\n");
	fprintf(buffer, "PORT: The remote port to connect to.\n");

	// Exit the program.
	if (message) {
		exit(EXIT_FAILURE);
	}
	exit(EXIT_SUCCESS);
}

/**
 * Validates a list of algorithm names as per RFC 4251.
 *
 * Returns 0 on success, -1 on error.
 */
int arguments_validate_algnames(char* algnames) {
	// 64 chars, no white space, commas, or control characters.
	char* cur;
	char* end;
	char* tmp;

	// Validation
	cur = algnames;
	while (1) {
		(end = strchrnul(cur, ','));

		// Length validation.
		if (end - cur > 64) {
			fprintf(stderr, "Alg name > 64 chars.\n");
			return -1;
		} else if (!(end - cur)) {
			fprintf(stderr, "Empty alg name.\n");
			return -1;
		}

		// Illegal characters.
		int ampersand = 0;
		for (tmp = cur; tmp < end; tmp++) {
			// Check double '@'.
			if ((*tmp) == '@') {
				if (ampersand) {
					fprintf(stderr, "Multiple '@' in "
						"algname.\n");
					return -1;
				}
				ampersand = 1;
			}
			// Control chars.
			// Possibly broken on terms with weird encoding.
			if ((*tmp) <= 32) {
				fprintf(stderr, "ASCII control char in "
					"algname.\n");
				return -1;
			}
		}

		// Loop increment.
		if (!(*end)) {
			break;
		} else {
			cur = end + 1;
		}
	}

	// Return success.
	return 0;
}

void arguments_parse(int argc, char* argv[], struct arguments* arguments) {
	static struct option options[] = {
		{"macs-stoc", required_argument, NULL, 'a'},
		{"comment", required_argument, NULL, 'c'},
		{"ciphers-stoc", required_argument, NULL, 'e'},
		{"defaults", no_argument, NULL, 'd'},
		{"force", no_argument, NULL, 'f'},
		{"help", no_argument,  NULL, 'h'},
		{"ciphers-ctos", required_argument, NULL, 'i'},
		{"host-keys", required_argument, NULL, 'k'},
		{"lang-stoc", required_argument, NULL, 'l'},
		{"macs-ctos", required_argument, NULL, 'm'},
		{"lang-ctos", required_argument, NULL, 'n'},
		{"protover", required_argument, NULL, 'p'},
		{"softver", required_argument, NULL, 's'},
		{"key-exchange", required_argument, NULL, 'x'},
		{"compression-ctos", required_argument, NULL, 'y'},
		{"compression-stoc", required_argument, NULL, 'z'},
		{0, 0, 0, 0}
	};

	// Set argument defaults.
	memset(arguments, 0, sizeof(*arguments));
	arguments->pve_protover = arg_pve_protover_default;
	arguments->pve_softver = arg_pve_softver_default;
	arguments->pve_comment = arg_pve_comment_default;
	arguments->an_kex = arg_an_kex_default;
	arguments->an_host_key_algs = arg_an_host_key_algs_default;
	arguments->an_ciphers_ctos = arg_an_ciphers_ctos_default;
	arguments->an_ciphers_stoc = arg_an_ciphers_stoc_default;
	arguments->an_macs_ctos = arg_an_macs_ctos_default;
	arguments->an_macs_stoc = arg_an_macs_stoc_default;
	arguments->an_compression_ctos = arg_an_compression_ctos_default;
	arguments->an_compression_stoc = arg_an_compression_stoc_default;
	arguments->an_lang_ctos = arg_an_lang_ctos_default;
	arguments->an_lang_stoc = arg_an_lang_stoc_default;

	// Parse optional arguments.
	int c;
	int force = 0;
	int index;
	while (1) {
		c = getopt_long(argc, argv, "a:c:de:fhi:k:l:m:n:p:s:x:y:z:", options, &index);
		if (c == -1) {
			// No more arguments.
			break;
		}
		switch(c) {
		case 'a':
			arguments->an_macs_stoc = optarg;
			break;
		case 'c':
			arguments->pve_comment = optarg;
			break;
		case 'd':
			usage_defaults();
			break;
		case 'e':
			arguments->an_ciphers_stoc = optarg;
			break;
		case 'f':
			force = 1;
			break;
		case 'h':
			usage_print(NULL, argv[0]);
			break;
		case 'i':
			arguments->an_ciphers_ctos = optarg;
			break;
		case 'k':
			arguments->an_host_key_algs = optarg;
			break;
		case 'l': // Probably broken.
			arguments->an_lang_stoc = optarg;
			break;
		case 'm':
			arguments->an_macs_ctos = optarg;
			break;
		case 'n': // Probably broken.
			arguments->an_lang_ctos = optarg;
			break;
		case 'p':
			arguments->pve_protover = optarg;
			break;
		case 's':
			arguments->pve_softver = optarg;
			break;
		case 'x':
			arguments->an_kex = optarg;
			break;
		case 'y':
			arguments->an_compression_ctos = optarg;
			break;
		case 'z':
			arguments->an_compression_stoc = optarg;
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

	// Validate algorithm names.
	if (force) {
		// Don't validate.
		return;
	}
	if (arguments_validate_algnames(arguments->an_macs_stoc)) {
		usage_print("Invalid MACs-alg S-to-C", argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_ciphers_stoc)) {
		usage_print("Invalid ciphers S-to-C", argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_ciphers_ctos)) {
		usage_print("Invalid ciphers C-to-S", argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_host_key_algs)) {
		usage_print("Invalid host key algnames",
			argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_kex)) {
		usage_print("Invalid kex algnames", argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_macs_ctos)) {
		usage_print("Invalid MACs C-to-S", argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_compression_ctos)) {
		usage_print("Invalid compression C-to-S",
			argv[0]);
	}
	if (arguments_validate_algnames(arguments->an_compression_stoc)) {
		usage_print("Invalid compression S-to-C",
			argv[0]);
	}
}

/*
 * Given the specified arguments, return a packet suitable for SSH Algorithm
 * Negotiation (RFC 4253) and outputs the size of said packet.  The packet
 * must be freed after use.  Returns 'NULL' on failure.
 */
char* ssherp_algneg_packet(struct arguments* arguments, size_t* size_out) {
	// Create algorithm negotiation packet.
	int i;
	size_t seek;
	char* sendbuf;
	size_t size;
	char* tmp;

	// Add packet type and cookie.
	size = 17;
	sendbuf = malloc(size);
	sendbuf[0] = 20; // SSH_MSG_KEXINIT
	strncpy(&sendbuf[1], "LOLZSORANDOMXDDD", 16);
	seek = 17;

	// Add Algorithm Negotation ("ANs") name lists.
	char* ans[10];
	ans[0] = arguments->an_kex;
	ans[1] = arguments->an_host_key_algs;
	ans[2] = arguments->an_ciphers_ctos;
	ans[3] = arguments->an_ciphers_stoc;
	ans[4] = arguments->an_macs_ctos;
	ans[5] = arguments->an_macs_stoc;
	ans[6] = arguments->an_compression_ctos;
	ans[7] = arguments->an_compression_stoc;
	ans[8] = arguments->an_lang_ctos;
	ans[9] = arguments->an_lang_stoc;
	for (i = 0; i < (sizeof(ans)/sizeof(char*)); i++) {
		size_t len = strlen(ans[i]);
		size_t nlen = htonl((uint32_t)len);
		size += len + 4;
		if (!(tmp = realloc(sendbuf, size))) {
			perror("Reallocating for AN");
			free(sendbuf);
			return NULL;
		}
		memcpy(&sendbuf[seek], &nlen, sizeof(uint32_t));
		seek += 4;
		strncpy(&sendbuf[seek], ans[i], len);
		seek += len;
	}

	// Add boolean and extensions.
	size += 1 + 4;
	if (!(tmp = realloc(sendbuf, size))) {
		perror("Reallocating for end bits");
		free(sendbuf);
		return NULL;
	}
	memset(&sendbuf[seek], 0, 5);

	// Return the packet.
	*size_out = size;
	return sendbuf;
}

/**
 * Wraps the specified payload in SSH's Binary Packet Protocol, except only
 * sort of since no encryption and MAC is done.  Returns a pointer to the
 * wrapped packet or 'NULL' on failure.
 */
char* ssherp_bpp_packet(char* payload, size_t size_in, size_t* size_out) {
	int i;

	// Calculate overall packet size.
	size_t size_tmp = size_in + 4 + 1;
	uint8_t padding = 16 + (8 - (size_tmp % 8));
	size_tmp += padding;

	// Allocate space for packet.
	char* packet = malloc(size_tmp);
	if (!packet) {
		fprintf(stderr, "Unable to allocate space for packet\n");
		return NULL;
	}

	// Create packet.
	uint32_t packet_length = htonl(size_tmp - 4);
	size_t seek;
	seek = 0;
	memcpy(packet, &packet_length, sizeof(uint32_t));
	seek += 4;
	packet[seek] = padding;
	seek += 1;
	memcpy(&packet[seek], payload, size_in);
	seek += size_in;
	for (i = 0; i < padding; i++) {
		packet[seek++] = 'x'; // Not very random.
	}

	// Return the packet.
	*size_out = size_tmp;
	return packet;
}

int main(int argc, char* argv[]) {
	struct addrinfo addrinfo_hint;
	struct addrinfo* addrinfo_res;
	struct arguments arguments;
	int fd;
	int ret;
	int status = EXIT_FAILURE;

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
	if ((ret = getaddrinfo(arguments.node, arguments.port,
		&addrinfo_hint, &addrinfo_res))) {
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
	char readbuf[2048];
	memset(readbuf, 0, sizeof(readbuf));
	// TODO: Handle potential pre-messages, which is a giant PITA.
	if ((ret = read(fd, readbuf, sizeof(readbuf))) == -1) {
		perror("Unable to read PVE from server.\n");
		goto out1;
	}
	fprintf(stderr, "Read bytes: %i\n", ret);
	if (strncmp(readbuf, "SSH-", 4)) {
		fprintf(stderr, "Unexpected protocol ident");
		goto out1;
	}
	char* end;
	if (!(end = strstr(readbuf, "\r\n"))) {
		fprintf(stderr, "No end to protocol ident");
		goto out1;
	}

	// Send Algorithm Negotiation Packet.
	size_t payload_len;
	char* payload = ssherp_algneg_packet(&arguments, &payload_len);
	if (!payload) {
		fprintf(stderr, "Error creating payload");
		goto out1;
	}
	size_t packet_len;
	char* packet = ssherp_bpp_packet(payload, payload_len, &packet_len);
	if (!packet) {
		fprintf(stderr, "Error creating packet");
		goto out2;
	}
	if (write(fd, packet, packet_len) < packet_len) {
		perror("Unable to write entire packet");
		goto out3;
	}

	// Exit the program.
	status = EXIT_SUCCESS;
out3:
	free(packet);
out2:
	free(payload);
out1:
	if (close(fd) == -1) {
		perror("Error closing socket");
	}
	exit(status);
}
