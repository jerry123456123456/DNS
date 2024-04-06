#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>

//DNS的端口号是53，服务器ip为114.114.114.114
#define DNS_SERVER_PORT		53
#define DNS_SERVER_IP		"114.114.114.114"

//定义DNS报文主机记录类型为0x01，定义了DNS报文中别名记录类型为0x05
#define DNS_HOST			0x01
#define DNS_CNAME			0x05

struct dns_header {

	unsigned short id;   //标识DNS报文
	unsigned short flags;   //标识DNS报文的标志位

	unsigned short questions; // 标识报文中包含的问题数
	unsigned short answer;    //报文中包含的回答数

	unsigned short authority;  //报文中包含的授权回答数
	unsigned short additional;  //标识报文中包含的额外信息数

};


struct dns_question {
	int length;     //域名的长度
	unsigned short qtype;  //表示问题的类型
	unsigned short qclass;  //标识问题的类
	unsigned char *name; //表示域名 
};

struct dns_item {
	char *domain;    //指向字符的指针，表示域名
	char *ip;     //指向字符的指针，标识ip地址
};


//client sendto dns server

int dns_create_header(struct dns_header *header) {

	if (header == NULL) return -1;
	memset(header, 0, sizeof(struct dns_header));

	//random
	srandom(time(NULL));
	header->id = random();

	header->flags = htons(0x0100);   //大端字节序，机器喜欢逆序
	header->questions = htons(1);   //表示问题数为1

	return 0;
}

// hostname: www.0voice.com
// www
// 0voice
// com

// name: 3www60voice3com0

int dns_create_question(struct dns_question *question, const char *hostname) {
	//算法用于将域名转换为需要的格式
	if (question == NULL || hostname == NULL) return -1;
	memset(question, 0, sizeof(struct dns_question));

	question->name = (char*)malloc(strlen(hostname) + 2);
	if (question->name == NULL) {
		return -2;
	}

	question->length = strlen(hostname) + 2;

	question->qtype = htons(1); //
	question->qclass = htons(1);

	// name 
	const char delim[2] = ".";
	char *qname = question->name;
	
	char *hostname_dup = strdup(hostname); // strdup --> malloc
	char *token = strtok(hostname_dup, delim); // www.0voice.com 

	while (token != NULL) {

		size_t len = strlen(token);

		*qname = len;
		qname ++;

		strncpy(qname, token, len+1);
		qname += len;

		token = strtok(NULL, delim); //0voice.com ,  com

	}

	free(hostname_dup);
	
}

// struct dns_header *header
// struct dns_question *question
// char *request

int dns_build_request(struct dns_header *header, struct dns_question *question, char *request, int rlen) {  //将问题部分和头部整合构建

	if (header == NULL || question == NULL || request == NULL) return -1;
	memset(request, 0, rlen);

	// header --> request
	
	memcpy(request, header, sizeof(struct dns_header));
	int offset = sizeof(struct dns_header);  //记录下一个写入的位置

	// question --> request
	memcpy(request+offset, question->name, question->length); //从request+offset的位置开始，将question->的数据复制到请求报文段中
	offset += question->length;

	memcpy(request+offset, &question->qtype, sizeof(question->qtype));
	offset += sizeof(question->qtype);

	memcpy(request+offset, &question->qclass, sizeof(question->qclass));
	offset += sizeof(question->qclass);

	return offset;
}


static int is_pointer(int in) {
	return ((in & 0xC0) == 0xC0);
}


static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len) {

	int flag = 0, n = 0, alen = 0;
	char *pos = out + (*len);

	while (1) {

		flag = (int)ptr[0];
		if (flag == 0) break;

		if (is_pointer(flag)) {
			
			n = (int)ptr[1];
			ptr = chunk + n;
			dns_parse_name(chunk, ptr, out, len);
			break;
			
		} else {

			ptr ++;
			memcpy(pos, ptr, flag);
			pos += flag;
			ptr += flag;

			*len += flag;
			if ((int)ptr[0] != 0) {
				memcpy(pos, ".", 1);
				pos += 1;
				(*len) += 1;
			}
		}
	
	}
	
}




static int dns_parse_response(char *buffer, struct dns_item **domains) {

	int i = 0;
	unsigned char *ptr = buffer;

	ptr += 4;
	int querys = ntohs(*(unsigned short*)ptr);

	ptr += 2;
	int answers = ntohs(*(unsigned short*)ptr);

	ptr += 6;
	for (i = 0;i < querys;i ++) {
		while (1) {
			int flag = (int)ptr[0];
			ptr += (flag + 1);

			if (flag == 0) break;
		}
		ptr += 4;
	}

	char cname[128], aname[128], ip[20], netip[4];
	int len, type, ttl, datalen;

	int cnt = 0;
	struct dns_item *list = (struct dns_item*)calloc(answers, sizeof(struct dns_item));
	if (list == NULL) {
		return -1;
	}

	for (i = 0;i < answers;i ++) {
		
		bzero(aname, sizeof(aname));
		len = 0;

		dns_parse_name(buffer, ptr, aname, &len);
		ptr += 2;

		type = htons(*(unsigned short*)ptr);
		ptr += 4;

		ttl = htons(*(unsigned short*)ptr);
		ptr += 4;

		datalen = ntohs(*(unsigned short*)ptr);
		ptr += 2;

		if (type == DNS_CNAME) {

			bzero(cname, sizeof(cname));
			len = 0;
			dns_parse_name(buffer, ptr, cname, &len);
			ptr += datalen;
			
		} else if (type == DNS_HOST) {

			bzero(ip, sizeof(ip));

			if (datalen == 4) {
				memcpy(netip, ptr, datalen);
				inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));

				printf("%s has address %s\n" , aname, ip);
				printf("\tTime to live: %d minutes , %d seconds\n", ttl / 60, ttl % 60);

				list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
				memcpy(list[cnt].domain, aname, strlen(aname));
				
				list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
				memcpy(list[cnt].ip, ip, strlen(ip));
				
				cnt ++;
			}
			
			ptr += datalen;
		}
	}

	*domains = list;
	ptr += 2;

	return cnt;
	
}


int dns_client_commit(const char *domain) {
	//创建一个UDP套接字，第一个参数表示使用ipv4地址族,第二个参数表示使用数据报套接字，返回的套接字描述符存储在sockfd中
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return  -1;
	}

	struct sockaddr_in servaddr = {0};   //用于存储服务器的地址信息
	servaddr.sin_family = AF_INET;          //设置地址族为ipv4
	servaddr.sin_port = htons(DNS_SERVER_PORT);  
	servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

	int ret = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	printf("connect : %d\n", ret);   //连接到DNS服务器

	struct dns_header header = {0};
	dns_create_header(&header);

	struct dns_question question = {0};
	dns_create_question(&question, domain);

	char request[1024] = {0};
	int length = dns_build_request(&header, &question, request, 1024);
	//至此请求报文创建完毕

	//开始发送
	// request
	int slen = sendto(sockfd, request, length, 0, (struct sockaddr*)&servaddr, sizeof(struct sockaddr));
	
	//recvfrom 
	char response[1024] = {0};
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	
	
	int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr*)&addr, (socklen_t*)&addr_len);

	struct dns_item *dns_domain = NULL;
	dns_parse_response(response, &dns_domain);

	free(dns_domain);
	
	return n;

}


int main(int argc, char *argv[]) {

	if (argc < 2) return -1;

	dns_client_commit(argv[1]);

}
