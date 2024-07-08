#include "wcn_chr.h"

static struct task_struct *client_rx_task;
static atomic_t wcn_chr_enable = ATOMIC_INIT(0);

struct socket *cl_sock;

static struct wcn_chr_event_list event_list[1] = {
		{"assert", 0x2501, 0},
};

int wcn_chr_write(char *buf, size_t len)
{
	int ret;
	struct msghdr send_msg = {0};
	struct kvec send_vec = {0};

	if (!cl_sock) {
		WCN_ERR("%s: invalid cl_sock\n", __func__);
		return -EINVAL;
	}

	send_vec.iov_base = buf;
	send_vec.iov_len = len;

	ret = kernel_sendmsg(cl_sock, &send_msg, &send_vec, 1, len);
	if (ret < 0) {
		WCN_ERR("%s: kernel_sendmsg failed with %d\n", __func__, ret);
		return -EINVAL;
	}

	return len;
}

int wcn_chr_report_event(char *str, u32 index)
{
	wcn_bsp_chr_cp2_assert_t chr_event = {0};
	char send_buf[BUF_SIZE] = {0};
	struct msghdr send_msg = {0};
	struct kvec send_vec = {0};
	int ret;
	char char_info[64] = {0};

	if (event_list[index].enable == 0) {
		WCN_INFO("event[%u]:%s not enable\n", index, event_list[index].name);
		return 0;
	}

	if (atomic_read(&wcn_chr_enable) == 0 || cl_sock == NULL) {
		WCN_INFO("%s: wcn chr not ready\n", __func__);
		return 0;
	}

	send_vec.iov_base = send_buf;
	send_vec.iov_len = BUF_SIZE;

	chr_event.cp_log_level = sysfs_info.loglevel;
	chr_event.ap_log_level = console_loglevel;
	snprintf(chr_event.error_dscp, sizeof(chr_event.error_dscp), str);
	snprintf(chr_event.cp_version, sizeof(chr_event.cp_version), sysfs_info.sw_ver_buf);

	ret = snprintf(char_info, sizeof(char_info), "0x%x,0x%x,%s,%s",
						chr_event.cp_log_level, chr_event.ap_log_level,
						chr_event.error_dscp, chr_event.cp_version);

	snprintf(send_buf, BUF_SIZE, "wcn_chr_ind_event,module=bsp,"
										"ref_count=%d,event_id=0x%x,"
										"version=0x%x,event_content_len=%d,"
										"char_info=%s",
			1, event_list[index].event_id, 1, ret, char_info);

	ret = kernel_sendmsg(cl_sock, &send_msg, &send_vec, 1, BUF_SIZE);
	if (ret < 0) {
		WCN_ERR("kernel_sendmsg failed with %d\n", ret);
		return ret;
	}

	return 0;
}

static int parse_event(char *buf, int len)
{
	char *tmp;
	unsigned int event_id, set, i;

	if (strncmp(buf, WCN_CHR_SOCKET_CMD_DISABLE,
					MIN(len, strlen(WCN_CHR_SOCKET_CMD_DISABLE))) == 0) {

		WCN_INFO("%s: %s\n", __func__, WCN_CHR_SOCKET_CMD_DISABLE);
		atomic_set(&wcn_chr_enable, 0);
		return 0;
	}

	if (strncmp(buf, WCN_CHR_SET_EVENT_HEAD,
					MIN(len, strlen(WCN_CHR_SET_EVENT_HEAD))) == 0) {

		WCN_INFO("%s: %s\n", __func__, buf);

		tmp = strstr(buf, "event_id=");
		tmp += strlen("event_id=");
		event_id = simple_strtol(tmp, NULL, 16);

		tmp = strstr(buf, "set=");
		tmp += strlen("set=");
		set = simple_strtol(tmp, NULL, 10);

		WCN_INFO("%s: %s: 0x%x-%d\n", __func__, WCN_CHR_SET_EVENT_HEAD, event_id, set);

		for (i = 0; i < ARRAY_SIZE(event_list); i++) {
			if (event_list[i].event_id == event_id) {
				event_list[i].enable = set;
				break;
			}
		}

		return 0;
	}

	return 0;
}

static __be32 my_aton(const char *str)
{
        unsigned int l;
        unsigned int val;
        int i;

        l = 0;
        for (i = 0; i < 4; i++) {
		l <<= 8;
		if (*str != '\0') {
			val = 0;
			while (*str != '\0' && *str != '.' && *str != +'\n') {
				val *= 10;
				val += *str - '0';
				str++;
			}
			l |= val;
			if (*str != '\0')
				str++;
		}
        }
        return htonl(l);
}

static int client_rx_thread(void *data)
{
	int ret;
	struct sockaddr_in s_addr;
	char recv_buf[BUF_SIZE] = {0};
	struct msghdr recv_msg = {0};
	struct kvec recv_vec = {0};

	cl_sock = kzalloc(sizeof(struct socket), GFP_KERNEL);
	if (!cl_sock) {
		WCN_ERR("kzalloc cl_sock failed\n");
		return -ENOMEM;
	}

retry:

	ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &cl_sock);
	if (ret < 0) {
		WCN_ERR("cl_sock create failed %d\n", ret);
		return -EINVAL;
	}



	s_addr.sin_family = AF_INET;
	s_addr.sin_port = htons(4756);
	s_addr.sin_addr.s_addr = my_aton("127.0.0.1");

	WCN_INFO("wait for chr server ready\n");

	//TODO:optimize:block here while server not ready
	while (cl_sock->ops->connect(cl_sock, (struct sockaddr *)&s_addr, sizeof(s_addr), 0))
		msleep(1000);

	WCN_INFO("chr server connected\n");
	atomic_set(&wcn_chr_enable, 1);

	recv_vec.iov_base = recv_buf;
	recv_vec.iov_len = BUF_SIZE;

	while (atomic_read(&wcn_chr_enable)) {
		memset(recv_buf, 0, sizeof(recv_buf));
		ret = kernel_recvmsg(cl_sock, &recv_msg, &recv_vec, 1, BUF_SIZE, 0);
		WCN_INFO("%s\n", recv_buf);
		parse_event(recv_buf, strlen(recv_buf));
	}

	sock_release(cl_sock);

	goto retry;
}

int wcn_chr_init(void)
{
	WCN_INFO("%s entry\n", __func__);

	client_rx_task = kthread_create(client_rx_thread, NULL, "wcn_chr_rx");
	if (IS_ERR_OR_NULL(client_rx_task)) {
		WCN_ERR("client rx thread create failed\n");
		return -1;
	}

	wake_up_process(client_rx_task);

	return 0;
}
